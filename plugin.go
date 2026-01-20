package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"

	"github.com/docker/go-plugins-helpers/volume"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/volumeattach"
	"github.com/gophercloud/gophercloud/v2/pagination"
)

type plugin struct {
	blockClient   *gophercloud.ServiceClient
	computeClient *gophercloud.ServiceClient
	config        *tConfig
	mutex         *sync.Mutex
}

func newPlugin(provider *gophercloud.ProviderClient, endpointOpts gophercloud.EndpointOpts, config *tConfig) (*plugin, error) {
	blockClient, err := openstack.NewBlockStorageV3(provider, endpointOpts)
	if err != nil {
		return nil, err
	}

	computeClient, err := openstack.NewComputeV2(provider, endpointOpts)
	if err != nil {
		return nil, err
	}

	if config.MachineID == "" {
		bytes, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return nil, err
		}
		id, err := uuid.FromString(strings.TrimSpace(string(bytes)))
		if err != nil {
			return nil, err
		}
		config.MachineID = id.String()
	}

	return &plugin{
		blockClient:   blockClient,
		computeClient: computeClient,
		config:        config,
		mutex:         &sync.Mutex{},
	}, nil
}

func (d plugin) Capabilities() *volume.CapabilitiesResponse {
	return &volume.CapabilitiesResponse{
		Capabilities: volume.Capability{Scope: "global"},
	}
}

func (d plugin) Create(r *volume.CreateRequest) error {
	logger := log.WithFields(log.Fields{"name": r.Name, "action": "create"})
	logger.Infof("Creating volume '%s' ...", r.Name)

	ctx := context.TODO()
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// DEFAULTS
	size := 10
	if s, ok := r.Options["size"]; ok {
		if v, err := strconv.Atoi(s); err == nil {
			size = v
		}
	}

	// Create volume only (do not attach yet)
	_, err := volumes.Create(ctx, d.blockClient, volumes.CreateOpts{
		Size: size,
		Name: r.Name,
	}, volumes.SchedulerHintOpts{}).Extract()
	if err != nil {
		return fmt.Errorf("Volume create failed: %v", err)
	}

	logger.Infof("Volume '%s' created (available)", r.Name)
	return nil
}

// --- Get volume ---
func (d plugin) Get(r *volume.GetRequest) (*volume.GetResponse, error) {
	vol, err := d.getByName(r.Name)
	if err != nil {
		return nil, err
	}

	return &volume.GetResponse{
		Volume: &volume.Volume{
			Name:       r.Name,
			CreatedAt:  vol.CreatedAt.Format(time.RFC3339),
			Mountpoint: filepath.Join(d.config.MountDir, r.Name),
		},
	}, nil
}

// --- List volumes ---
func (d plugin) List() (*volume.ListResponse, error) {
	ctx := context.TODO()
	var vols []*volume.Volume

	pager := volumes.List(d.blockClient, volumes.ListOpts{})
	_ = pager.EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
		vList, _ := volumes.ExtractVolumes(page)
		for _, v := range vList {
			if v.Name != "" {
				vols = append(vols, &volume.Volume{
					Name:      v.Name,
					CreatedAt: v.CreatedAt.Format(time.RFC3339),
				})
			}
		}
		return true, nil
	})

	return &volume.ListResponse{Volumes: vols}, nil
}

// --- Mount volume ---
func (d plugin) Mount(r *volume.MountRequest) (*volume.MountResponse, error) {
    logger := log.WithFields(log.Fields{"name": r.Name, "action": "mount"})
    logger.Infof("Mounting volume '%s'", r.Name)

    vol, err := d.getByName(r.Name)
    if err != nil {
        return nil, fmt.Errorf("Volume not found: %v", err)
    }

    mountPath := filepath.Join(d.config.MountDir, r.Name)

    // CHECK 1: Is it already mounted on this host?
    mounted, err := isMounted(mountPath)
    if err != nil {
        logger.Warnf("Failed to check mount status: %v", err)
    }
    if mounted {
        logger.Infof("Volume '%s' is already mounted at %s", r.Name, mountPath)
        return &volume.MountResponse{Mountpoint: mountPath}, nil
    }

    existing, _ := filepath.Glob("/dev/vd*")
    logger.Infof("Devices before attach: %v", existing)

    // CHECK 2: Is it attached to THIS instance?
    var attachedToThisInstance bool
    var devicePath string

    if len(vol.Attachments) > 0 {
        for _, attachment := range vol.Attachments {
            if attachment.ServerID == d.config.MachineID {
                attachedToThisInstance = true
                devicePath = attachment.Device
                logger.Infof("Volume %s already attached to this instance as %s", vol.ID, devicePath)
                break
            }
        }
    }

    // Attach only if not attached to this instance
    if !attachedToThisInstance {
        logger.Infof("Attaching volume %s to instance %s", vol.ID, d.config.MachineID)
        opts := volumeattach.CreateOpts{VolumeID: vol.ID}
        _, err := volumeattach.Create(context.TODO(), d.computeClient, d.config.MachineID, opts).Extract()
        if err != nil {
            return nil, fmt.Errorf("Attach failed: %v", err)
        }

        logger.Infof("Waiting for volume to reach 'in-use' state")
        vol, err = d.waitOnVolumeState(context.TODO(), vol, "in-use")
        if err != nil {
            return nil, fmt.Errorf("Timeout waiting for volume to attach: %v", err)
        }
        logger.Infof("Volume %s is now in-use", vol.ID)

        // Find the new device
        logger.Infof("Searching for new block device...")
        devicePath, err = findDeviceWithTimeout(existing)
        if err != nil {
            current, _ := filepath.Glob("/dev/vd*")
            logger.Errorf("Failed to find device. Before: %v, After: %v", existing, current)
            return nil, fmt.Errorf("Block device not found for volume %s", vol.ID)
        }
    } else {
        // Device should already exist, verify it
        if devicePath == "" {
            // Try to find it
            devicePath, err = findDeviceWithTimeout(existing)
            if err != nil {
                return nil, fmt.Errorf("Block device not found for attached volume %s", vol.ID)
            }
        }
    }

    logger.Infof("Using device: %s", devicePath)

    fsType, err := getFilesystemType(devicePath)
    if err != nil {
        return nil, fmt.Errorf("Detecting filesystem failed: %v", err)
    }

    if fsType == "" {
        logger.Infof("Formatting device %s as ext4", devicePath)
        if err := formatFilesystem(devicePath, r.Name, "ext4"); err != nil {
            return nil, fmt.Errorf("Formatting failed: %v", err)
        }
    } else {
        logger.Infof("Device %s already has filesystem: %s", devicePath, fsType)
    }

    if err = os.MkdirAll(mountPath, 0700); err != nil {
    	return nil, fmt.Errorf("Cannot create mount path: %v", err)
	}

	logger.Infof("Mounting %s to %s", devicePath, mountPath)
	if out, err := exec.Command("mount", devicePath, mountPath).CombinedOutput(); err != nil {
		// Check if it's "already mounted" error
		if strings.Contains(string(out), "already mounted") {
			logger.Infof("Device already mounted, continuing...")
			return &volume.MountResponse{Mountpoint: mountPath}, nil
		}
		return nil, fmt.Errorf("Mount failed: %s", out)
	}

	logger.Infof("Volume '%s' mounted successfully at %s", r.Name, mountPath)
	return &volume.MountResponse{Mountpoint: mountPath}, nil
}

// Helper function to check if path is mounted
func isMounted(path string) (bool, error) {
    err := exec.Command("mountpoint", "-q", path).Run()
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            // Exit code 1 means not mounted
            if exitErr.ExitCode() == 1 {
                return false, nil
            }
        }
        return false, err
    }
    return true, nil
}

func findNewDevice(existing []string) (string, error) {
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		devices, _ := filepath.Glob("/dev/vd*")

		for _, d := range devices {
			if !contains(existing, d) && !strings.HasSuffix(d, "1") &&
				!strings.HasSuffix(d, "2") && !strings.HasSuffix(d, "3") && !strings.HasSuffix(d, "4") {
				return d, nil
			}
		}
	}
	return "", errors.New("block device not found")
}

func (d plugin) Path(r *volume.PathRequest) (*volume.PathResponse, error) {
	return &volume.PathResponse{
		Mountpoint: filepath.Join(d.config.MountDir, r.Name),
	}, nil
}

func (d plugin) Remove(r *volume.RemoveRequest) error {
	ctx := context.TODO()
	vol, err := d.getByName(r.Name)
	if err != nil {
		return err
	}

	if len(vol.Attachments) > 0 {
		if _, err := d.detachVolume(ctx, vol); err != nil {
			return err
		}
	}

	return volumes.Delete(ctx, d.blockClient, vol.ID, volumes.DeleteOpts{}).ExtractErr()
}

func (d plugin) Unmount(r *volume.UnmountRequest) error {
    logger := log.WithFields(log.Fields{"name": r.Name, "action": "unmount"})
    logger.Infof("Unmounting volume '%s'", r.Name)

    mountPath := filepath.Join(d.config.MountDir, r.Name)

    // Check if actually mounted
    mounted, err := isMounted(mountPath)
    if err != nil {
        logger.Warnf("Failed to check mount status: %v", err)
    }
    if !mounted {
        logger.Infof("Volume '%s' is not mounted, skipping unmount", r.Name)
        return nil
    }

    logger.Infof("Unmounting %s", mountPath)
    if out, err := exec.Command("umount", mountPath).CombinedOutput(); err != nil {
        return fmt.Errorf("Unmount failed: %s", out)
    }

    logger.Infof("Volume '%s' unmounted successfully", r.Name)
    return nil
}

func (d plugin) getByName(name string) (*volumes.Volume, error) {
	var vol *volumes.Volume
	ctx := context.TODO()
	pager := volumes.List(d.blockClient, volumes.ListOpts{Name: name})
	err := pager.EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
		vList, _ := volumes.ExtractVolumes(page)
		for _, v := range vList {
			if v.Name == name {
				vol = &v
				return false, nil
			}
		}
		return true, nil
	})

	if vol == nil || vol.ID == "" {
		return nil, errors.New("Not Found")
	}
	return vol, err
}

func (d plugin) detachVolume(ctx context.Context, vol *volumes.Volume) (*volumes.Volume, error) {
	for _, att := range vol.Attachments {
		if err := volumeattach.Delete(ctx, d.computeClient, att.ServerID, att.ID).ExtractErr(); err != nil {
			return nil, err
		}
	}
	return vol, nil
}

func (d plugin) waitOnVolumeState(ctx context.Context, vol *volumes.Volume, status string) (*volumes.Volume, error) {
	if vol.Status == status {
		return vol, nil
	}

	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return vol, fmt.Errorf("volume %s did not reach status %s (last=%s)", vol.ID, status, vol.Status)
		case <-ticker.C:
			updated, err := volumes.Get(ctx, d.blockClient, vol.ID).Extract()
			if err != nil {
				return nil, err
			}
			vol = updated
			if vol.Status == status {
				return vol, nil
			}
			if status == "in-use" && vol.Status == "available" {
				log.Warnf("Volume %s still available while waiting for in-use, continuing", vol.ID)
			}
		}
	}
}
