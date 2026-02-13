package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	log.Infof("Discovering OpenStack endpoints...")
	log.Infof("EndpointOpts: Region=%s, Availability=%s", endpointOpts.Region, endpointOpts.Availability)

	// Try to create block storage client
	blockClient, err := openstack.NewBlockStorageV3(provider, endpointOpts)
	if err != nil {
		log.Errorf("Failed to discover block storage endpoint using standard method: %v", err)
		identityEndpoint := provider.IdentityEndpoint

		parts := strings.SplitN(identityEndpoint, "://", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid identity endpoint format: %s", identityEndpoint)
		}
		scheme := parts[0]
		hostAndPath := parts[1]

		hostParts := strings.SplitN(hostAndPath, "/", 2)
		host := hostParts[0]

		cinderURL := fmt.Sprintf("%s://%s/volume/v3", scheme, host)

		log.Infof("Attempting manual endpoint construction: %s", cinderURL)

		blockClient = &gophercloud.ServiceClient{
			ProviderClient: provider,
			Endpoint:       cinderURL,
			Type:           "block-storage",
		}

		// ResourceBase should have the trailing slash for proper path construction
		blockClient.ResourceBase = cinderURL + "/"

		log.Infof("Manually constructed block storage client - Endpoint: %s, ResourceBase: %s",
			blockClient.Endpoint, blockClient.ResourceBase)
	} else {
		log.Infof("Block storage endpoint discovered: %s", blockClient.Endpoint)
	}

	computeClient, err := openstack.NewComputeV2(provider, endpointOpts)
	if err != nil {
		log.Errorf("Failed to discover compute endpoint: %v", err)
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}
	log.Infof("Compute endpoint discovered: %s", computeClient.Endpoint)

	if config.MachineID == "" {
		// Try to get instance UUID from OpenStack metadata first (most reliable)
		machineID, err := getInstanceIDFromMetadata()
		if err == nil && machineID != "" {
			config.MachineID = machineID
			log.Infof("Using instance ID from OpenStack metadata: %s", machineID)
		} else {
			// Fallback to /etc/machine-id
			log.Warnf("Could not get instance ID from metadata: %v, falling back to /etc/machine-id", err)
			bytes, err := os.ReadFile("/etc/machine-id")
			if err != nil {
				return nil, err
			}

			machineIDStr := strings.TrimSpace(string(bytes))

			// /etc/machine-id might be in format without dashes (32 hex chars)
			// OpenStack expects UUID format with dashes
			if len(machineIDStr) == 32 && !strings.Contains(machineIDStr, "-") {
				// Convert to UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
				machineIDStr = fmt.Sprintf("%s-%s-%s-%s-%s",
					machineIDStr[0:8],
					machineIDStr[8:12],
					machineIDStr[12:16],
					machineIDStr[16:20],
					machineIDStr[20:32])
				log.Infof("Converted machine-id to UUID format: %s", machineIDStr)
			}

			// Validate it's a proper UUID
			id, err := uuid.FromString(machineIDStr)
			if err != nil {
				return nil, fmt.Errorf("invalid machine-id format: %v", err)
			}
			config.MachineID = id.String()
			log.Infof("Using machine-id: %s", config.MachineID)
		}
	}

	log.Infof("Plugin initialized with MachineID: %s", config.MachineID)

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
	existing, err := d.getByName(r.Name)
    if err == nil && existing != nil {
        log.Infof("Volume '%s' already exists (ID: %s), skipping create", r.Name, existing.ID)
        return nil
    }

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

	// Parse keyLock argument from docker-compose
	keyLock := "false"
	if ad, ok := r.Options["key_lock"]; ok {
		keyLock = ad
	}

	metadata := map[string]string{
		"key_lock": keyLock,
		"docker_volume": "true",
	}

	// Create volume only (do not attach yet)
	_, err = volumes.Create(ctx, d.blockClient, volumes.CreateOpts{
		Size: size,
		Name: r.Name,
		Metadata: metadata,
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

    mountPath := filepath.Join(d.config.MountDir, r.Name)

    mounted, _ := isMounted(mountPath)
    if !mounted {
        log.Warnf("Path() called but volume not mounted, attempting mount...")

        _, err := d.Mount(&volume.MountRequest{
            Name: r.Name,
            ID:   r.Name,
        })
        if err != nil {
            log.Errorf("Auto-mount from Path() failed: %v", err)
        }
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

func (d plugin) Mount(r *volume.MountRequest) (*volume.MountResponse, error) {
	freshID, err := getInstanceIDFromMetadata()
    if err == nil && freshID != "" && freshID != d.config.MachineID {
        log.Warnf("MachineID mismatch! config=%s metadata=%s, updating...",
            d.config.MachineID, freshID)
        d.config.MachineID = freshID
    }

    logger := log.WithFields(log.Fields{"name": r.Name, "action": "mount"})
    logger.Infof("Mounting volume '%s' (our machine-id: %s)", r.Name, d.config.MachineID)

    d.mutex.Lock()
    defer d.mutex.Unlock()

    vol, err := d.getByName(r.Name)
    if err != nil {
        return nil, fmt.Errorf("Volume not found: %v", err)
    }

    logger.Infof("Volume found: ID=%s, Status=%s, Attachments=%d", vol.ID, vol.Status, len(vol.Attachments))

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
        logger.Infof("Volume has %d attachment(s)", len(vol.Attachments))
        for i, attachment := range vol.Attachments {
            logger.Infof("Attachment %d: server_id=%s, device=%s, attachment_id=%s",
                i, attachment.ServerID, attachment.Device, attachment.ID)

            if attachment.ServerID == d.config.MachineID {
                attachedToThisInstance = true
                devicePath = attachment.Device
                logger.Infof("✓ Volume %s already attached to THIS instance as %s", vol.ID, devicePath)
                break
            } else {
                // Volume is attached to a different instance (or same VM with different machine-id after reboot)
                logger.Warnf("✗ Volume %s is attached to DIFFERENT server: %s (our ID: %s)",
                    vol.ID, attachment.ServerID, d.config.MachineID)

                // Check instance state before attempting detach
                // If instance is rebooting, wait for it to complete
                logger.Infof("→ Checking server %s state before detach...", attachment.ServerID)
                serverState, err := d.getServerState(context.TODO(), attachment.ServerID)
                if err != nil {
                    logger.Warnf("Could not get server state: %v, attempting detach anyway", err)
                } else {
                    logger.Infof("Server state: %s, task_state: %s", serverState.Status, serverState.TaskState)

                    // If server is rebooting, wait for it to complete
                    if serverState.TaskState == "reboot_started" || serverState.TaskState == "rebooting" {
                        logger.Infof("→ Server is rebooting, waiting up to 60s for completion...")
                        for i := 0; i < 60; i++ {
                            time.Sleep(1 * time.Second)
                            serverState, err = d.getServerState(context.TODO(), attachment.ServerID)
                            if err != nil {
                                break
                            }
                            if serverState.TaskState == "" || serverState.TaskState == "none" {
                                logger.Infof("✓ Server reboot completed (state: %s)", serverState.Status)
                                break
                            }
                            if i%10 == 0 {
                                logger.Infof("Still waiting... (task_state: %s)", serverState.TaskState)
                            }
                        }

                        // Check if reboot completed
                        if serverState.TaskState == "reboot_started" || serverState.TaskState == "rebooting" {
                            logger.Warnf("Server still rebooting after 60s, will try detach anyway")
                        }
                    }
                }

                // Force detach from other instance
                logger.Infof("→ Attempting force detach from server %s", attachment.ServerID)
                ctx := context.TODO()
                if err := volumeattach.Delete(ctx, d.computeClient, attachment.ServerID, attachment.ID).ExtractErr(); err != nil {
                    logger.Errorf("✗ Detach failed: %v", err)

                    // If detach failed due to instance state, wait and retry
                    if strings.Contains(err.Error(), "task_state") {
                        logger.Infof("→ Detach failed due to instance state, waiting 10s and retrying...")
                        time.Sleep(10 * time.Second)
                        if err := volumeattach.Delete(ctx, d.computeClient, attachment.ServerID, attachment.ID).ExtractErr(); err != nil {
                            return nil, fmt.Errorf("failed to detach volume from server %s after retry: %v", attachment.ServerID, err)
                        }
                        logger.Infof("✓ Detach succeeded on retry")
                    } else {
                        return nil, fmt.Errorf("failed to detach volume from server %s: %v", attachment.ServerID, err)
                    }
                }
                logger.Infof("✓ Detached successfully")

                logger.Infof("→ Waiting for volume to reach 'available' state...")
                vol, err = d.waitOnVolumeState(ctx, vol, "available")
                if err != nil {
                    logger.Errorf("✗ Timeout waiting for available state: %v", err)
                    return nil, fmt.Errorf("timeout waiting for volume to become available: %v", err)
                }
                logger.Infof("✓ Volume is now available")
                // After detach, vol.Attachments should be empty, so attachedToThisInstance stays false
                break
            }
        }
    } else {
        logger.Infof("Volume has no attachments (available)")
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
            return nil, fmt.Errorf("block device not found for volume %s: %v", vol.ID, err)
        }
    } else {
        // Volume already attached - need to find which device it is
        logger.Infof("Volume already attached to this instance")

        // ALWAYS search by volume ID (don't trust OpenStack device path)
        // OpenStack may report /dev/vdb but kernel creates /dev/vde
        logger.Infof("Searching for device by volume ID (ignoring OpenStack device path)...")
        devicePath, err = findDeviceByVolumeID(vol.ID)
        if err != nil {
            logger.Errorf("Failed to find device by volume ID: %v", err)

            // Wait a bit and retry (device might not be ready yet)
            logger.Infof("Waiting for device to appear...")
            time.Sleep(2 * time.Second)
            devicePath, err = findDeviceByVolumeID(vol.ID)
            if err != nil {
                return nil, fmt.Errorf("cannot find device for attached volume %s: %v", vol.ID, err)
            }
        }
        logger.Infof("Found device by volume ID: %s", devicePath)

        // Double-check that device is not already mounted elsewhere
        mounted, mountpoint, _ := isDeviceMounted(devicePath)
        if mounted {
            logger.Warnf("Device %s is already mounted at %s!", devicePath, mountpoint)
            // If it's mounted to the correct path, just return success
            if mountpoint == mountPath {
                logger.Infof("Device is already mounted at correct location")
                return &volume.MountResponse{Mountpoint: mountPath}, nil
            }
            // If mounted elsewhere, this is an error
            return nil, fmt.Errorf("device %s is already mounted at %s (expected %s)",
                devicePath, mountpoint, mountPath)
        }
    }

    logger.Infof("Using device: %s", devicePath)

    // Wait a bit for device to be fully ready after attach
    time.Sleep(2 * time.Second)

    // Check filesystem type
    fsType, err := getFilesystemType(devicePath)
    if err != nil {
        logger.Warnf("Error detecting filesystem (device may not be ready): %v", err)
        // Try waiting a bit more
        time.Sleep(3 * time.Second)
        fsType, err = getFilesystemType(devicePath)
        if err != nil {
            return nil, fmt.Errorf("detecting filesystem failed after retry: %v", err)
        }
    }

    if fsType == "" {
        logger.Infof("No filesystem detected, formatting device %s as ext4", devicePath)

        // Double-check the device is not mounted anywhere before formatting
        out, _ := exec.Command("lsblk", "-no", "MOUNTPOINT", devicePath).CombinedOutput()
        mountpoint := strings.TrimSpace(string(out))
        if mountpoint != "" {
            logger.Warnf("Device appears to be mounted at: %s", mountpoint)
            return nil, fmt.Errorf("device %s is already mounted at %s", devicePath, mountpoint)
        }

        if err := formatFilesystem(devicePath, r.Name, "ext4"); err != nil {
            return nil, fmt.Errorf("formatting failed: %v", err)
        }
        logger.Infof("Device %s formatted successfully", devicePath)
    } else {
        logger.Infof("Device %s already has filesystem: %s (skipping format)", devicePath, fsType)
    }

    if err = os.MkdirAll(mountPath, 0755); err != nil {
        return nil, fmt.Errorf("cannot create mount path: %v", err)
    }

    logger.Infof("Mounting %s to %s", devicePath, mountPath)
    if out, err := exec.Command("mount", devicePath, mountPath).CombinedOutput(); err != nil {
        if strings.Contains(string(out), "already mounted") {
            logger.Infof("Device already mounted, continuing...")
            return &volume.MountResponse{Mountpoint: mountPath}, nil
        }
        return nil, fmt.Errorf("mount failed: %s", out)
    }

    lostFoundPath := filepath.Join(mountPath, "lost+found")
    if _, err := os.Stat(lostFoundPath); err == nil {
        logger.Infof("Fixing permissions on lost+found directory")
        if out, err := exec.Command("chmod", "777", lostFoundPath).CombinedOutput(); err != nil {
            logger.Warnf("Failed to chmod lost+found: %s", out)
        }
        if out, err := exec.Command("rm", "-rf", lostFoundPath).CombinedOutput(); err != nil {
            logger.Warnf("Failed to remove lost+found: %s", out)
        } else {
            logger.Infof("Removed lost+found directory")
        }
    }

    logger.Infof("Setting permissions on mount point")
    if out, err := exec.Command("chmod", "-R", "777", mountPath).CombinedOutput(); err != nil {
        logger.Warnf("Failed to set permissions: %s", out)
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

func (d plugin) Path(r *volume.PathRequest) (*volume.PathResponse, error) {
    mountPath := filepath.Join(d.config.MountDir, r.Name)

    mounted, _ := isMounted(mountPath)
    if !mounted {
        log.Warnf("Path() called but volume not mounted, attempting mount...")

        _, err := d.Mount(&volume.MountRequest{
            Name: r.Name,
            ID:   r.Name,
        })
        if err != nil {
            log.Errorf("Auto-mount from Path() failed: %v", err)
        }
    }

	return &volume.PathResponse{
		Mountpoint: filepath.Join(d.config.MountDir, r.Name),
	}, nil
}

func (d plugin) Remove(r *volume.RemoveRequest) error {
    logger := log.WithFields(log.Fields{"name": r.Name, "action": "remove"})
    logger.Infof("Removing volume '%s'", r.Name)

    ctx := context.TODO()
    d.mutex.Lock()
    defer d.mutex.Unlock()

    vol, err := d.getByName(r.Name)
    if err != nil {
        logger.Warnf("Volume not found in OpenStack: %v", err)
        return err
    }

    mountPath := filepath.Join(d.config.MountDir, r.Name)

    mounted, err := isMounted(mountPath)
    if err != nil {
        logger.Warnf("Failed to check mount status: %v", err)
    }

    if mounted {
        logger.Infof("Volume is mounted at %s, unmounting...", mountPath)
        if out, err := exec.Command("umount", mountPath).CombinedOutput(); err != nil {
            logger.Errorf("Unmount failed: %s", out)
            logger.Infof("Attempting force unmount...")
            if out, err := exec.Command("umount", "-f", mountPath).CombinedOutput(); err != nil {
                logger.Errorf("Force unmount also failed: %s", out)
                logger.Infof("Attempting lazy unmount...")
                exec.Command("umount", "-l", mountPath).CombinedOutput()
            }
        } else {
            logger.Infof("Successfully unmounted %s", mountPath)
        }

        if err := os.Remove(mountPath); err != nil {
            logger.Warnf("Failed to remove mount directory: %v", err)
        }
    } else {
        logger.Infof("Volume is not mounted, skipping unmount")
    }

    if len(vol.Attachments) > 0 {
        logger.Infof("Volume has %d attachment(s), detaching...", len(vol.Attachments))

        for _, att := range vol.Attachments {
            logger.Infof("Detaching from server %s (attachment ID: %s)", att.ServerID, att.ID)
            if err := volumeattach.Delete(ctx, d.computeClient, att.ServerID, att.ID).ExtractErr(); err != nil {
                logger.Errorf("Detach failed: %v", err)
                return fmt.Errorf("failed to detach volume: %v", err)
            }
        }

        logger.Infof("Waiting for volume to reach 'available' state...")
        vol, err = d.waitOnVolumeState(ctx, vol, "available")
        if err != nil {
            logger.Errorf("Timeout waiting for available state: %v", err)
            logger.Warnf("Continuing with delete despite state issue...")
        } else {
            logger.Infof("Volume is now available")
        }
    } else {
        logger.Infof("Volume has no attachments")
    }

    logger.Infof("Deleting volume %s from OpenStack", vol.ID)
    if err := volumes.Delete(ctx, d.blockClient, vol.ID, volumes.DeleteOpts{}).ExtractErr(); err != nil {
        logger.Errorf("Delete failed: %v", err)
        return fmt.Errorf("failed to delete volume: %v", err)
    }

    logger.Infof("Volume '%s' removed successfully", r.Name)
    return nil
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
            return vol, fmt.Errorf("volume %s did not reach status %s within 60s (last status: %s)",
                vol.ID, status, vol.Status)
        case <-ticker.C:
            updated, err := volumes.Get(ctx, d.blockClient, vol.ID).Extract()
            if err != nil {
                log.Warnf("Error getting volume status: %v", err)
                continue
            }
            vol = updated
            log.Debugf("Volume %s status: %s (waiting for %s)", vol.ID, vol.Status, status)

            if vol.Status == status {
                return vol, nil
            }

            if vol.Status == "error" {
                return vol, fmt.Errorf("volume %s entered error state", vol.ID)
            }
        }
    }
}

// ServerState represents the state of a compute instance
type ServerState struct {
    Status    string
    TaskState string
}

// getServerState retrieves the current state of a compute instance
func (d plugin) getServerState(ctx context.Context, serverID string) (*ServerState, error) {
    type serverResponse struct {
        Server struct {
            Status    string `json:"status"`
            TaskState string `json:"OS-EXT-STS:task_state"`
        } `json:"server"`
    }

    url := fmt.Sprintf("%s/servers/%s", d.computeClient.ResourceBase, serverID)

    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-Auth-Token", d.computeClient.Token())
    req.Header.Set("Accept", "application/json")

    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
    }

    var data serverResponse
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        return nil, err
    }

    return &ServerState{
        Status:    data.Server.Status,
        TaskState: data.Server.TaskState,
    }, nil
}
