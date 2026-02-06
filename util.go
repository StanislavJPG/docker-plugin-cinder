package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    log "github.com/sirupsen/logrus"
)

var filesystems []string = []string{
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "fat",
    "fat32",
    "ntfs",
    "xfs",
}

func contains(slice []string, x string) bool {
    for _, s := range slice {
       if s == x {
          return true
       }
    }
    return false
}

func getFilesystemType(dev string) (string, error) {
    out, err := exec.Command("blkid", "-s", "TYPE", "-o", "value", dev).CombinedOutput()
    if err != nil {
       if len(out) == 0 {
          return "", nil
       }
       return "", errors.New(string(out))
    }
    return strings.TrimSpace(string(out)), nil
}

func formatFilesystem(dev, label, filesystem string) error {
    if !contains(filesystems, filesystem) {
       return fmt.Errorf("filesystem '%s' does not exist", filesystem)
    }

    path, err := exec.LookPath("mkfs." + filesystem)
    if err != nil {
       return fmt.Errorf("mkfs.%s not found", filesystem)
    }

    out, err := exec.Command(path, "-L", label, dev).CombinedOutput()
    if err != nil {
       return errors.New(string(out))
    }

    return nil
}

func findDeviceWithTimeout(existing []string) (string, error) {
    log.Infof("Starting device search. Existing devices: %v", existing)

    for i := 0; i < 20; i++ {
        time.Sleep(500 * time.Millisecond)
        devices, _ := filepath.Glob("/dev/vd*")
        log.Debugf("Iteration %d: found devices: %v", i, devices)

        var newDevices []string
        for _, d := range devices {
            isPartition := strings.HasSuffix(d, "1") ||
                          strings.HasSuffix(d, "2") ||
                          strings.HasSuffix(d, "3") ||
                          strings.HasSuffix(d, "4") ||
                          strings.HasSuffix(d, "5") ||
                          strings.HasSuffix(d, "6") ||
                          strings.HasSuffix(d, "7") ||
                          strings.HasSuffix(d, "8") ||
                          strings.HasSuffix(d, "9")

            if !contains(existing, d) && !isPartition {
                log.Infof("Found new device candidate: %s", d)
                newDevices = append(newDevices, d)
            }
        }

        if len(newDevices) > 0 {
            log.Infof("Returning new device: %s", newDevices[0])
            return newDevices[0], nil
        }
    }

    log.Errorf("Block device not found after 20 iterations")
    return "", fmt.Errorf("block device not found")
}

func isDirectoryPresent(path string) (bool, error) {
    stat, err := os.Stat(path)
    if os.IsNotExist(err) {
       return false, nil
    } else if err != nil {
       return false, err
    } else {
       return stat.IsDir(), nil
    }
}

// getInstanceIDFromMetadata retrieves the instance UUID from OpenStack metadata service
// This is more reliable than /etc/machine-id as it doesn't change on reboot
func getInstanceIDFromMetadata() (string, error) {
    // Try the OpenStack metadata service
    metadataURL := "http://169.254.169.254/openstack/latest/meta_data.json"

    client := &http.Client{
        Timeout: 2 * time.Second,
    }

    resp, err := client.Get(metadataURL)
    if err != nil {
        return "", fmt.Errorf("failed to contact metadata service: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return "", fmt.Errorf("metadata service returned status %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read metadata response: %v", err)
    }

    // Parse JSON to extract uuid
    var metadata map[string]interface{}
    if err := json.Unmarshal(body, &metadata); err != nil {
        return "", fmt.Errorf("failed to parse metadata JSON: %v", err)
    }

    uuid, ok := metadata["uuid"].(string)
    if !ok || uuid == "" {
        return "", fmt.Errorf("uuid not found in metadata")
    }

    return uuid, nil
}

// deviceExists checks if a device path exists
func deviceExists(devicePath string) bool {
    _, err := os.Stat(devicePath)
    return err == nil
}

// isDeviceMounted checks if a device is currently mounted anywhere
func isDeviceMounted(devicePath string) (bool, string, error) {
    out, err := exec.Command("findmnt", "-n", "-o", "TARGET", "-S", devicePath).CombinedOutput()
    if err != nil {
        // findmnt returns non-zero if device is not mounted
        return false, "", nil
    }

    mountpoint := strings.TrimSpace(string(out))
    if mountpoint != "" {
        return true, mountpoint, nil
    }

    return false, "", nil
}

// findDeviceByVolumeID finds a device by matching the volume ID with device serial
// OpenStack volumes expose their ID as the device serial number
// FIXED: Now checks if device is already mounted and skips it
func findDeviceByVolumeID(volumeID string) (string, error) {
    log.Infof("Searching for device with volume ID: %s", volumeID)

    devices, err := filepath.Glob("/dev/vd[b-z]")
    if err != nil {
        return "", fmt.Errorf("failed to list devices: %v", err)
    }

    // First pass: look for exact match that's not mounted
    for _, dev := range devices {
        // Skip partition devices
        if strings.ContainsAny(dev[len(dev)-1:], "0123456789") {
            continue
        }

        // Check if device is already mounted
        mounted, mountpoint, _ := isDeviceMounted(dev)
        if mounted {
            log.Debugf("Device %s is already mounted at %s, skipping", dev, mountpoint)
            continue
        }

        // Try to get device serial using udevadm or lsblk
        serial := getDeviceSerial(dev)
        log.Debugf("Device %s has serial: %s", dev, serial)

        // Match serial with volume ID
        // OpenStack truncates UUID to 20 chars for serial, so we check prefix match
        if serial != "" && len(serial) >= 20 {
            volumePrefix := volumeID
            if len(volumePrefix) > 20 {
                volumePrefix = volumePrefix[:20]
            }

            if strings.HasPrefix(volumeID, serial) || serial == volumePrefix {
                log.Infof("Found matching device %s for volume %s (serial: %s)", dev, volumeID, serial)
                return dev, nil
            }
        }
    }

    // Second pass: if no unmounted device found, try to find any match
    // (this shouldn't normally happen, but helps with debugging)
    for _, dev := range devices {
        if strings.ContainsAny(dev[len(dev)-1:], "0123456789") {
            continue
        }

        serial := getDeviceSerial(dev)
        if serial != "" && len(serial) >= 20 {
            volumePrefix := volumeID
            if len(volumePrefix) > 20 {
                volumePrefix = volumePrefix[:20]
            }

            if strings.HasPrefix(volumeID, serial) || serial == volumePrefix {
                mounted, mountpoint, _ := isDeviceMounted(dev)
                if mounted {
                    log.Warnf("Found device %s for volume %s but it's already mounted at %s",
                        dev, volumeID, mountpoint)
                }
                return dev, nil
            }
        }
    }

    return "", fmt.Errorf("no device found for volume ID %s", volumeID)
}

// getDeviceSerial tries to get device serial number
func getDeviceSerial(device string) string {
    // Try lsblk first (most reliable)
    out, err := exec.Command("lsblk", "-no", "SERIAL", device).CombinedOutput()
    if err == nil && len(out) > 0 {
        serial := strings.TrimSpace(string(out))
        if serial != "" {
            return serial
        }
    }

    // Try udevadm as fallback
    out, err = exec.Command("udevadm", "info", "--query=property", "--name="+device).CombinedOutput()
    if err == nil {
        lines := strings.Split(string(out), "\n")
        for _, line := range lines {
            if strings.HasPrefix(line, "ID_SERIAL=") || strings.HasPrefix(line, "ID_SERIAL_SHORT=") {
                parts := strings.SplitN(line, "=", 2)
                if len(parts) == 2 && parts[1] != "" {
                    return strings.TrimSpace(parts[1])
                }
            }
        }
    }

    return ""
}
