"""Hardware controller and physical media sensor for USB Floppy drives.

Bypasses the Linux VFS page-cache trap by directly reading /sys/block/<dev>/size:
- size == 2880: 1.44MB physical floppy disk is present in drive.
- size == 0: floppy disk is physically ejected / no media.
"""

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("floppy_key.hardware")

KEY_FILE_NAME = ".floppy-key"
FLOPPY_SECTOR_COUNT = 2880  # 1.44MB (2880 * 512 bytes)


@dataclass
class FloppyDevice:
    name: str           # e.g. "sdb"
    dev_path: str       # e.g. "/dev/sdb"
    sysfs_path: Path    # e.g. Path("/sys/block/sdb")
    vendor: str
    model: str


def find_floppy_device() -> Optional[FloppyDevice]:
    """Auto-discover a connected USB floppy drive in /sys/block.

    Detects via udev properties (ID_TYPE=floppy, ID_BUS=usb, TEAC/floppy models)
    or block size matching 2880 sectors.
    """
    sys_block = Path("/sys/block")
    if not sys_block.is_dir():
        return None

    # Search all block devices
    candidates = []
    for item in sys_block.iterdir():
        if item.name.startswith("loop") or item.name.startswith("zram") or item.name.startswith("nvme"):
            continue

        dev_name = item.name
        dev_path = f"/dev/{dev_name}"

        # Inspect udev properties
        try:
            res = subprocess.run(
                ["udevadm", "info", "-q", "property", "-p", str(item)],
                capture_output=True,
                text=True,
                timeout=2,
            )
            props = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

            id_type = props.get("ID_TYPE", "").lower()
            id_bus = props.get("ID_BUS", "").lower()
            vendor = props.get("ID_VENDOR", "")
            model = props.get("ID_MODEL", "")

            # Check if identified as floppy
            is_floppy = False
            if id_type == "floppy":
                is_floppy = True
            elif "teac" in vendor.lower() or "teac" in model.lower() or "floppy" in model.lower():
                is_floppy = True
            elif id_bus == "usb":
                size_file = item / "size"
                if size_file.is_file():
                    try:
                        sz = int(size_file.read_text().strip())
                        if sz == FLOPPY_SECTOR_COUNT:
                            is_floppy = True
                    except Exception:
                        pass

            if is_floppy:
                candidates.append(
                    FloppyDevice(
                        name=dev_name,
                        dev_path=dev_path,
                        sysfs_path=item,
                        vendor=vendor,
                        model=model,
                    )
                )
        except Exception as e:
            logger.debug("Failed checking block device %s: %s", dev_name, e)

    if candidates:
        # Prefer device with media inserted if multiple
        for c in candidates:
            if is_disk_present(c):
                return c
        return candidates[0]

    return None


def is_disk_present(device: FloppyDevice) -> bool:
    """Read hardware sensor directly from sysfs.

    Returns True ONLY if physical 1.44MB media is detected (size == 2880).
    Returns False immediately when disk is ejected (size == 0).
    """
    size_file = device.sysfs_path / "size"
    if not size_file.is_file():
        return False

    try:
        size = int(size_file.read_text().strip())
        return size == FLOPPY_SECTOR_COUNT
    except Exception:
        return False


def get_current_mount_point(device: FloppyDevice) -> Optional[Path]:
    """Check /proc/mounts for the existing mount point of the floppy device."""
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == device.dev_path:
                    # In /proc/mounts spaces are escaped as \040
                    raw_mp = parts[1].replace("\\040", " ")
                    mp = Path(raw_mp)
                    if mp.is_dir():
                        return mp
    except Exception as e:
        logger.debug("Failed reading /proc/mounts: %s", e)

    return None


def ensure_mounted(device: FloppyDevice, require_writable: bool = False) -> Optional[Path]:
    """Ensure the floppy disk is mounted and return the mount path.

    Mounts via udisksctl with current user's UID/GID to guarantee write access.
    If already mounted but not writable by the user, remounts cleanly.
    """
    if not is_disk_present(device):
        logger.debug("Cannot mount: physical disk not present.")
        return None

    mp = get_current_mount_point(device)
    if mp:
        if require_writable and not os.access(mp, os.W_OK):
            logger.info("Existing mount %s is not writable by current user. Remounting...", mp)
            try:
                subprocess.run(
                    ["udisksctl", "unmount", "-b", device.dev_path, "--force", "--no-user-interaction"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except Exception as e:
                logger.warning("Unmount before remount failed: %s", e)
            mp = None
        else:
            return mp

    # Try mounting via udisksctl with explicit user ownership options
    uid = os.getuid()
    gid = os.getgid()
    opts = f"uid={uid},gid={gid}"

    try:
        res = subprocess.run(
            ["udisksctl", "mount", "-b", device.dev_path, "-o", opts, "--no-user-interaction"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            logger.debug("Mount with options '%s' failed, retrying without options: %s", opts, res.stderr.strip())
            res = subprocess.run(
                ["udisksctl", "mount", "-b", device.dev_path, "--no-user-interaction"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        # Parse output: "Mounted /dev/sdb at /run/media/colimy/disk"
        for part in res.stdout.split():
            if part.startswith("/"):
                p = Path(part)
                if p.is_dir():
                    return p
    except Exception as e:
        logger.warning("udisksctl mount failed: %s", e)

    # Re-check mount table in case udisksctl succeeded asynchronously
    time.sleep(0.5)
    return get_current_mount_point(device)


def force_unmount_if_stale(device: FloppyDevice) -> None:
    """Purge stale mount point when physical disk is ejected (size == 0).

    Forces udisksctl unmount so Linux VFS drops cached metadata and blocks.
    """
    if is_disk_present(device):
        return

    mp = get_current_mount_point(device)
    if mp:
        logger.info("Cleaning up stale mount for ejected disk: %s", mp)
        try:
            subprocess.run(
                ["udisksctl", "unmount", "-b", device.dev_path, "--force", "--no-user-interaction"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception as e:
            logger.debug("Cleanup unmount failed: %s", e)


def read_key_file(mount_point: Path) -> Optional[Dict[str, Any]]:
    """Read and parse the .floppy-key token file from the mounted disk."""
    key_path = mount_point / KEY_FILE_NAME
    if not key_path.is_file():
        return None

    try:
        with open(key_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to parse key file %s: %s", key_path, e)
        return None


def write_key_file(mount_point: Path, payload: Dict[str, Any]) -> Path:
    """Write the .floppy-key token file and sync filesystem to physical media."""
    key_path = mount_point / KEY_FILE_NAME

    # Remove existing key file if present to prevent permission conflict on overwrite
    if key_path.exists():
        try:
            key_path.unlink()
        except Exception as e:
            logger.debug("Could not unlink existing key file: %s", e)

    try:
        with open(key_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except PermissionError as e:
        raise PermissionError(
            f"Cannot write key to floppy disk: {e}.\n"
            "Please check if the physical write-protect tab on the back of the 3.5\" floppy disk is open (locked) "
            "or if the disk is mounted read-only."
        ) from e

    # Flush all buffers to magnetic media
    os.sync()
    return key_path


VOLUME_ANCHOR_FILE = ".floppy-uuid"


def get_disk_volume_id(device: FloppyDevice, mount_point: Path, create_if_missing: bool = False) -> str:
    """Retrieve or initialize a persistent volume identifier for the floppy media.

    Combines the filesystem UUID (if present via udev) with a persistent on-disk anchor.
    """
    udev_uuid = ""
    try:
        res = subprocess.run(
            ["udevadm", "info", "-q", "property", "-p", str(device.sysfs_path)],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            if line.startswith("ID_FS_UUID="):
                udev_uuid = line.split("=", 1)[1].strip()
                break
    except Exception:
        pass

    anchor_path = mount_point / VOLUME_ANCHOR_FILE
    disk_anchor = ""
    if anchor_path.is_file():
        try:
            disk_anchor = anchor_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    if not disk_anchor and create_if_missing:
        import uuid
        disk_anchor = str(uuid.uuid4())
        try:
            anchor_path.write_text(disk_anchor + "\n", encoding="utf-8")
            os.sync()
        except Exception as e:
            logger.debug("Failed writing volume anchor: %s", e)

    if udev_uuid and disk_anchor:
        return f"{udev_uuid}-{disk_anchor}"
    elif udev_uuid:
        return udev_uuid
    elif disk_anchor:
        return disk_anchor
    else:
        return "unidentified-volume"


def wipe_key_file(mount_point: Path) -> bool:
    """Wipe and remove .floppy-key and .floppy-uuid from the floppy disk."""
    key_path = mount_point / KEY_FILE_NAME
    wiped = False
    if key_path.is_file():
        try:
            sz = key_path.stat().st_size
            if sz > 0:
                with open(key_path, "wb") as f:
                    f.write(os.urandom(sz))
                os.sync()
            key_path.unlink()
            os.sync()
            wiped = True
        except Exception as e:
            logger.warning("Failed to wipe key file: %s", e)

    anchor_path = mount_point / VOLUME_ANCHOR_FILE
    if anchor_path.is_file():
        try:
            anchor_path.unlink()
            os.sync()
            wiped = True
        except Exception:
            pass

    return wiped
