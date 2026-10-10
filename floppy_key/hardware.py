"""Hardware controller and physical media sensor for USB Floppy drives.

Bypasses the Linux VFS page-cache trap by directly reading /sys/block/<dev>/size:
- size == 2880: 1.44MB physical floppy disk is present in drive.
- size == 0: floppy disk is physically ejected / no media.
"""

from dataclasses import dataclass
import errno
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("floppy_key.hardware")

KEY_FILE_NAME = ".floppy-key"
KEY_TMP_FILE_NAME = f"{KEY_FILE_NAME}.tmp"
LEGACY_VOLUME_ANCHOR_FILE = ".floppy-uuid"
FLOPPY_SECTOR_COUNT = 2880  # 1.44MB (2880 * 512 bytes)


class KeyFileError(Exception):
    """A key file exists on the disk but is unreadable or malformed."""


class WriteProtectedError(PermissionError):
    """The floppy could not be written at all (nothing was modified)."""


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

    candidates = []
    for item in sys_block.iterdir():
        if item.name.startswith(("loop", "zram", "nvme", "dm-", "md", "sr", "ram")):
            continue

        dev_name = item.name
        dev_path = f"/dev/{dev_name}"

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

            is_floppy = False
            if id_type == "floppy":
                is_floppy = True
            elif "teac" in vendor.lower() or "teac" in model.lower() or "floppy" in model.lower():
                is_floppy = True
            elif id_bus == "usb":
                size_file = item / "size"
                if size_file.is_file():
                    try:
                        if int(size_file.read_text().strip()) == FLOPPY_SECTOR_COUNT:
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
        for c in candidates:
            if is_disk_present(c):
                return c
        return candidates[0]

    return None


def device_still_attached(device: FloppyDevice) -> bool:
    """Cheap check that a previously discovered drive is still connected."""
    return device.sysfs_path.exists()


def is_disk_present(device: FloppyDevice) -> bool:
    """Read hardware sensor directly from sysfs.

    Returns True ONLY if physical 1.44MB media is detected (size == 2880).
    Returns False immediately when disk is ejected (size == 0).
    """
    size_file = device.sysfs_path / "size"
    if not size_file.is_file():
        return False

    try:
        return int(size_file.read_text().strip()) == FLOPPY_SECTOR_COUNT
    except Exception:
        return False


_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


def unescape_mount_path(raw: str) -> str:
    """Decode octal escapes (\\040, \\011, \\012, \\134) used in /proc/mounts."""
    return _MOUNT_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), raw)


def get_device_nodes(device: FloppyDevice) -> list[str]:
    """Return candidates for mountable device nodes (partition 1 if present, else disk)."""
    nodes = []
    part1 = device.sysfs_path / f"{device.name}1"
    if part1.is_dir():
        nodes.append(f"/dev/{device.name}1")
    nodes.append(device.dev_path)
    return nodes


def get_current_mount_point(device: FloppyDevice) -> Optional[Path]:
    """Check /proc/mounts for the existing mount point of the floppy device."""
    candidate_devs = set(get_device_nodes(device))
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in candidate_devs:
                    mp = Path(unescape_mount_path(parts[1]))
                    if mp.is_dir():
                        return mp
    except Exception as e:
        logger.debug("Failed reading /proc/mounts: %s", e)

    return None


def _udisks_unmount(device: FloppyDevice) -> None:
    for node in get_device_nodes(device):
        try:
            subprocess.run(
                ["udisksctl", "unmount", "-b", node, "--force", "--no-user-interaction"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception as e:
            logger.warning("udisksctl unmount failed for %s: %s", node, e)


def ensure_mounted(
    device: FloppyDevice, require_writable: bool = False, read_only: bool = False
) -> Optional[Path]:
    """Ensure the floppy disk is mounted and return the mount path.

    - require_writable: if an existing mount is not writable, remount once.
      The returned mount may still be read-only (e.g. write-protect tab set);
      callers that need to write must handle WriteProtectedError.
    - read_only: when a fresh mount is needed, mount with `ro` to minimise
      filesystem writes on untrusted media (used at the lock screen).
    """
    if not is_disk_present(device):
        logger.debug("Cannot mount: physical disk not present.")
        return None

    mp = get_current_mount_point(device)
    if mp:
        if require_writable and not os.access(mp, os.W_OK):
            logger.info("Existing mount %s is not writable by current user. Remounting...", mp)
            _udisks_unmount(device)
        else:
            return mp

    base_opts = ["ro"] if (read_only and not require_writable) else []
    attempts = [
        ",".join(base_opts + [f"uid={os.getuid()}", f"gid={os.getgid()}"]),
        ",".join(base_opts),
    ]

    target_node = get_device_nodes(device)[0]
    try:
        res = None
        for opts in attempts:
            cmd = ["udisksctl", "mount", "-b", target_node, "--no-user-interaction"]
            if opts:
                cmd += ["-o", opts]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                break
            logger.debug("Mount with options '%s' failed: %s", opts, res.stderr.strip())

        # Parse output: "Mounted /dev/sdb at /run/media/colimy/FLOPPY DISK."
        if res is not None and res.returncode == 0:
            out = res.stdout.strip()
            if " at " in out:
                raw_target = out.split(" at ", 1)[1].rstrip(".")
                p = Path(raw_target)
                if p.is_dir():
                    return p
            for part in out.split():
                if part.startswith("/"):
                    p = Path(part.rstrip("."))
                    if p.is_dir():
                        return p
    except Exception as e:
        logger.warning("udisksctl mount failed: %s", e)

    # Re-check mount table in case udisksctl succeeded but output was not parseable
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
        _udisks_unmount(device)


def _parse_key_file(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise KeyFileError(f"{path.name}: unreadable ({e})") from e

    if not isinstance(data, dict):
        raise KeyFileError(f"{path.name}: not a JSON object")
    for field in ("key_id", "token"):
        value = data.get(field)
        if not isinstance(value, str) or not value or not value.isascii():
            raise KeyFileError(f"{path.name}: field '{field}' missing or malformed")
    return data


def read_key_file(mount_point: Path) -> Optional[Dict[str, Any]]:
    """Read and validate the key file from the mounted disk.

    Falls back to the temporary file left by an interrupted write, since
    rename on FAT is not crash-atomic.

    Returns:
        The key payload, or None if no key file exists at all.
    Raises:
        KeyFileError if a key file exists but neither copy is valid.
    """
    key_path = mount_point / KEY_FILE_NAME
    tmp_path = mount_point / KEY_TMP_FILE_NAME

    primary_error: Optional[KeyFileError] = None
    if key_path.is_file():
        try:
            return _parse_key_file(key_path)
        except KeyFileError as e:
            primary_error = e
            logger.warning("Primary key file invalid: %s", e)

    if tmp_path.is_file():
        try:
            data = _parse_key_file(tmp_path)
            logger.info("Recovered key from interrupted write (%s).", KEY_TMP_FILE_NAME)
            return data
        except KeyFileError as e:
            raise primary_error or e

    if primary_error:
        raise primary_error
    return None


_WRITE_PROTECT_ERRNOS = (errno.EACCES, errno.EPERM, errno.EROFS)


def write_key_file(mount_point: Path, payload: Dict[str, Any]) -> Path:
    """Write the key file via temp file + rename and sync to physical media.

    Raises:
        WriteProtectedError: the temp file could not even be created, so the
            disk is guaranteed to be unmodified.
        OSError: any later failure; the on-disk state is then uncertain.
    """
    key_path = mount_point / KEY_FILE_NAME
    tmp_path = mount_point / KEY_TMP_FILE_NAME

    try:
        f = open(tmp_path, "w", encoding="utf-8")
    except OSError as e:
        if e.errno in _WRITE_PROTECT_ERRNOS:
            raise WriteProtectedError(
                f"Cannot write key to floppy disk: {e}. "
                "Check whether the write-protect tab on the 3.5\" disk is open "
                "or the disk is mounted read-only."
            ) from e
        raise

    with f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())

    tmp_path.replace(key_path)
    os.sync()
    return key_path


def _overwrite_and_unlink(path: Path) -> bool:
    """Overwrite file contents in place (no truncation), sync, then delete."""
    if not path.is_file():
        return False
    try:
        size = path.stat().st_size
        if size > 0:
            # r+b keeps the existing cluster allocation on FAT, unlike "wb"
            # which truncates first and may write the noise elsewhere.
            with open(path, "r+b") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        os.sync()
        return True
    except Exception as e:
        logger.warning("Failed to wipe %s: %s", path, e)
        return False


def wipe_key_file(mount_point: Path) -> bool:
    """Overwrite and remove key files (and the legacy volume anchor) from the disk."""
    wiped = False
    for name in (KEY_FILE_NAME, KEY_TMP_FILE_NAME):
        if _overwrite_and_unlink(mount_point / name):
            wiped = True

    anchor_path = mount_point / LEGACY_VOLUME_ANCHOR_FILE
    if anchor_path.is_file():
        try:
            anchor_path.unlink()
            os.sync()
            wiped = True
        except Exception:
            pass

    return wiped
