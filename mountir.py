#!/usr/bin/env python3
r"""
    __  ___                  __  ________
   /  |/  /___  __  ______  / /_/  _/ __ \
  / /|_/ / __ \/ / / / __ \/ __// // /_/ /
 / /  / / /_/ / /_/ / / / / /__/ // _, _/
/_/  /_/\____/\__,_/_/ /_/\__/___/_/ |_|

MountIR - Forensic Disk Image Mounting Utility
"""

MOUNTIR_VERSION = "1.0.0"

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Ensure script directory is on the path for local imports
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils import (
    logger, setup_logging, check_root, generate_mount_id,
    ensure_mount_dir, cleanup_mount_dir, format_bytes, run_command,
    find_mounts_under, loop_devices_backing,
    Fore, Style, HAS_COLOR,
)
from detector import (
    ImageType, detect_image_type, find_images_in_dir, is_bundle_image,
    _is_secondary_segment, SUPPORTED_FORMATS, display_format,
)
from handlers import get_handler, ALL_HANDLER_CLASSES, NO_PARTITION_TYPES
from handlers.base import MountResult
from partition import (
    expose_partitions, mount_partition, unmount_partitions,
    detect_lvm, activate_lvm, deactivate_lvm,
    infer_os, kernel_filesystems, PartitionInfo, _enrich_with_blkid,
)
from state import StateManager, MountedImage, MountedPartition
import zfs
import bootstrap


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
    __  ___                  __  ________
   /  |/  /___  __  ______  / /_/  _/ __ \
  / /|_/ / __ \/ / / / __ \/ __// // /_/ /
 / /  / / /_/ / /_/ / / / / /__/ // _, _/
/_/  /_/\____/\__,_/_/ /_/\__/___/_/ |_|
"""


def print_banner():
    """Print the MountIR banner to stderr."""
    version_line = f"  MountIR v{MOUNTIR_VERSION} - Forensic Disk Image Mounting"

    if HAS_COLOR:
        print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}", file=sys.stderr)
        print(f"{Fore.WHITE}{Style.BRIGHT}{version_line}{Style.RESET_ALL}\n",
              file=sys.stderr)
    else:
        print(BANNER, file=sys.stderr)
        print(f"{version_line}\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Command: mount
# ---------------------------------------------------------------------------
def cmd_mount(args):
    """Mount one or more forensic disk images.

    Accepts a single image, several images/globs, or a directory to scan for
    every recognised image inside it (see :func:`_collect_images`).  Each image
    is mounted independently under its own ``<mount-base>/<mount-id>`` tree; a
    failure on one image is logged and the rest still mount.
    """
    # Handle JSON input mode (Whirlpool integration)
    if args.json_input:
        _apply_json_input(args)

    # Root check
    if not check_root():
        logger.error("MountIR requires root privileges. Run with sudo.")
        sys.exit(1)

    # Resolve the image list (expands directories and globs).
    images = _collect_images(args)
    if not images:
        logger.error("No image(s) found to mount")
        sys.exit(1)

    multi = len(images) > 1
    if multi:
        logger.info("Found %d image(s) to mount", len(images))

    state_mgr = StateManager()
    json_objects = []
    success = 0
    for image_path in images:
        outcome = _mount_one_image(image_path, args, state_mgr)
        if outcome is None:
            continue
        success += 1
        mounted, partition_infos = outcome
        if getattr(args, "json", False):
            json_objects.append(_build_json_output(mounted, partition_infos))

    if multi:
        logger.info("Mounted %d of %d image(s)", success, len(images))

    if getattr(args, "json", False):
        # Preserve the single-object shape for back-compat (Whirlpool); only
        # wrap in a list when several images were mounted in one invocation.
        if multi:
            print(json.dumps({"mounts": json_objects}, indent=2))
        elif json_objects:
            print(json.dumps(json_objects[0], indent=2))

    # A single explicit image that failed should be a hard error (exit 1), as
    # before; a multi-image run is best-effort and only fails if nothing mounted.
    if success == 0:
        sys.exit(1)


def _mount_one_image(image_path: Path, args, state_mgr: StateManager):
    """Mount a single image and record its state.

    Returns ``(MountedImage, [PartitionInfo, ...])`` on success, or ``None`` on
    failure (after logging).  Never raises for a per-image problem, so a
    multi-image run keeps going.
    """
    force = getattr(args, "force", False)

    if not image_path.exists():
        logger.error("Image not found: %s", image_path)
        return None

    # Detect image type
    image_type = detect_image_type(image_path)
    if image_type == ImageType.UNKNOWN:
        logger.error("Unrecognized image format: %s", image_path)
        logger.error("Supported formats: %s", SUPPORTED_FORMATS)
        return None
    logger.info("Detected image type: %s (%s)", display_format(image_path, image_type), image_path.name)

    # Get handler and check tools
    handler = get_handler(image_type)
    tool_status = handler.check_tools()
    if not tool_status["usable"]:
        logger.error(
            "Missing required tools for %s: %s",
            handler.format_name, ", ".join(tool_status["missing"]),
        )
        logger.error("Install dependencies with: mountir setup")
        return None
    if tool_status.get("fallback_in_use"):
        logger.info("Using fallback tools for %s", handler.format_name)

    # Create mount hierarchy
    mount_base = Path(args.mount_base)
    case_id = getattr(args, "case_id", None) or ""
    mount_id = generate_mount_id(case_id, image_path.stem)
    image_mount_dir = mount_base / mount_id
    container_dir = image_mount_dir / "container"
    partitions_dir = image_mount_dir / "partitions"

    ensure_mount_dir(container_dir)
    ensure_mount_dir(partitions_dir)

    # Mount the container
    logger.info("Mounting container: %s", image_path.name)
    result = handler.mount(image_path, container_dir)
    if not result.success:
        logger.error("Container mount failed (%s): %s", image_path.name, result.error)
        cleanup_mount_dir(image_mount_dir)
        return None

    # Track state for building the MountedImage
    secondary_loop = ""
    partition_infos = []
    lvm_vg_names = []
    partition_loops = []  # per-partition offset loop devices we created
    zfs_pools = []  # ZFS pools we imported (exported on unmount)

    # Detect and mount partitions
    skip_partitions = (
        getattr(args, "no_partitions", False) or
        image_type in NO_PARTITION_TYPES
    )

    if not skip_partitions:
        # Read the partition table from / back offset loops with a block device
        # when the handler produced one (NBD / raw loop), else the FUSE-exposed
        # raw image file (EWF / AFF).
        backing = result.block_device or (
            str(result.raw_image_path) if result.raw_image_path else ""
        )
        if backing:
            partition_infos, partition_loops = expose_partitions(backing, force=force)

            # LVM physical volumes may live on the exposed partition devices.
            part_devices = [p.device for p in partition_infos if p.device]
            lvm_vg_names = detect_lvm(part_devices)
            if lvm_vg_names:
                lv_paths = activate_lvm(lvm_vg_names)
                for i, lv_path in enumerate(lv_paths):
                    lv_part = PartitionInfo(device=lv_path, number=200 + i)
                    _enrich_with_blkid(lv_part)
                    partition_infos.append(lv_part)

        # Mount each partition
        for part in partition_infos:
            part_mount = partitions_dir / _partition_dir_name(part)
            mount_partition(part, part_mount, force=force)

        # Import any ZFS pools living on the exposed devices (read-only). The
        # zfs_member partitions above are intentionally skipped by
        # mount_partition; the pool is brought online here instead.
        zfs_pools, zfs_dataset_infos = _import_zfs_pools(partition_infos, image_mount_dir)
        partition_infos.extend(zfs_dataset_infos)

    elif image_type in NO_PARTITION_TYPES:
        logger.info(
            "Skipping partition detection (%s has no partition table)",
            display_format(image_path, image_type),
        )

    # Save state
    mounted = MountedImage(
        mount_id=mount_id,
        image_path=str(image_path),
        image_type=image_type.value,
        case_id=case_id,
        mount_base=str(mount_base),
        container_mount=str(container_dir),
        block_device=result.block_device or "",
        loop_device=result.loop_device or "",
        secondary_loop=secondary_loop,
        partition_loops=partition_loops,
        raw_image_path=str(result.raw_image_path or ""),
        partitions=[
            MountedPartition(
                device=p.device,
                number=p.number,
                filesystem=p.filesystem,
                mount_point=str(p.mount_point or ""),
                label=p.label,
                size_bytes=p.size_bytes,
                mounted=p.mounted,
            )
            for p in partition_infos
        ],
        lvm_vg_names=lvm_vg_names,
        zfs_pools=zfs_pools,
        mounted_at=datetime.now().isoformat(),
        handler_class=handler.__class__.__name__,
    )
    state_mgr.add_mount(mounted)

    # Print summary
    _print_mount_summary(mount_id, image_path, image_type, result,
                          partition_infos, image_mount_dir, args)

    return mounted, partition_infos


def _collect_images(args):
    """Resolve the ``mount`` arguments into a de-duplicated list of image paths.

    Each entry may be a single image file, a shell glob (also expanded here so
    quoted patterns work), or a directory to scan for recognised images
    (honouring ``--recursive`` and ``--pattern``).  Explicit files are taken
    as-is (type detection happens later); directory scans skip continuation
    segments so a multi-part set resolves to one mount.
    """
    import glob

    raw = getattr(args, "image_path", None)
    if isinstance(raw, str):
        raw = [raw]
    raw = raw or []

    recursive = getattr(args, "recursive", False)
    pattern = getattr(args, "pattern", None)

    images = []
    seen = set()

    def _add(path: Path) -> None:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key not in seen:
            seen.add(key)
            images.append(path)

    for entry in raw:
        has_glob = any(c in entry for c in "*?[")
        matches = sorted(glob.glob(entry))
        if has_glob and not matches:
            logger.warning("No files matched pattern: %s", entry)
            continue
        expanded = [Path(p) for p in matches] or [Path(entry)]
        for p in expanded:
            # A directory is scanned for images -- unless it's itself a bundle
            # image (macOS .sparsebundle), which we mount rather than scan into.
            if p.is_dir() and not is_bundle_image(p):
                found = find_images_in_dir(p, recursive=recursive, pattern=pattern)
                if not found:
                    logger.warning("No mountable images found in directory: %s", p)
                for f in found:
                    _add(f)
            elif p.exists():
                # A wildcard behaves like a mini directory scan, so drop
                # continuation pieces (e.g. '<set>.*' matching .E02/.002). An
                # explicitly-named single file is always taken as-is.
                if has_glob and _is_secondary_segment(p):
                    logger.debug("Skipping continuation segment from glob: %s", p)
                    continue
                _add(p)
            else:
                logger.error("Image not found: %s", p)

    return images


def _import_zfs_pools(partition_infos, image_mount_dir: Path):
    """Import ZFS pools found on the exposed devices, read-only.

    Returns ``(pool_names, dataset_infos)``: the imported pool names (to export
    on unmount) and PartitionInfo rows for each mounted dataset (for the
    summary and state). Pools are imported under ``<image>/zfs/<pool>`` so the
    evidence filesystem tree is reconstructed inside our managed mount dir.
    """
    vdevs = [p.device for p in partition_infos
             if p.device and p.filesystem == "zfs_member"]
    if not vdevs:
        return [], []
    if not zfs.zfs_available():
        logger.warning(
            "ZFS member device(s) present but zpool/zfs aren't installed - "
            "skipping pool import. Install zfsutils-linux (mountir setup).")
        return [], []

    candidates = zfs.scan_pools(vdevs)
    if not candidates:
        logger.warning(
            "ZFS member device(s) present but no importable pool was found "
            "(the pool may span vdevs held in other images).")
        return [], []

    pool_names, dataset_infos = [], []
    number = 300
    for cand in candidates:
        altroot = image_mount_dir / "zfs" / cand.name
        ensure_mount_dir(altroot)
        effective = zfs.import_pool(cand, altroot, vdevs)
        if not effective:
            continue
        pool_names.append(effective)
        for dataset, mountpoint in zfs.mount_datasets(effective):
            dataset_infos.append(PartitionInfo(
                device=dataset, number=number, filesystem="zfs",
                label=dataset, mount_point=Path(mountpoint), mounted=True,
            ))
            number += 1
    return pool_names, dataset_infos


def _partition_dir_name(part) -> str:
    """Build a readable mount-point dir name like 'p2_ntfs_Windows'.

    Uses the filesystem label when present, otherwise the GPT partition name.
    Both are sanitised to a filesystem-safe slug.
    """
    name = f"p{part.number}"
    if part.filesystem:
        name += f"_{part.filesystem}"
    label = part.label or getattr(part, "pt_name", "")
    if label:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "", label)[:32]
        if safe:
            name += f"_{safe}"
    return name


def _apply_json_input(args):
    """Parse JSON input and apply to args."""
    json_path = args.json_input
    if json_path == "-":
        data = json.load(sys.stdin)
    else:
        data = json.loads(Path(json_path).read_text(encoding="utf-8"))

    # Apply JSON fields to args
    if "image_path" in data:
        args.image_path = data["image_path"]
    if "case_id" in data:
        args.case_id = data["case_id"]
    if "mount_base" in data:
        args.mount_base = data["mount_base"]

    opts = data.get("mount_options", {})
    if opts.get("no_partitions"):
        args.no_partitions = True


def _print_mount_summary(mount_id, image_path, image_type, result,
                          partitions, image_mount_dir, args):
    """Print a human-readable mount summary."""
    mounted_count = sum(1 for p in partitions if p.mounted)
    failed_count = sum(1 for p in partitions if p.mount_error)
    skipped_count = sum(1 for p in partitions
                        if not p.mounted and not p.mount_error)

    print(file=sys.stderr)
    _h = lambda s: f"{Fore.GREEN}{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLOR else s
    _v = lambda s: f"{Fore.WHITE}{s}{Style.RESET_ALL}" if HAS_COLOR else s

    print(_h("Mount Summary"), file=sys.stderr)
    print(_h("=" * 50), file=sys.stderr)
    print(f"  {'Image:':<18} {_v(image_path.name)}", file=sys.stderr)
    print(f"  {'Type:':<18} {_v(display_format(image_path, image_type))}", file=sys.stderr)
    os_hint = infer_os(partitions)
    if os_hint != "Unknown":
        print(f"  {'Likely OS:':<18} {_v(os_hint)}", file=sys.stderr)
    print(f"  {'Mount ID:':<18} {_v(mount_id)}", file=sys.stderr)
    print(f"  {'Mount Dir:':<18} {_v(str(image_mount_dir))}", file=sys.stderr)

    if result.block_device:
        print(f"  {'Block Device:':<18} {_v(result.block_device)}", file=sys.stderr)
    if result.raw_image_path:
        print(f"  {'Raw Image:':<18} {_v(str(result.raw_image_path))}", file=sys.stderr)

    if partitions:
        print(f"\n  {'Partitions:':<18} {mounted_count} mounted", file=sys.stderr)
        _w = lambda s: f"{Fore.YELLOW}{s}{Style.RESET_ALL}" if HAS_COLOR else s
        if skipped_count:
            print(f"  {'Skipped:':<18} "
                  f"{skipped_count} not a mountable filesystem", file=sys.stderr)
        if failed_count:
            print(f"  {'Warnings:':<18} {_w(f'{failed_count} failed to mount')}",
                  file=sys.stderr)

        for p in partitions:
            fs_info = p.filesystem or getattr(p, "skip_reason", "") or "unknown"
            if p.label:
                fs_info += f" ({p.label})"
            if p.mounted:
                _ok = lambda s: f"{Fore.GREEN}{s}{Style.RESET_ALL}" if HAS_COLOR else s
                print(f"    {p.device:<20} {fs_info:<16} {_ok(str(p.mount_point))}",
                      file=sys.stderr)
            elif p.mount_error:
                _err = lambda s: f"{Fore.RED}{s}{Style.RESET_ALL}" if HAS_COLOR else s
                print(f"    {p.device:<20} {fs_info:<16} {_err('FAIL: ' + p.mount_error)}",
                      file=sys.stderr)
            else:
                # Deliberately not mounted: bootcode, swap, pool member, LVM PV.
                reason = getattr(p, "skip_reason", "") or p.filesystem or "no filesystem"
                print(f"    {p.device:<20} {fs_info:<16} "
                      f"{_w(f'skipped ({reason})')}", file=sys.stderr)

        # A filesystem bigger than its partition entry is exposed over a wider
        # window than the table describes; say so, it changes what the mounted
        # bytes mean.
        widened = [p for p in partitions
                   if getattr(p, "window_bytes", 0) > p.size_bytes > 0]
        if widened:
            print(f"\n  {'Extended windows:':<18} (filesystem larger than its "
                  f"partition entry)", file=sys.stderr)
            for p in widened:
                print(f"    {p.device:<20} table {p.size_bytes} B -> exposed "
                      f"{p.window_bytes} B", file=sys.stderr)

    # In best-effort (--force) mode, surface the raw block devices of anything
    # that couldn't be mounted so the analyst can image/carve them directly.
    if getattr(args, "force", False):
        raw_devices = [p.device for p in partitions
                       if p.device and not p.mounted and p.mount_error]
        if raw_devices:
            print(f"\n  {'Raw devices:':<18} (exposed for carving / manual mount)",
                  file=sys.stderr)
            for dev in raw_devices:
                print(f"    {dev}", file=sys.stderr)

    print(file=sys.stderr)


def _build_json_output(mounted, partitions) -> dict:
    """Build the machine-readable result object for one mounted image."""
    return {
        "mount_id": mounted.mount_id,
        "image_path": mounted.image_path,
        "image_type": mounted.image_type,
        "mount_base": mounted.mount_base,
        "block_device": mounted.block_device,
        "partitions": [
            {
                "device": p.device,
                "number": p.number,
                "filesystem": p.filesystem,
                "label": p.label,
                "mount_point": str(p.mount_point) if p.mount_point else None,
                "mounted": p.mounted,
            }
            for p in partitions
        ],
    }


# ---------------------------------------------------------------------------
# Command: unmount
# ---------------------------------------------------------------------------
def cmd_unmount(args):
    """Unmount previously mounted disk images."""
    if not check_root():
        logger.error("MountIR requires root privileges. Run with sudo.")
        sys.exit(1)

    state_mgr = StateManager()
    state = state_mgr.load()

    if not state.mounted_images:
        logger.info("No mounted images found")
        return

    if getattr(args, "all", False):
        targets = list(state.mounted_images)
    else:
        mount_ref = args.mount_point
        target = (
            state_mgr.find_by_mount_id(mount_ref) or
            state_mgr.find_by_path(mount_ref)
        )
        if not target:
            logger.error("No mounted image found for: %s", mount_ref)
            logger.info("Use 'mountir list' to see mounted images")
            sys.exit(1)
        targets = [target]

    success_count = 0
    for mounted in targets:
        if _unmount_single(mounted, state_mgr):
            success_count += 1

    logger.info("Unmounted %d of %d image(s)", success_count, len(targets))


def _umount_path(path: str) -> bool:
    """Unmount a path, falling back to a lazy unmount if it is busy.

    A busy mount (e.g. a shell with its cwd inside it) makes a normal umount
    fail; the lazy `umount -l` fallback detaches it so cleanup can proceed.
    """
    for cmd in (["umount", path], ["umount", "-l", path]):
        try:
            run_command(cmd, capture=False)  # check=True: raises on failure
            if "-l" in cmd:
                logger.warning("Lazy-unmounted busy path: %s", path)
            else:
                logger.debug("Unmounted: %s", path)
            return True
        except subprocess.CalledProcessError:
            continue
        except FileNotFoundError:
            logger.error("umount command not found")
            return False
    logger.error("Failed to unmount %s (in use? 'cd' out of it and retry)", path)
    return False


def _unmount_single(mounted: MountedImage, state_mgr: StateManager) -> bool:
    """Unmount a single image in reverse order.

    Order: partitions -> LVM -> secondary loop -> container. Returns True only
    when every layer was released (a lazy fallback still counts as released).
    """
    logger.info("Unmounting: %s (%s)", mounted.mount_id, mounted.image_path)
    all_ok = True

    # 0. Export ZFS pools first: this unmounts all their datasets and releases
    #    the vdev (offset-loop) devices, so it must happen before we detach the
    #    loops those pools sit on.
    for pool in getattr(mounted, "zfs_pools", []) or []:
        if not zfs.export_pool(pool):
            all_ok = False

    # 1. Unmount partitions (reverse order). ZFS datasets were already unmounted
    #    by the pool export above, so skip them here.
    for part in reversed(mounted.partitions):
        if part.filesystem == "zfs":
            continue
        if part.mounted and part.mount_point:
            if not _umount_path(part.mount_point):
                all_ok = False

    # 2. Deactivate LVM
    if mounted.lvm_vg_names:
        deactivate_lvm(mounted.lvm_vg_names)

    # 3. Detach per-partition offset loop devices (reverse order). These are
    #    backed by the raw image / whole-disk loop, so release them before the
    #    container/secondary loop they sit on.
    for loop in reversed(getattr(mounted, "partition_loops", []) or []):
        try:
            run_command(["losetup", "-d", loop], check=False, capture=False)
            logger.debug("Detached partition loop: %s", loop)
        except Exception:
            pass

    # 4. Detach secondary loop device (for FUSE raw images)
    if mounted.secondary_loop:
        try:
            run_command(["losetup", "-d", mounted.secondary_loop], check=False, capture=False)
            logger.debug("Detached secondary loop: %s", mounted.secondary_loop)
        except Exception:
            pass

    # 5. Unmount container
    try:
        handler = get_handler(ImageType(mounted.image_type))
        container_result = MountResult(
            success=True,
            mount_point=Path(mounted.container_mount) if mounted.container_mount else None,
            block_device=mounted.block_device or None,
            loop_device=mounted.loop_device or None,
        )
        if handler.unmount(container_result) is False:
            all_ok = False
    except Exception as e:
        logger.error("Failed to unmount container: %s", e)
        all_ok = False

    # 6. Cleanup directories (rmdir only removes empty dirs, so a still-busy
    #    mount is left in place rather than disturbed).
    if mounted.mount_base and mounted.mount_id:
        cleanup_mount_dir(Path(mounted.mount_base) / mounted.mount_id)

    # 7. Remove from state
    state_mgr.remove_mount(mounted.mount_id)
    if all_ok:
        logger.info("Successfully unmounted: %s", mounted.mount_id)
    else:
        logger.warning(
            "Unmounted %s with errors - a mount was busy. Make sure no shell "
            "or process is inside the mount, then retry.", mounted.mount_id,
        )
    return all_ok


# ---------------------------------------------------------------------------
# Command: list
# ---------------------------------------------------------------------------
def _filter_by_base(images, mount_base):
    """Return only images whose mount_base is at or under *mount_base*.

    ``mount_base`` of None means "no filter" (list everything).  Comparison is
    on the resolved path so ``-d /mnt/mountir`` matches a mount recorded with a
    trailing slash or a relative form.
    """
    if not mount_base:
        return list(images)
    base = str(Path(mount_base).resolve()).rstrip("/")
    matched = []
    for img in images:
        mb = str(Path(img.mount_base).resolve()).rstrip("/") if img.mount_base else ""
        if mb == base or mb.startswith(base + "/"):
            matched.append(img)
    return matched


def cmd_list(args):
    """List currently mounted disk images (optionally filtered by base dir)."""
    state_mgr = StateManager()
    state = state_mgr.load()

    mount_base = getattr(args, "mount_base", None)
    images = _filter_by_base(state.mounted_images, mount_base)

    if not images:
        if mount_base:
            logger.info("No mounted images under %s", mount_base)
        else:
            logger.info("No mounted images")
        return

    # Check for stale mounts
    stale = state_mgr.verify_mounts()
    stale_ids = {img.mount_id for img in stale}

    if getattr(args, "json", False):
        from dataclasses import asdict
        output = {
            "mounted_images": [asdict(img) for img in images],
            "stale_mount_ids": [i for i in stale_ids
                                if any(img.mount_id == i for img in images)],
        }
        print(json.dumps(output, indent=2))
        return

    _h = lambda s: f"{Fore.CYAN}{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLOR else s

    print(file=sys.stderr)
    print(_h(f"Mounted Images ({len(images)})"), file=sys.stderr)
    print(_h("=" * 70), file=sys.stderr)

    for img in images:
        status = ""
        if img.mount_id in stale_ids:
            status = f" {Fore.YELLOW}[STALE]{Style.RESET_ALL}" if HAS_COLOR else " [STALE]"

        print(f"\n  Mount ID:    {img.mount_id}{status}", file=sys.stderr)
        print(f"  Image:       {img.image_path}", file=sys.stderr)
        print(f"  Type:        {img.image_type.upper()}", file=sys.stderr)
        if img.case_id:
            print(f"  Case ID:     {img.case_id}", file=sys.stderr)
        print(f"  Mounted At:  {img.mounted_at}", file=sys.stderr)
        print(f"  Mount Dir:   {Path(img.mount_base) / img.mount_id}", file=sys.stderr)

        if img.block_device:
            print(f"  Block Dev:   {img.block_device}", file=sys.stderr)

        mounted_parts = [p for p in img.partitions if p.mounted]
        if mounted_parts:
            print(f"  Partitions:  {len(mounted_parts)} mounted", file=sys.stderr)
            for p in mounted_parts:
                fs = p.filesystem or "unknown"
                lbl = f" ({p.label})" if p.label else ""
                print(f"    {p.device:<20} {fs}{lbl:<16} -> {p.mount_point}",
                      file=sys.stderr)

    print(file=sys.stderr)

    listed_stale = [img for img in images if img.mount_id in stale_ids]
    if listed_stale:
        logger.warning(
            "%d stale mount(s) detected (may have been lost after reboot). "
            "Use 'unmount --all' to clean state.",
            len(listed_stale),
        )


# ---------------------------------------------------------------------------
# Command: check
# ---------------------------------------------------------------------------
def cmd_check(args):
    """Check tool dependency availability."""
    from utils import tool_exists

    # Format handlers: (label, [tools incl. fallbacks], apt package hint)
    handlers_to_check = [
        ("E01/L01/Ex01", ["ewfmount"], "ewf-tools"),
        ("DD/Raw/IMG", ["losetup"], "util-linux (built-in)"),
        ("VMDK", ["qemu-nbd", "vmdkmount"], "qemu-utils / libvmdk-utils"),
        ("VHD/VHDX", ["qemu-nbd", "vhdimount"], "qemu-utils / libvhdi-utils"),
        ("QCOW2", ["qemu-nbd"], "qemu-utils"),
        ("ISO", ["mount"], "util-linux (built-in)"),
        ("AFF", ["affuse"], "afflib-tools"),
    ]

    # Supporting tools
    support_tools = [
        ("fdisk", "util-linux (built-in)", "Partition detection"),
        ("blkid", "util-linux (built-in)", "Filesystem identification"),
        ("kpartx", "kpartx", "Partition mapping"),
        ("pvs", "lvm2", "LVM detection"),
        ("fusermount", "fuse", "FUSE unmounting"),
        ("file", "file (built-in)", "Image type detection"),
    ]

    # Filesystem drivers: (label, helper-binary-or-None, install hint,
    # description, in-kernel type name or None). A filesystem is available when
    # the kernel provides it *or* its userspace helper is installed, so both are
    # checked -- reporting "builtin" for a driver this kernel doesn't actually
    # have (WSL2 has no ufs) is worse than reporting nothing.
    kernel_fs = kernel_filesystems()
    fs_drivers = [
        ("NTFS", "ntfs-3g", "ntfs-3g", "Windows volumes", "ntfs3"),
        ("exFAT", "mount.exfat-fuse", "exfat-fuse",
         "exFAT (kernel 5.4+ also works)", "exfat"),
        ("HFS+", "fsck.hfsplus", "hfsprogs", "macOS legacy volumes", "hfsplus"),
        ("APFS", "apfs-fuse", "built from source: mountir setup",
         "macOS APFS volumes", None),
        ("VMFS3/5", "vmfs-fuse", "vmfs-tools", "VMware ESXi 5.x datastores", None),
        ("VMFS6", "vmfs6-fuse", "vmfs6-tools", "VMware ESXi 6.5+ datastores", None),
        ("ZFS", "zpool", "zfsutils-linux",
         "ZFS pools (also needs kernel module)", None),
        ("UFS", "fuse-ufs", "mountir setup --ufs",
         "FreeBSD/NetScaler/pfSense", "ufs"),
        ("ext2/3/4, XFS, btrfs, vfat", None, "built in", "Linux/Windows volumes",
         "ext4"),
    ]

    def _driver_status(tool, kernel_name):
        """(available, provider) for one filesystem-driver row."""
        if kernel_name and kernel_name in kernel_fs:
            return True, "kernel"
        if tool and tool_exists(tool):
            return True, tool
        return False, ""

    if getattr(args, "json", False):
        output = {"format_handlers": {}, "support_tools": {},
                  "filesystem_drivers": {}}
        for fmt, tools, pkg in handlers_to_check:
            output["format_handlers"][fmt] = {
                t: tool_exists(t) for t in tools
            }
        for tool, pkg, desc in support_tools:
            output["support_tools"][tool] = tool_exists(tool)
        for label, tool, hint, desc, kernel_name in fs_drivers:
            available, provider = _driver_status(tool, kernel_name)
            output["filesystem_drivers"][label] = {
                "available": available, "provider": provider,
            }
        output["ewfmount_version"] = bootstrap.installed_ewfmount_version()
        output["ewfmount_modern"] = bootstrap.have_modern_libewf()
        output["ewfmount_fuse"] = bootstrap.ewfmount_has_fuse()
        output["ewfmount_path"] = bootstrap.best_ewfmount()
        print(json.dumps(output, indent=2))
        return

    _h = lambda s: f"{Fore.CYAN}{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLOR else s
    _ok = lambda s: f"{Fore.GREEN}{s}{Style.RESET_ALL}" if HAS_COLOR else s
    _miss = lambda s: f"{Fore.RED}{s}{Style.RESET_ALL}" if HAS_COLOR else s

    print(file=sys.stderr)
    print(_h("MountIR Dependency Check"), file=sys.stderr)
    print(_h("=" * 55), file=sys.stderr)

    print(f"\n{_h('Format Handlers:')}", file=sys.stderr)
    for fmt, tools, pkg in handlers_to_check:
        statuses = []
        for tool in tools:
            exists = tool_exists(tool)
            status = _ok("OK") if exists else _miss("MISSING")
            statuses.append(f"{tool}: {status}")
        print(f"  {fmt:<14} {' | '.join(statuses)}", file=sys.stderr)
        if any(not tool_exists(t) for t in tools):
            print(f"  {'':14} Install: sudo apt install {pkg}", file=sys.stderr)

    # ewfmount: apt ships the 2014 legacy line (no EWF2); flag whether the
    # installed build can read EnCase v7 Ex01/Lx01 images. We report the
    # *newest* ewfmount found and the exact path MountIR will invoke, since
    # PATH/sudo secure_path may otherwise surface the legacy build first.
    ewf_ver = bootstrap.installed_ewfmount_version()
    ewf_path = bootstrap.best_ewfmount()
    if ewf_ver:
        modern = bootstrap.have_modern_libewf()
        has_fuse = bootstrap.ewfmount_has_fuse()
        if modern and has_fuse:
            note = _ok(f"v{ewf_ver}: modern + FUSE, Ex01/Lx01 mountable")
        elif modern and not has_fuse:
            note = _miss(f"v{ewf_ver}: modern but NO FUSE - cannot mount")
        else:
            note = _miss(f"v{ewf_ver}: legacy, no Ex01/Lx01")
        print(f"  {'':14} {note}", file=sys.stderr)
        if ewf_path:
            print(f"  {'':14} Using: {ewf_path}", file=sys.stderr)
        if modern and not has_fuse:
            print(f"  {'':14} Rebuild with FUSE: mountir setup --force",
                  file=sys.stderr)
        elif not modern:
            print(f"  {'':14} Build modern libewf: mountir setup",
                  file=sys.stderr)

    print(f"\n{_h('Support Tools:')}", file=sys.stderr)
    for tool, pkg, desc in support_tools:
        exists = tool_exists(tool)
        status = _ok("OK") if exists else _miss("MISSING")
        print(f"  {tool:<14} {status:<10} {desc}", file=sys.stderr)
        if not exists:
            print(f"  {'':14} Install: sudo apt install {pkg}", file=sys.stderr)

    print(f"\n{_h('Filesystem Drivers:')}", file=sys.stderr)
    for label, tool, hint, desc, kernel_name in fs_drivers:
        available, provider = _driver_status(tool, kernel_name)
        status = _ok("OK") if available else _miss("MISSING")
        via = f" [{provider}]" if provider else ""
        print(f"  {label:<26} {status:<10} {desc}{via}", file=sys.stderr)
        if available:
            continue
        if hint.startswith(("built from source", "mountir ")):
            print(f"  {'':26} {hint}", file=sys.stderr)
        else:
            print(f"  {'':26} Install: sudo apt install {hint}", file=sys.stderr)
        if kernel_name:
            print(f"  {'':26} (or a kernel providing '{kernel_name}')",
                  file=sys.stderr)

    print(f"\n  Run 'mountir setup' to install everything automatically.\n",
          file=sys.stderr)


# Mount bases we refuse to "clean" without --force, so a mistyped --mount-base
# can never mass-unmount a system path.
_PROTECTED_BASES = {
    "/", "/mnt", "/home", "/dev", "/proc", "/sys", "/run", "/boot",
    "/usr", "/var", "/etc", "/tmp", "/root", "/srv", "/opt",
}


def cmd_clean(args):
    """Scavenge the mount base for orphaned mounts and remove them.

    Unmounts anything still mounted under --mount-base (deepest first, with a
    lazy fallback), detaches loop devices backing files there, removes the
    leftover mount-point directories, and prunes stale state entries.
    """
    if not check_root():
        logger.error("MountIR requires root privileges. Run with sudo.")
        sys.exit(1)

    base = Path(args.mount_base).resolve()
    force = getattr(args, "force", False)

    # Safety guard: never mass-unmount a system path by accident.
    if str(base) in _PROTECTED_BASES or len(base.parts) < 3:
        logger.error(
            "Refusing to clean '%s' - it looks like a system path. Point "
            "--mount-base at a dedicated directory such as /mnt/mountir%s.",
            base, "" if force else " (or pass --force)",
        )
        if not force:
            sys.exit(1)

    if not base.exists():
        logger.info("Nothing to clean: %s does not exist", base)
        return

    state_mgr = StateManager()

    # Gather loop devices to detach -- captured BEFORE unmounting. Unmounting a
    # FUSE container mangles its backing-file path (".../ewf1" -> "/ewf1"), which
    # hides the loop from a path-based lookup and orphans it. We collect from two
    # sources: the live losetup table matched by backing path (valid only while
    # the container is still mounted) and recorded state (exact device names,
    # immune to the mangling).
    loops_to_detach = set(loop_devices_backing(base))
    pools_to_export = set()
    base_str = str(base)
    for img in state_mgr.load().mounted_images:
        mb = str(img.mount_base or "")
        if mb == base_str or mb.startswith(f"{base_str}/"):
            loops_to_detach.update(img.partition_loops or [])
            if img.secondary_loop:
                loops_to_detach.add(img.secondary_loop)
            pools_to_export.update(getattr(img, "zfs_pools", []) or [])

    # 0. Export ZFS pools first: a plain umount of a dataset leaves the pool
    #    imported and its vdev loops held, so detaching them would fail.
    for pool in sorted(pools_to_export):
        zfs.export_pool(pool)

    # 1. Unmount everything under the base, deepest first.
    mounts = find_mounts_under(base)
    if mounts:
        logger.info("Unmounting %d mount(s) under %s", len(mounts), base)
    for mp in mounts:
        _umount_path(mp)

    # 2. Detach the loop devices gathered above (now released by the unmounts).
    for dev in sorted(loops_to_detach):
        try:
            run_command(["losetup", "-d", dev], check=False, capture=False)
            logger.info("Detached loop device: %s", dev)
        except Exception:
            pass

    # 3. Remove leftover (now-empty) mount-point directories.
    for child in sorted(base.iterdir()):
        if child.is_dir():
            cleanup_mount_dir(child)

    # 4. Prune state entries that are no longer actually mounted.
    for stale in state_mgr.verify_mounts():
        state_mgr.remove_mount(stale.mount_id)
        logger.info("Pruned stale state entry: %s", stale.mount_id)

    remaining = find_mounts_under(base)
    if remaining:
        logger.warning(
            "%d mount(s) under %s are still busy and were left in place. "
            "Make sure nothing is using them, then re-run.",
            len(remaining), base,
        )
    else:
        logger.info("Cleanup complete - %s is clear", base)


def cmd_setup(args):
    """Install all MountIR dependencies (Python + system forensic tools).

    ``--force`` rebuilds the source-built tools (apfs-fuse, libewf) even when
    already present; without it an existing modern libewf/apfs-fuse is reused.
    ``--ufs`` additionally installs the cargo-built UFS driver.
    """
    bootstrap.run_bootstrap(
        force=getattr(args, "force", False),
        with_fuse_ufs=getattr(args, "with_fuse_ufs", False),
    )


def cmd_install_deps(args):
    """Backwards-compatible alias for 'setup' (installs system tools)."""
    cmd_setup(args)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="mountir",
        description="MountIR - Forensic Disk Image Mounting Utility",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"MountIR v{MOUNTIR_VERSION}",
    )
    parser.add_argument(
        "--no-setup", action="store_true",
        help="Skip the first-run dependency bootstrap",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- mount ---
    mount_parser = subparsers.add_parser("mount", help="Mount a forensic disk image")
    mount_parser.add_argument(
        "image_path", nargs="*",
        help="One or more image files, globs, or a directory to scan for images",
    )
    mount_parser.add_argument(
        "-d", "--mount-base", "--dir", dest="mount_base", default="/mnt/mountir",
        metavar="DIR",
        help="Base directory for mount points (default: /mnt/mountir)",
    )
    mount_parser.add_argument(
        "-r", "--recursive", action="store_true",
        help="When a directory is given, scan it recursively for images",
    )
    mount_parser.add_argument(
        "--pattern", metavar="GLOB",
        help="Only mount files matching this glob when scanning a directory "
             "(e.g. '*.E01')",
    )
    mount_parser.add_argument(
        "--force", "--best-effort", dest="force", action="store_true",
        help="Best-effort mount: survive corrupt partition tables (expose the "
             "whole disk) and brute-force the filesystem type regardless of OS",
    )
    mount_parser.add_argument(
        "--case-id", default="",
        help="Case identifier (used in mount point naming)",
    )
    mount_parser.add_argument(
        "--no-partitions", action="store_true",
        help="Mount container only, skip partition detection",
    )
    mount_parser.add_argument(
        "--json-input", metavar="FILE",
        help="Read mount request from JSON file (use '-' for stdin)",
    )
    mount_parser.add_argument("-v", "--verbose", action="store_true")
    mount_parser.add_argument("--json", action="store_true",
                               help="Output results as JSON")

    # --- unmount ---
    unmount_parser = subparsers.add_parser("unmount", help="Unmount a mounted image")
    unmount_parser.add_argument(
        "mount_point", nargs="?",
        help="Mount ID or path to unmount",
    )
    unmount_parser.add_argument(
        "--all", action="store_true",
        help="Unmount all mounted images",
    )
    unmount_parser.add_argument("-v", "--verbose", action="store_true")
    unmount_parser.add_argument("--json", action="store_true",
                                 help="Output results as JSON")

    # --- list ---
    list_parser = subparsers.add_parser("list", help="List mounted images")
    list_parser.add_argument(
        "-d", "--mount-base", "--dir", dest="mount_base", default=None,
        metavar="DIR",
        help="Only list images mounted under this base directory "
             "(default: list all)",
    )
    list_parser.add_argument("-v", "--verbose", action="store_true")
    list_parser.add_argument("--json", action="store_true",
                              help="Output results as JSON")

    # --- check ---
    check_parser = subparsers.add_parser("check", help="Check tool dependencies")
    check_parser.add_argument("-v", "--verbose", action="store_true")
    check_parser.add_argument("--json", action="store_true",
                               help="Output results as JSON")

    # --- clean ---
    clean_parser = subparsers.add_parser(
        "clean", help="Unmount and remove orphaned mounts under the mount base",
    )
    clean_parser.add_argument(
        "-d", "--mount-base", "--dir", dest="mount_base", default="/mnt/mountir",
        metavar="DIR",
        help="Mount base to clean (default: /mnt/mountir)",
    )
    clean_parser.add_argument(
        "--force", action="store_true",
        help="Override the system-path safety guard",
    )
    clean_parser.add_argument("-v", "--verbose", action="store_true")

    # --- setup ---
    setup_parser = subparsers.add_parser(
        "setup", help="Install all MountIR dependencies (Python + system tools)",
    )
    setup_parser.add_argument("-v", "--verbose", action="store_true")
    setup_parser.add_argument(
        "--force", action="store_true",
        help="Rebuild source-built tools (apfs-fuse, libewf) even if already "
             "present; set MOUNTIR_LIBEWF_VERSION to pull a newer libewf",
    )
    setup_parser.add_argument(
        "--ufs", dest="with_fuse_ufs", action="store_true",
        help="Also install the fuse-ufs UFS driver via cargo (needs a Rust "
             "toolchain). Required for FreeBSD/pfSense/NetScaler UFS volumes on "
             "kernels without the 'ufs' driver, such as WSL2",
    )

    # --- install-deps (legacy alias for setup) ---
    install_parser = subparsers.add_parser(
        "install-deps", help="Alias for 'setup' (install system forensic tools)",
    )
    install_parser.add_argument("-v", "--verbose", action="store_true")
    install_parser.add_argument("--force", action="store_true",
                                help="Rebuild source-built tools")
    install_parser.add_argument(
        "--ufs", dest="with_fuse_ufs", action="store_true",
        help="Also install the fuse-ufs UFS driver via cargo",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
COMMAND_MAP = {
    "mount": cmd_mount,
    "unmount": cmd_unmount,
    "list": cmd_list,
    "check": cmd_check,
    "clean": cmd_clean,
    "setup": cmd_setup,
    "install-deps": cmd_install_deps,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help(sys.stderr)
        sys.exit(0)

    # Whether to run the first-run dependency bootstrap for this command.
    # 'setup'/'install-deps' do their own install; --no-setup / the
    # MOUNTIR_NO_BOOTSTRAP env var opt out entirely.
    skip_bootstrap = (
        args.command in ("setup", "install-deps")
        or getattr(args, "no_setup", False)
    )

    # Re-launch inside the project virtualenv BEFORE any real work, so Python
    # dependencies load from the venv rather than the system/root interpreter.
    # No-op once inside the venv (or when opted out); may replace the process.
    if not skip_bootstrap:
        bootstrap.ensure_venv_runtime()

    # Setup logging
    verbose = getattr(args, "verbose", False)
    log_file = setup_logging(verbose)

    print_banner()
    logger.debug("MountIR v%s started", MOUNTIR_VERSION)
    logger.debug("Log file: %s", log_file)

    # Now inside the venv: install any missing system forensic tools (once,
    # tracked by a marker file).
    if not skip_bootstrap:
        bootstrap.ensure_system_bootstrap()

    # Validate mount subcommand has image_path
    if args.command == "mount" and not args.image_path and not args.json_input:
        logger.error("mount requires an image path or --json-input")
        sys.exit(1)

    # Validate unmount subcommand
    if args.command == "unmount" and not args.mount_point and not getattr(args, "all", False):
        logger.error("unmount requires a mount point/ID or --all")
        sys.exit(1)

    # Dispatch
    handler_fn = COMMAND_MAP.get(args.command)
    if handler_fn:
        try:
            handler_fn(args)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            sys.exit(130)
        except Exception as e:
            logger.error("Unexpected error: %s", e)
            logger.debug("Traceback:", exc_info=True)
            sys.exit(1)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
