#!/usr/bin/env python3
"""MountIR image type detection via file extension and magic bytes."""

import re
import subprocess
from enum import Enum
from pathlib import Path
from typing import Optional

from utils import logger, run_command


class ImageType(str, Enum):
    """Supported disk image formats."""
    E01 = "e01"
    L01 = "l01"
    VMDK = "vmdk"
    VHD = "vhd"
    VHDX = "vhdx"
    RAW = "raw"       # dd, raw, img, bin, 001
    ISO = "iso"
    AFF = "aff"
    AFF4 = "aff4"
    QCOW2 = "qcow2"
    SPLIT_RAW = "split_raw"  # .001/.002/.003 multi-segment raw
    VDI = "vdi"
    OVA = "ova"
    DMG = "dmg"
    SPARSEIMAGE = "sparseimage"
    XVA = "xva"
    UNKNOWN = "unknown"


# Human-readable list of supported formats (used in CLI messages/help).
SUPPORTED_FORMATS = (
    "E01/L01, Ex01/Lx01, DD/Raw/IMG, VMDK, VHD/VHDX, QCOW2, ISO, AFF, "
    "AFF4, VDI, OVA, DMG, sparseimage, XVA, split-raw"
)

# Extension -> ImageType mapping.
# Ex01/Lx01 are EnCase EWF version 2 containers; ewfmount handles them with
# the same code path as E01/L01, so they map onto the same ImageType.
_EXTENSION_MAP = {
    ".e01": ImageType.E01,
    ".ex01": ImageType.E01,   # EWF2 (EnCase v7+)
    ".l01": ImageType.L01,
    ".lx01": ImageType.L01,    # EWF2 logical evidence
    ".vmdk": ImageType.VMDK,
    ".vhd": ImageType.VHD,
    ".vhdx": ImageType.VHDX,
    ".dd": ImageType.RAW,
    ".raw": ImageType.RAW,
    ".img": ImageType.RAW,
    ".bin": ImageType.RAW,
    ".001": ImageType.RAW,       # May be upgraded to SPLIT_RAW below
    ".iso": ImageType.ISO,
    ".aff": ImageType.AFF,
    ".aff4": ImageType.AFF4,
    ".qcow2": ImageType.QCOW2,
    ".qcow": ImageType.QCOW2,
    ".vdi": ImageType.VDI,
    ".ova": ImageType.OVA,
    ".dmg": ImageType.DMG,
    ".sparseimage": ImageType.SPARSEIMAGE,
    ".sparsebundle": ImageType.SPARSEIMAGE,
    ".xva": ImageType.XVA,
}

# Display labels for the EWF sub-formats. The E01 and L01 ImageTypes each cover
# both EWF v1 and EWF v2 (Ex01/Lx01) because ewfmount handles them identically;
# this maps back to the specific container so logs/summaries show what the
# analyst actually supplied.
_EWF_DISPLAY_BY_EXT = {
    ".e01": "E01",
    ".ex01": "Ex01",
    ".l01": "L01",
    ".lx01": "Lx01",
}


def display_format(image_path: Path, image_type: ImageType) -> str:
    """Human-facing label for the detected format.

    E01/L01 cover both EWF v1 and v2 (Ex01/Lx01) under one handler; this surfaces
    the specific container (Ex01/Lx01) from the file extension so the analyst sees
    what they supplied. Every other format uses the ImageType name upper-cased.
    """
    if image_type in (ImageType.E01, ImageType.L01):
        label = _EWF_DISPLAY_BY_EXT.get(image_path.suffix.lower())
        if label:
            return label
    return image_type.value.upper()


# Multi-segment E01 extensions: .E02-.E99, .EAA-.EZZ
# We recognise these so we can point the user to .E01
_E01_SEGMENT_PATTERN = None  # compiled on first use


def _is_e01_segment(ext: str) -> bool:
    """Check if an extension looks like an E01 segment (.E02-.E99, .EAA-.EZZ)."""
    import re
    global _E01_SEGMENT_PATTERN
    if _E01_SEGMENT_PATTERN is None:
        _E01_SEGMENT_PATTERN = re.compile(
            r"^\.[eE]([0-9]{2}|[a-zA-Z]{2})$"
        )
    return bool(_E01_SEGMENT_PATTERN.match(ext))


# ---------------------------------------------------------------------------
# Multi-image / directory scanning
# ---------------------------------------------------------------------------
# Extensions that mark the *primary* (first/only) file of a mountable image.
# Used when scanning a directory so a folder of evidence can be mounted in one
# shot.  Continuation segments (.E02+, .002+) and VMDK split extents are
# deliberately excluded so a multi-segment set mounts once, from its first file.
PRIMARY_IMAGE_EXTENSIONS = frozenset(_EXTENSION_MAP.keys())

# VMDK split extents (e.g. ``disk-s001.vmdk``, ``disk-f001.vmdk``,
# ``disk-flat.vmdk``, ``disk-delta.vmdk``) share the ``.vmdk`` suffix with the
# descriptor that actually drives the mount; skip the extents in a dir scan.
_VMDK_EXTENT_RE = re.compile(r"-(s\d+|f\d+|flat|delta|sesparse)\.vmdk$", re.I)

# Image "files" that are actually directories/bundles rather than regular files:
# a macOS sparsebundle is a directory whose contents the handler reassembles.
# These must be matched as images (not scanned into) during a directory walk.
_DIRECTORY_IMAGE_EXTENSIONS = frozenset({".sparsebundle"})


def is_bundle_image(path: Path) -> bool:
    """True when *path* is a directory that is itself a mountable image.

    The only current case is a macOS ``.sparsebundle`` (a directory bundle).
    Callers use this to mount such a directory rather than scanning into it.
    """
    return path.is_dir() and path.suffix.lower() in _DIRECTORY_IMAGE_EXTENSIONS


def _is_secondary_segment(path: Path) -> bool:
    """True for files that are a continuation piece of a multi-part image.

    These are mounted implicitly via their primary file (the EWF/raw set, the
    VMDK descriptor), so a directory scan must not treat them as separate
    images.
    """
    name = path.name.lower()
    ext = path.suffix.lower()
    # VMDK split extents share the .vmdk suffix with the descriptor that drives
    # the mount, so they must be caught before the primary-extension check.
    if _VMDK_EXTENT_RE.search(name):
        return True
    # A recognised primary extension (.e01, .001, .vmdk, ...) is the first/only
    # file of a set, never a continuation piece.
    if ext in PRIMARY_IMAGE_EXTENSIONS:
        return False
    # EWF continuation segments (.E02-.E99, .EAA-.EZZ).
    if _is_e01_segment(ext):
        return True
    # Split raw beyond the first piece (.002, .003 ...); .001 is a primary ext.
    if re.fullmatch(r"\.\d{3}", ext):
        return True
    return False


def is_primary_image(path: Path) -> bool:
    """True when *path* is the primary file (or bundle) of a mountable image."""
    if _is_secondary_segment(path):
        return False
    if path.suffix.lower() in _DIRECTORY_IMAGE_EXTENSIONS:
        return path.is_dir()           # macOS .sparsebundle is a directory
    if not path.is_file():
        return False
    return path.suffix.lower() in PRIMARY_IMAGE_EXTENSIONS


def _scan_match(path: Path) -> bool:
    """A directory/glob match worth queuing: a regular file or a bundle image,
    that isn't a continuation segment of a multi-part set."""
    if _is_secondary_segment(path):
        return False
    if path.suffix.lower() in _DIRECTORY_IMAGE_EXTENSIONS:
        return path.is_dir()
    return path.is_file()


def find_images_in_dir(
    directory: Path,
    recursive: bool = False,
    pattern: Optional[str] = None,
) -> list:
    """Return the primary images inside *directory*, sorted by path.

    With *pattern* (a glob such as ``*.E01``) only matching entries are returned;
    otherwise every recognised primary image extension is matched.  Continuation
    segments and VMDK extents are filtered out so multi-part sets resolve to a
    single mount, and macOS ``.sparsebundle`` directories are matched as images
    rather than scanned into.  *recursive* walks subdirectories.
    """
    globber = directory.rglob if recursive else directory.glob
    if pattern:
        # Even with an explicit pattern, drop continuation segments so e.g.
        # '*.E0*' doesn't queue every segment of one set as separate images.
        return [p for p in sorted(globber(pattern)) if _scan_match(p)]
    return [p for p in sorted(globber("*")) if is_primary_image(p)]


def detect_image_type(image_path: Path) -> ImageType:
    """Detect image type from extension first, then file(1) magic.

    Args:
        image_path: Path to the disk image file.

    Returns:
        Detected ImageType, or ImageType.UNKNOWN.
    """
    if not image_path.exists():
        logger.error("Image file does not exist: %s", image_path)
        return ImageType.UNKNOWN

    # --- Extension-based detection ---
    ext = image_path.suffix.lower()
    if ext in _EXTENSION_MAP:
        detected = _EXTENSION_MAP[ext]

        # Special case: .001 may be a split raw if .002 sibling exists
        if ext == ".001" and detected == ImageType.RAW:
            sibling_002 = image_path.parent / f"{image_path.stem}.002"
            if sibling_002.exists():
                logger.debug(
                    "Found .002 sibling for %s — treating as SPLIT_RAW",
                    image_path.name,
                )
                return ImageType.SPLIT_RAW

        logger.debug("Detected %s from extension '%s'", detected.value, ext)
        return detected

    # Check for E01 segment files
    if _is_e01_segment(ext):
        logger.warning(
            "File appears to be an E01 segment (%s). "
            "Please provide the first segment (.E01).",
            ext,
        )
        return ImageType.E01

    # --- Magic-based detection using file(1) ---
    magic_type = _detect_by_magic(image_path)
    if magic_type is not None:
        logger.debug("Detected %s from file magic", magic_type.value)
        return magic_type

    logger.warning("Could not determine image type for: %s", image_path)
    return ImageType.UNKNOWN


def _detect_by_magic(image_path: Path) -> Optional[ImageType]:
    """Use the `file` command to detect image type from magic bytes."""
    try:
        result = run_command(
            ["file", "--brief", str(image_path)],
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            return None

        output = result.stdout.strip().lower()
        logger.debug("file(1) output: %s", output)

        # EWF / Expert Witness (covers EWF v1 E01/L01 and EWF v2 Ex01/Lx01)
        if "expert witness" in output or "ewf" in output:
            return ImageType.E01

        # QCOW
        if "qemu qcow" in output or "qcow2" in output:
            return ImageType.QCOW2

        # VMware
        if "vmware" in output or "vmdk" in output:
            return ImageType.VMDK

        # Microsoft Disk Image (VHD)
        if "microsoft disk image" in output:
            return ImageType.VHD

        # ISO 9660
        if "iso 9660" in output:
            return ImageType.ISO

        # Raw disk image indicators
        if "x86 boot sector" in output:
            return ImageType.RAW
        if "dos/mbr boot sector" in output:
            return ImageType.RAW

        # AFF
        if "aff " in output or "advanced forensic" in output:
            return ImageType.AFF

        # AFF4 (uses ZIP container with AFF4 metadata)
        if "aff4" in output:
            return ImageType.AFF4

        # VDI (VirtualBox)
        if "virtualbox" in output or "vdi " in output:
            return ImageType.VDI

        # OVA (TAR archive containing OVF + VMDK)
        if "posix tar" in output or "tar archive" in output:
            # Could be OVA or XVA — extension already handled above,
            # but if we're here, extension didn't match.
            pass

        # DMG (Apple Disk Image)
        if "apple" in output and "disk image" in output:
            return ImageType.DMG

        # XVA (Xen Virtual Appliance) — typically a tar
        if "xen" in output and "virtual" in output:
            return ImageType.XVA

    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("file(1) command not available or timed out")

    return None
