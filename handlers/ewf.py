#!/usr/bin/env python3
"""Handler for E01/L01 and Ex01/Lx01 (EnCase/EWF) disk images using ewfmount.

ewfmount transparently handles both EWF version 1 (E01/L01) and EWF version 2
(Ex01/Lx01) containers, so a single handler covers all four extensions.
"""

from pathlib import Path
from typing import List

import bootstrap
from handlers.base import BaseHandler, MountResult
from utils import logger, run_command, fuse_unmount

# EWF version 2 containers (EnCase v7+); only a modern libewf can read these.
_EWF2_SUFFIXES = (".ex01", ".lx01")

# Logical evidence files (EnCase L01/Lx01) hold a reconstructed file/folder tree
# rather than a bit-for-bit disk image. ewfmount must be told to expose them in
# "files" mode (``-f files``); with the default "raw" mode it treats the
# container as a physical image and exits non-zero. Physical images (E01/Ex01)
# use the default raw mode, which yields the ewf1 device downstream code expects.
_LOGICAL_SUFFIXES = (".l01", ".lx01")


class EwfHandler(BaseHandler):
    """Mount E01/L01/Ex01/Lx01 images via ewfmount (FUSE).

    ewfmount creates a FUSE mount point containing a raw device file
    (typically 'ewf1') that represents the uncompressed disk image.

    The binary is resolved with :func:`bootstrap.best_ewfmount`, which picks the
    newest ewfmount installed rather than whatever PATH (or ``sudo``'s
    ``secure_path``) happens to surface first -- so an EWF2-capable build in
    /usr/local/bin is used for Ex01/Lx01 even when the frozen apt build shadows
    it on PATH.
    """

    @property
    def format_name(self) -> str:
        return "E01/EWF (incl. Ex01)"

    @property
    def required_tools(self) -> List[str]:
        return ["ewfmount"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount E01/L01/Ex01/Lx01 image via ewfmount.

        Physical images (E01/Ex01) are exposed as a raw device at
        <mount_point>/ewf1 for downstream partition detection. Logical evidence
        files (L01/Lx01) hold a file/folder tree rather than a disk, so they are
        mounted with ewfmount's ``-f files`` mode and the reconstructed tree
        appears directly under <mount_point> (no ewf1, no partition table).
        ewfmount automatically handles multi-segment images (.E01,.E02,...).
        """
        binary = bootstrap.best_ewfmount() or "ewfmount"
        suffix = image_path.suffix.lower()
        is_ewf2 = suffix in _EWF2_SUFFIXES
        is_logical = suffix in _LOGICAL_SUFFIXES

        # Ex01/Lx01 need EWF2 support; the 2014 legacy apt build can't read them
        # and fails with an opaque "unable to open" error. Warn up front with the
        # actionable fix so the failure isn't a mystery.
        if is_ewf2 and not bootstrap.have_modern_libewf():
            ver = bootstrap.ewfmount_version_of(binary) or "unknown"
            logger.warning(
                "%s is an EWF2 (Ex01/Lx01) image but the available ewfmount "
                "(%s, v%s) is the 2014 legacy line, which cannot read EWF2. "
                "Run 'mountir setup' to build modern libewf.",
                image_path.name, binary, ver,
            )

        # Logical evidence files must be mounted in "files" mode so the acquired
        # file/folder tree is reconstructed; the default raw mode treats the
        # container as a disk and ewfmount exits non-zero.
        cmd = [binary]
        if is_logical:
            cmd += ["-f", "files"]
        cmd += [str(image_path), str(mount_point)]

        try:
            run_command(cmd, capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # A logical mount exposes the file tree directly at the mount point --
        # there is no ewf1 device and no partition table to parse. Report the
        # mount point itself as the browsable evidence root.
        if is_logical:
            try:
                populated = any(mount_point.iterdir())
            except OSError as e:
                return MountResult(
                    success=False, mount_point=mount_point,
                    error=f"ewfmount succeeded but the file tree is unreadable: {e}",
                )
            if not populated:
                return MountResult(
                    success=False, mount_point=mount_point,
                    error="ewfmount succeeded but the logical file tree is empty",
                )
            logger.info(
                "Mounted logical evidence %s -> %s (file tree)",
                image_path.name, mount_point,
            )
            return MountResult(success=True, mount_point=mount_point)

        # Physical image: find the raw image file (typically ewf1)
        raw_path = mount_point / "ewf1"
        if not raw_path.exists():
            # Some versions use different naming
            candidates = list(mount_point.iterdir())
            if candidates:
                raw_path = candidates[0]
                logger.debug("EWF raw image at non-standard path: %s", raw_path)
            else:
                return MountResult(
                    success=False,
                    mount_point=mount_point,
                    error="ewfmount succeeded but no raw image found",
                )

        logger.info(
            "Mounted %s -> %s (raw: %s)",
            image_path.name, mount_point, raw_path.name,
        )
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount the ewfmount FUSE filesystem."""
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
