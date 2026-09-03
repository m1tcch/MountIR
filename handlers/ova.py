#!/usr/bin/env python3
"""Handler for OVA (Open Virtualization Archive) disk images.

OVA files are TAR archives containing a .vmdk (and .ovf manifest).
This handler extracts the archive and delegates to VmdkHandler.
"""

import shutil
import tarfile
from pathlib import Path
from typing import List, Optional

from handlers.base import BaseHandler, MountResult
from handlers.vmdk import VmdkHandler
from utils import logger, make_scratch_dir, safe_extractall


class OvaHandler(BaseHandler):
    """Mount OVA images by extracting and delegating to VmdkHandler.

    OVA (Open Virtualization Archive) is a TAR file containing:
      - .ovf descriptor
      - .vmdk virtual disk(s)
      - .mf manifest (optional)

    This handler extracts the TAR, locates the .vmdk file inside,
    and delegates mounting to VmdkHandler.
    """

    @property
    def format_name(self) -> str:
        return "OVA"

    @property
    def required_tools(self) -> List[str]:
        return ["tar"]

    def check_tools(self):
        """Check for tar + VmdkHandler tools."""
        result = super().check_tools()

        # Also verify VmdkHandler tools are available
        vmdk_handler = VmdkHandler()
        vmdk_check = vmdk_handler.check_tools()
        if not vmdk_check["usable"]:
            result["missing"].extend(vmdk_check["missing"])
            result["usable"] = False

        return result

    def _find_vmdk_in_tar(self, tar_path: Path) -> Optional[str]:
        """Find the .vmdk member inside the TAR archive."""
        try:
            with tarfile.open(tar_path, "r") as tf:
                for member in tf.getnames():
                    if member.lower().endswith(".vmdk"):
                        return member
        except (tarfile.TarError, OSError) as e:
            logger.error("Failed to read OVA archive: %s", e)
        return None

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Extract OVA archive and mount the VMDK inside.

        Steps:
          1. Extract the TAR archive to a temp directory
          2. Locate the .vmdk file
          3. Delegate to VmdkHandler
        """
        # Find the VMDK inside the archive first
        vmdk_member = self._find_vmdk_in_tar(image_path)
        if not vmdk_member:
            return MountResult(
                success=False,
                error=f"No .vmdk file found inside OVA: {image_path.name}",
            )

        # Extract to a temp directory
        temp_dir = make_scratch_dir("ova")
        try:
            with tarfile.open(image_path, "r") as tf:
                safe_extractall(tf, temp_dir)
                logger.debug("Extracted OVA to: %s", temp_dir)
        except (tarfile.TarError, OSError, ValueError) as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(success=False, error=f"OVA extraction failed: {e}")

        vmdk_path = temp_dir / vmdk_member
        if not vmdk_path.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(
                success=False,
                error=f"Extracted VMDK not found at expected path: {vmdk_path}",
            )

        logger.info(
            "Extracted %s from OVA -> %s", vmdk_member, vmdk_path,
        )

        # Delegate to VmdkHandler
        vmdk_handler = VmdkHandler()
        result = vmdk_handler.mount(vmdk_path, mount_point)

        if result.success:
            # Store the raw_image_path to the temp dir for cleanup
            # We stash the temp_dir path via the raw_image_path field
            # so unmount can clean it up
            result.raw_image_path = temp_dir
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return result

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount the VMDK (via VmdkHandler), then clean up extracted temp dir."""
        success = True

        # Delegate VMDK unmount
        vmdk_handler = VmdkHandler()
        if not vmdk_handler.unmount(mount_result):
            success = False

        # Clean up the extracted temp directory
        if mount_result.raw_image_path and mount_result.raw_image_path.is_dir():
            try:
                shutil.rmtree(mount_result.raw_image_path)
                logger.debug(
                    "Cleaned up OVA temp directory: %s",
                    mount_result.raw_image_path,
                )
            except Exception as e:
                logger.warning(
                    "Failed to clean up OVA temp dir %s: %s",
                    mount_result.raw_image_path, e,
                )

        return success
