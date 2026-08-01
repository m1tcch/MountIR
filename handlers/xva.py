#!/usr/bin/env python3
"""Handler for XVA (Xen Virtual Appliance) disk images."""

import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command


COPY_BUFFER = 4 * 1024 * 1024  # 4 MB — large buffer for disk image I/O


class XvaHandler(BaseHandler):
    """Mount XVA images by extracting and reassembling raw disk chunks.

    XVA (Xen Virtual Appliance) is a TAR archive containing numbered
    raw disk chunks organised in Ref:<N>/ directories:
        Ref:0/chunk-000000000
        Ref:0/chunk-000000001
        ...

    This handler extracts the archive, reassembles the chunks into a
    single raw image, then attaches it via losetup.
    """

    @property
    def format_name(self) -> str:
        return "XVA"

    @property
    def required_tools(self) -> List[str]:
        return ["losetup"]

    def _find_chunk_dirs(self, extract_dir: Path) -> List[Path]:
        """Find Ref:N directories containing disk chunks, sorted by ref number."""
        chunk_dirs = []
        for child in sorted(extract_dir.iterdir()):
            if child.is_dir() and child.name.startswith("Ref:"):
                # Verify it contains chunk files
                chunks = sorted(child.glob("chunk-*"))
                if chunks:
                    chunk_dirs.append(child)
        return chunk_dirs

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Extract XVA archive, reassemble chunks, and loop-mount.

        Steps:
          1. Extract the TAR archive
          2. Find Ref:N/ directories with chunk files
          3. Concatenate chunks into a single raw image
          4. Attach via losetup
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="mountir_xva_"))

        # --- Step 1: Extract ---
        try:
            with tarfile.open(image_path, "r") as tf:
                tf.extractall(temp_dir)
                logger.debug("Extracted XVA to: %s", temp_dir)
        except (tarfile.TarError, OSError) as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(
                success=False,
                error=f"XVA extraction failed: {e}",
            )

        # --- Step 2: Find chunk directories ---
        chunk_dirs = self._find_chunk_dirs(temp_dir)
        if not chunk_dirs:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(
                success=False,
                error=f"No disk chunk directories (Ref:N/) found in XVA",
            )

        # Use the first Ref directory (primary disk)
        chunk_dir = chunk_dirs[0]
        if len(chunk_dirs) > 1:
            logger.info(
                "Multiple disk refs found in XVA; using %s", chunk_dir.name,
            )

        # --- Step 3: Reassemble chunks ---
        chunks = sorted(chunk_dir.glob("chunk-*"))
        if not chunks:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(
                success=False,
                error=f"No chunks found in {chunk_dir.name}",
            )

        combined_path = temp_dir / f"{image_path.stem}.raw"
        try:
            with open(combined_path, "wb") as outfile:
                for chunk in chunks:
                    logger.debug("  Assembling chunk: %s", chunk.name)
                    with open(chunk, "rb") as infile:
                        shutil.copyfileobj(infile, outfile, length=COPY_BUFFER)

            logger.info(
                "Reassembled %d chunks from %s -> %s",
                len(chunks), chunk_dir.name, combined_path,
            )
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(
                success=False,
                error=f"Chunk reassembly failed: {e}",
            )

        # --- Step 4: Loop mount ---
        try:
            result = run_command([
                "losetup",
                "--find", "--show",
                "--read-only",
                "--partscan",
                str(combined_path),
            ])
            loop_device = result.stdout.strip()
            if not loop_device:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return MountResult(
                    success=False,
                    error="losetup returned empty device path",
                )

            logger.info("Attached %s as %s", combined_path.name, loop_device)
            return MountResult(
                success=True,
                block_device=loop_device,
                loop_device=loop_device,
                raw_image_path=temp_dir,  # Store temp dir for cleanup
            )

        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(success=False, error=str(e))

    def unmount(self, mount_result: MountResult) -> bool:
        """Detach loop device and clean up extracted temp directory."""
        success = True

        # Detach the loop device
        if mount_result.loop_device:
            try:
                run_command(["losetup", "-d", mount_result.loop_device], capture=False)
                logger.info(
                    "Detached loop device: %s", mount_result.loop_device,
                )
            except Exception as e:
                logger.error(
                    "Failed to detach %s: %s", mount_result.loop_device, e,
                )
                success = False

        # Clean up the entire temp directory (extracted chunks + combined raw)
        if mount_result.raw_image_path and mount_result.raw_image_path.is_dir():
            try:
                shutil.rmtree(mount_result.raw_image_path)
                logger.debug(
                    "Cleaned up XVA temp directory: %s",
                    mount_result.raw_image_path,
                )
            except Exception as e:
                logger.warning(
                    "Failed to clean up XVA temp dir %s: %s",
                    mount_result.raw_image_path, e,
                )

        return success
