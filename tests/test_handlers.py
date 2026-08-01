"""Tests for handler registry and base handler logic."""

from unittest.mock import patch

import pytest

from detector import ImageType
from handlers import (
    get_handler, HANDLER_REGISTRY, ALL_HANDLER_CLASSES, NO_PARTITION_TYPES,
)
from handlers.base import BaseHandler, MountResult
from handlers.raw import RawHandler
from handlers.ewf import EwfHandler
from handlers.vmdk import VmdkHandler
from handlers.vhd import VhdHandler
from handlers.qcow import QcowHandler
from handlers.iso import IsoHandler
from handlers.aff import AffHandler


class TestHandlerRegistry:
    """Test the handler registry and factory."""

    @pytest.mark.parametrize("image_type,handler_class", [
        (ImageType.E01, EwfHandler),
        (ImageType.L01, EwfHandler),
        (ImageType.VMDK, VmdkHandler),
        (ImageType.VHD, VhdHandler),
        (ImageType.VHDX, VhdHandler),
        (ImageType.RAW, RawHandler),
        (ImageType.ISO, IsoHandler),
        (ImageType.AFF, AffHandler),
        (ImageType.QCOW2, QcowHandler),
    ])
    def test_get_handler_returns_correct_type(self, image_type, handler_class):
        """get_handler returns correct handler class for each ImageType."""
        handler = get_handler(image_type)
        assert isinstance(handler, handler_class)

    def test_get_handler_unknown_raises(self):
        """get_handler raises ValueError for UNKNOWN type."""
        with pytest.raises(ValueError, match="No handler"):
            get_handler(ImageType.UNKNOWN)

    def test_registry_covers_all_types(self):
        """Registry has entries for all ImageType values except UNKNOWN."""
        for image_type in ImageType:
            if image_type == ImageType.UNKNOWN:
                continue
            assert image_type in HANDLER_REGISTRY, f"Missing handler for {image_type}"

    def test_all_handler_classes_list(self):
        """ALL_HANDLER_CLASSES contains all handler types."""
        assert EwfHandler in ALL_HANDLER_CLASSES
        assert RawHandler in ALL_HANDLER_CLASSES
        assert VmdkHandler in ALL_HANDLER_CLASSES
        assert VhdHandler in ALL_HANDLER_CLASSES
        assert IsoHandler in ALL_HANDLER_CLASSES
        assert AffHandler in ALL_HANDLER_CLASSES
        assert QcowHandler in ALL_HANDLER_CLASSES


class TestNoPartitionTypes:
    """Test NO_PARTITION_TYPES set."""

    def test_iso_in_no_partition(self):
        assert ImageType.ISO in NO_PARTITION_TYPES

    def test_l01_in_no_partition(self):
        assert ImageType.L01 in NO_PARTITION_TYPES

    def test_e01_not_in_no_partition(self):
        """E01 (disk image) should have partitions."""
        assert ImageType.E01 not in NO_PARTITION_TYPES

    def test_raw_not_in_no_partition(self):
        assert ImageType.RAW not in NO_PARTITION_TYPES


class TestVhdHandlerVariants:
    """Test VHD vs VHDX handler differences."""

    def test_vhd_has_fallback(self):
        handler = VhdHandler(is_vhdx=False)
        assert "vhdimount" in handler.fallback_tools

    def test_vhdx_no_fallback(self):
        handler = VhdHandler(is_vhdx=True)
        assert handler.fallback_tools == []

    def test_vhd_format_name(self):
        assert VhdHandler(is_vhdx=False).format_name == "VHD"

    def test_vhdx_format_name(self):
        assert VhdHandler(is_vhdx=True).format_name == "VHDX"


class TestCheckTools:
    """Test BaseHandler.check_tools() logic."""

    def test_all_tools_present(self):
        """check_tools with all primary tools available."""
        handler = RawHandler()
        with patch("handlers.base.tool_exists", return_value=True):
            result = handler.check_tools()
        assert result["usable"] is True
        assert result["fallback_in_use"] is False
        assert "losetup" in result["available"]
        assert result["missing"] == []

    def test_all_tools_missing(self):
        """check_tools with all tools missing."""
        handler = EwfHandler()
        with patch("handlers.base.tool_exists", return_value=False):
            result = handler.check_tools()
        assert result["usable"] is False
        assert "ewfmount" in result["missing"]

    def test_fallback_used(self):
        """check_tools with primary missing but fallback present."""
        handler = VmdkHandler()
        def mock_tool(name):
            return name == "vmdkmount"  # primary qemu-nbd missing, fallback available
        with patch("handlers.base.tool_exists", side_effect=mock_tool):
            result = handler.check_tools()
        assert result["usable"] is True
        assert result["fallback_in_use"] is True


class TestMountResult:
    """Test MountResult dataclass."""

    def test_success_result(self):
        r = MountResult(success=True, block_device="/dev/nbd0")
        assert r.success is True
        assert r.block_device == "/dev/nbd0"
        assert r.error is None

    def test_failure_result(self):
        r = MountResult(success=False, error="tool not found")
        assert r.success is False
        assert r.error == "tool not found"
        assert r.block_device is None

    def test_defaults(self):
        r = MountResult(success=True)
        assert r.mount_point is None
        assert r.block_device is None
        assert r.loop_device is None
        assert r.raw_image_path is None
        assert r.error is None


class TestHandlerProperties:
    """Test handler property values."""

    @pytest.mark.parametrize("handler,name", [
        (RawHandler(), "DD/Raw"),
        (EwfHandler(), "E01/EWF (incl. Ex01)"),
        (VmdkHandler(), "VMDK"),
        (QcowHandler(), "QCOW2"),
        (IsoHandler(), "ISO"),
        (AffHandler(), "AFF"),
    ])
    def test_format_name(self, handler, name):
        assert handler.format_name == name

    @pytest.mark.parametrize("handler,tools", [
        (RawHandler(), ["losetup"]),
        (EwfHandler(), ["ewfmount"]),
        (VmdkHandler(), ["qemu-nbd"]),
        (QcowHandler(), ["qemu-nbd"]),
        (IsoHandler(), ["mount"]),
        (AffHandler(), ["affuse"]),
    ])
    def test_required_tools(self, handler, tools):
        assert handler.required_tools == tools


class TestEwfBinaryResolution:
    """EWF handler invokes the newest ewfmount, not just PATH's first hit."""

    def test_mount_uses_best_ewfmount(self, tmp_path):
        from pathlib import Path

        image = tmp_path / "evidence.Ex01"
        image.write_bytes(b"\x00")
        mp = tmp_path / "container"
        mp.mkdir()
        (mp / "ewf1").write_bytes(b"\x00")  # ewfmount's raw output stand-in

        with patch("handlers.ewf.bootstrap.best_ewfmount",
                   return_value="/usr/local/bin/ewfmount"), \
             patch("handlers.ewf.bootstrap.have_modern_libewf", return_value=True), \
             patch("handlers.ewf.run_command") as rc:
            result = EwfHandler().mount(image, mp)

        assert result.success is True
        # The resolved (modern) binary is what actually runs.
        assert rc.call_args.args[0][0] == "/usr/local/bin/ewfmount"

    def test_ex01_with_legacy_build_warns(self, tmp_path, caplog):
        import logging

        image = tmp_path / "evidence.ex01"
        image.write_bytes(b"\x00")
        mp = tmp_path / "container"
        mp.mkdir()
        (mp / "ewf1").write_bytes(b"\x00")

        with patch("handlers.ewf.bootstrap.best_ewfmount",
                   return_value="/usr/bin/ewfmount"), \
             patch("handlers.ewf.bootstrap.have_modern_libewf", return_value=False), \
             patch("handlers.ewf.bootstrap.ewfmount_version_of", return_value="20140807"), \
             patch("handlers.ewf.run_command"), \
             caplog.at_level(logging.WARNING, logger="MountIR"):
            EwfHandler().mount(image, mp)

        assert any("legacy" in r.message.lower() or "EWF2" in r.message
                   for r in caplog.records)


class TestEwfLogicalVsPhysical:
    """Logical (L01/Lx01) images mount with ``-f files``; physical don't."""

    @pytest.mark.parametrize("ext", [".L01", ".Lx01"])
    def test_logical_uses_files_format(self, tmp_path, ext):
        """L01/Lx01 pass '-f files' and report the mount point as the file tree."""
        image = tmp_path / f"evidence{ext}"
        image.write_bytes(b"\x00")
        mp = tmp_path / "container"
        mp.mkdir()
        # A '-f files' mount exposes a reconstructed tree, not an ewf1 device.
        (mp / "Users").mkdir()

        with patch("handlers.ewf.bootstrap.best_ewfmount",
                   return_value="/usr/local/bin/ewfmount"), \
             patch("handlers.ewf.bootstrap.have_modern_libewf", return_value=True), \
             patch("handlers.ewf.run_command") as rc:
            result = EwfHandler().mount(image, mp)

        assert result.success is True
        # No raw device for a logical mount -- the mount point is the tree.
        assert result.raw_image_path is None
        assert result.mount_point == mp
        # ewfmount was invoked in files mode, before the positional args.
        cmd = rc.call_args.args[0]
        assert cmd[:3] == ["/usr/local/bin/ewfmount", "-f", "files"]
        assert cmd[-2:] == [str(image), str(mp)]

    def test_logical_empty_tree_is_failure(self, tmp_path):
        """A logical mount that exposes nothing is reported as a failure."""
        image = tmp_path / "evidence.Lx01"
        image.write_bytes(b"\x00")
        mp = tmp_path / "container"
        mp.mkdir()  # left empty -- ewfmount produced no tree

        with patch("handlers.ewf.bootstrap.best_ewfmount",
                   return_value="/usr/local/bin/ewfmount"), \
             patch("handlers.ewf.bootstrap.have_modern_libewf", return_value=True), \
             patch("handlers.ewf.run_command"):
            result = EwfHandler().mount(image, mp)

        assert result.success is False
        assert "empty" in (result.error or "").lower()

    @pytest.mark.parametrize("ext", [".E01", ".Ex01"])
    def test_physical_does_not_use_files_format(self, tmp_path, ext):
        """E01/Ex01 mount in raw mode (no '-f files') and expose ewf1."""
        image = tmp_path / f"evidence{ext}"
        image.write_bytes(b"\x00")
        mp = tmp_path / "container"
        mp.mkdir()
        (mp / "ewf1").write_bytes(b"\x00")

        with patch("handlers.ewf.bootstrap.best_ewfmount",
                   return_value="/usr/local/bin/ewfmount"), \
             patch("handlers.ewf.bootstrap.have_modern_libewf", return_value=True), \
             patch("handlers.ewf.run_command") as rc:
            result = EwfHandler().mount(image, mp)

        assert result.success is True
        assert result.raw_image_path == mp / "ewf1"
        cmd = rc.call_args.args[0]
        assert "-f" not in cmd
        assert cmd == ["/usr/local/bin/ewfmount", str(image), str(mp)]
