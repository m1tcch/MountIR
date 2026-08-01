"""Tests for partition.py mount diagnostics.

Covers the three reasons a readable partition was previously reported as an
opaque "FAIL: dmesg(1) may have more information": the diagnosis being thrown
away, non-filesystem slices being mounted at all, and a filesystem that claims
more space than its partition-table entry allows.
"""

import struct
import subprocess
from unittest.mock import MagicMock, patch

from partition import (
    PartitionInfo,
    _best_mount_error,
    _diagnose_mount_failure,
    _driver_available,
    _fs_claimed_size,
    _no_driver_error,
    _nonfs_partition_kind,
    _short_mount_error,
    _widen_to_filesystem,
    mount_partition,
)


class TestMountErrorReporting:
    """mount(8) prints its diagnosis first and its boilerplate last."""

    WRONG_FS = (
        "mount: /mnt/mountir/x/p2: wrong fs type, bad option, bad superblock on "
        "/dev/loop5p2, missing codepage or helper program, or other error.\n"
        "       dmesg(1) may have more information after failed mount system call.\n"
    )
    UNKNOWN_TYPE = "mount: /mnt/mountir/x/p4: unknown filesystem type 'ufs'.\n"

    @staticmethod
    def _err(stderr):
        return subprocess.CalledProcessError(32, ["mount"], "", stderr)

    def test_boilerplate_is_not_reported_as_the_error(self):
        message = _short_mount_error(self._err(self.WRONG_FS))
        assert "dmesg(1)" not in message
        assert message.startswith("wrong fs type, bad option, bad superblock")

    def test_mount_prefix_is_stripped(self):
        assert _short_mount_error(self._err(self.UNKNOWN_TYPE)) == (
            "unknown filesystem type 'ufs'"
        )

    def test_helper_prefix_is_stripped(self):
        stderr = "mount.ntfs-3g: Failed to read last sector\n"
        assert _short_mount_error(self._err(stderr)) == "Failed to read last sector"

    def test_empty_stderr_falls_back_to_the_exit_code(self):
        assert "32" in _short_mount_error(self._err(""))

    def test_specific_error_beats_the_generic_catch_all(self):
        """Every attempt list ends with auto-detect; its error must not win."""
        generic = _short_mount_error(self._err(self.WRONG_FS))
        specific = _short_mount_error(self._err(self.UNKNOWN_TYPE))
        assert _best_mount_error([specific, generic]) == specific

    def test_driver_message_beats_unknown_type(self):
        specific = "Failed to read last sector"
        assert _best_mount_error(
            ["unknown filesystem type 'ufs'", specific]) == specific


class TestNonFilesystemPartitions:
    """Bootcode/swap slices are skipped, not reported as mount failures."""

    @staticmethod
    def _p(type_hint):
        return PartitionInfo(number=1, type_hint=type_hint)

    def test_freebsd_boot_variant_guid(self):
        """Release images carry a vendor-varying node; prefixes still match."""
        kind = _nonfs_partition_kind(self._p("83bd6b9d-7f41-11dc-be0b-001560b84f0f"))
        assert "freebsd-boot" in kind

    def test_freebsd_boot_canonical_guid(self):
        kind = _nonfs_partition_kind(self._p("83bd6b9d-7f41-11dc-be0b-001e4f32e6b9"))
        assert "freebsd-boot" in kind

    def test_freebsd_swap(self):
        assert _nonfs_partition_kind(
            self._p("516e7cb5-6ecf-11d6-8ff8-00022d09712b")) == "freebsd-swap"

    def test_freebsd_ufs_is_a_real_filesystem(self):
        assert _nonfs_partition_kind(
            self._p("516e7cb6-6ecf-11d6-8ff8-00022d09712b")) == ""

    def test_efi_system_partition_is_a_real_filesystem(self):
        assert _nonfs_partition_kind(
            self._p("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")) == ""

    def test_mbr_linux_swap(self):
        assert _nonfs_partition_kind(self._p("0x82")) == "Linux swap"

    def test_mbr_type_without_the_0x_prefix(self):
        assert _nonfs_partition_kind(self._p("82")) == "Linux swap"

    def test_mbr_linux_data_is_a_real_filesystem(self):
        assert _nonfs_partition_kind(self._p("0x83")) == ""

    def test_no_type_hint_is_not_classified(self):
        assert _nonfs_partition_kind(self._p("")) == ""

    def test_skipped_partition_is_neither_mounted_nor_failed(self, tmp_path):
        part = PartitionInfo(device="/dev/loop0p1", number=1,
                             skip_reason="freebsd-swap")
        with patch("partition.run_command") as run:
            result = mount_partition(part, tmp_path / "p1")
        run.assert_not_called()
        assert result.mounted is False
        assert result.mount_error is None


class TestFilesystemClaimedSize:
    """Read the extent each filesystem claims straight from its superblock."""

    @staticmethod
    def _volume(tmp_path, offset, payload):
        path = tmp_path / "vol.img"
        data = bytearray(offset + len(payload))
        data[offset:offset + len(payload)] = payload
        path.write_bytes(bytes(data))
        return str(path)

    def test_ext4_blocks_times_block_size(self, tmp_path):
        sb = bytearray(1024)
        struct.pack_into("<H", sb, 56, 0xEF53)   # s_magic
        struct.pack_into("<I", sb, 24, 0)        # 1024-byte blocks
        struct.pack_into("<I", sb, 4, 142336)    # s_blocks_count_lo
        device = self._volume(tmp_path, 1024, sb)
        assert _fs_claimed_size(device, "ext4") == 142336 * 1024

    def test_ext4_64bit_uses_the_high_block_count(self, tmp_path):
        sb = bytearray(1024)
        struct.pack_into("<H", sb, 56, 0xEF53)
        struct.pack_into("<I", sb, 24, 2)        # 4096-byte blocks
        struct.pack_into("<I", sb, 96, 0x80)     # INCOMPAT_64BIT
        struct.pack_into("<I", sb, 0x150, 1)     # s_blocks_count_hi
        device = self._volume(tmp_path, 1024, sb)
        assert _fs_claimed_size(device, "ext4") == (1 << 32) * 4096

    def test_btrfs_uses_the_device_total_bytes(self, tmp_path):
        sb = bytearray(4096)
        sb[64:72] = b"_BHRfS_M"
        struct.pack_into("<Q", sb, 0x70, 999)        # pool total, multi-device
        struct.pack_into("<Q", sb, 0xD1, 261095424)  # dev_item.total_bytes
        device = self._volume(tmp_path, 65536, sb)
        assert _fs_claimed_size(device, "btrfs") == 261095424

    def test_exfat_volume_length_is_in_sectors(self, tmp_path):
        sb = bytearray(512)
        sb[3:11] = b"EXFAT   "
        struct.pack_into("<Q", sb, 72, 202752)
        sb[108] = 9                              # 512-byte sectors
        device = self._volume(tmp_path, 0, sb)
        assert _fs_claimed_size(device, "exfat") == 202752 * 512

    def test_ntfs_includes_the_backup_boot_sector(self, tmp_path):
        sb = bytearray(512)
        sb[3:11] = b"NTFS    "
        struct.pack_into("<H", sb, 11, 512)
        struct.pack_into("<Q", sb, 40, 120831)
        device = self._volume(tmp_path, 0, sb)
        assert _fs_claimed_size(device, "ntfs") == 120832 * 512

    def test_xfs_superblock_is_big_endian(self, tmp_path):
        sb = bytearray(512)
        sb[:4] = b"XFSB"
        struct.pack_into(">I", sb, 4, 4096)
        struct.pack_into(">Q", sb, 8, 2560)
        device = self._volume(tmp_path, 0, sb)
        assert _fs_claimed_size(device, "xfs") == 2560 * 4096

    def test_unnamed_type_still_finds_the_superblock(self, tmp_path):
        """blkid may name nothing; every probe is magic-checked, so sweep them."""
        sb = bytearray(512)
        sb[3:11] = b"EXFAT   "
        struct.pack_into("<Q", sb, 72, 1000)
        sb[108] = 9
        device = self._volume(tmp_path, 0, sb)
        assert _fs_claimed_size(device, "") == 1000 * 512

    def test_no_superblock_reports_unknown(self, tmp_path):
        assert _fs_claimed_size(self._volume(tmp_path, 0, b"\x00" * 4096),
                                "ext4") == 0

    def test_unreadable_device_reports_unknown(self, tmp_path):
        assert _fs_claimed_size(str(tmp_path / "absent"), "ext4") == 0


class TestWidenToFilesystem:
    """A filesystem bigger than its partition entry is re-exposed in full."""

    DISK = 262144000
    START = 116391936
    TABLE_SIZE = 41943040

    def _part(self):
        return PartitionInfo(device="/dev/loop9", number=1, filesystem="ext4",
                             start_bytes=self.START, size_bytes=self.TABLE_SIZE,
                             window_bytes=self.TABLE_SIZE,
                             backing_loop="/dev/loop9")

    def test_window_is_widened_to_the_claimed_extent(self):
        part = self._part()
        created = ["/dev/loop9"]
        with patch("partition._fs_claimed_size", return_value=145752064), \
             patch("partition._attach_offset_loop",
                   return_value="/dev/loop20") as attach, \
             patch("partition._detach_loop") as detach:
            _widen_to_filesystem(part, "/dev/loop5", self.DISK, created)

        attach.assert_called_once_with("/dev/loop5", self.START, 145752064)
        detach.assert_called_once_with("/dev/loop9")
        assert part.device == "/dev/loop20"
        assert part.window_bytes == 145752064
        assert created == ["/dev/loop20"]

    def test_window_is_capped_at_the_end_of_the_media(self):
        part = self._part()
        with patch("partition._fs_claimed_size", return_value=999999999), \
             patch("partition._attach_offset_loop",
                   return_value="/dev/loop20") as attach, \
             patch("partition._detach_loop"):
            _widen_to_filesystem(part, "/dev/loop5", self.DISK, [])
        attach.assert_called_once_with("/dev/loop5", self.START,
                                       self.DISK - self.START)

    def test_a_filesystem_that_fits_is_left_alone(self):
        part = self._part()
        with patch("partition._fs_claimed_size", return_value=1024), \
             patch("partition._attach_offset_loop") as attach:
            _widen_to_filesystem(part, "/dev/loop5", self.DISK, [])
        attach.assert_not_called()
        assert part.device == "/dev/loop9"
        assert part.fs_claimed_bytes == 1024

    def test_failure_to_widen_keeps_the_original_exposure(self):
        part = self._part()
        with patch("partition._fs_claimed_size", return_value=145752064), \
             patch("partition._attach_offset_loop", return_value=None), \
             patch("partition._detach_loop") as detach:
            _widen_to_filesystem(part, "/dev/loop5", self.DISK, [])
        detach.assert_not_called()
        assert part.device == "/dev/loop9"


class TestDriverAvailability:
    """Tell "this host has no driver" apart from "this volume is broken"."""

    def test_kernel_driver_present(self):
        with patch("partition._kernel_filesystems", return_value={"ext4"}):
            assert _driver_available("ext4") is True

    def test_userspace_helper_counts_as_available(self):
        """ntfs-3g mounts NTFS with no 'ntfs' line in /proc/filesystems."""
        with patch("partition._kernel_filesystems", return_value=set()), \
             patch("partition.tool_exists", side_effect=lambda t: t == "ntfs-3g"):
            assert _driver_available("ntfs") is True

    def test_absent_driver_reported_once_modprobe_fails(self):
        with patch("partition._kernel_filesystems", return_value={"ext4", "vfat"}), \
             patch("partition.tool_exists", return_value=False), \
             patch("partition.run_command", return_value=MagicMock(returncode=1)):
            assert _driver_available("ufs") is False

    def test_module_loaded_on_demand_counts_as_available(self):
        with patch("partition._kernel_filesystems",
                   side_effect=[{"ext4"}, {"ext4", "ufs"}]), \
             patch("partition.tool_exists", return_value=False), \
             patch("partition.run_command", return_value=MagicMock(returncode=0)):
            assert _driver_available("ufs") is True

    def test_no_driver_error_names_the_remedy(self):
        message = _no_driver_error("ufs")
        assert "ufs" in message and "fuse-ufs" in message


class TestDiagnoseMountFailure:
    """The reported cause must name something the analyst can act on."""

    def test_missing_driver_beats_the_catch_all(self):
        part = PartitionInfo(device="/dev/nbd3p4", number=4, filesystem="ufs",
                             size_bytes=5368709120)
        with patch("partition._driver_available", return_value=False):
            message = _diagnose_mount_failure(part,
                                              ["unknown filesystem type 'ufs'"])
        assert message.startswith("no 'ufs' filesystem driver")

    def test_truncated_media_is_named(self):
        """Widening ran out of disk, so the filesystem still doesn't fit."""
        part = PartitionInfo(device="/dev/loop9", number=1, filesystem="btrfs",
                             size_bytes=41943040, window_bytes=50000000,
                             fs_claimed_bytes=261095424)
        with patch("partition._driver_available", return_value=True):
            message = _diagnose_mount_failure(
                part, ["wrong fs type, bad option, bad superblock"])
        assert "261095424" in message and "50000000" in message

    def test_kernel_ring_buffer_explains_the_catch_all(self):
        part = PartitionInfo(device="/dev/loop9", number=1, filesystem="ext4",
                             size_bytes=41943040, window_bytes=41943040)
        with patch("partition._driver_available", return_value=True), \
             patch("partition._dmesg_hint",
                   return_value="EXT4-fs (loop9): bad geometry"):
            message = _diagnose_mount_failure(
                part, ["wrong fs type, bad option, bad superblock"])
        assert "bad geometry" in message

    def test_a_specific_error_is_passed_through(self):
        part = PartitionInfo(device="/dev/loop9", number=1, filesystem="ntfs")
        with patch("partition._driver_available", return_value=True):
            assert _diagnose_mount_failure(
                part, ["Failed to read last sector"]) == "Failed to read last sector"
