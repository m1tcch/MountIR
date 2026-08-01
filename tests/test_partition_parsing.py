"""Tests for partition.py - fdisk/blkid output parsing and mount options."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from partition import (
    _detect_via_fdisk,
    _enrich_with_blkid,
    _fuse_mount_commands,
    _geometry_ok,
    _mount_attempts,
    _whole_volume_fs,
    infer_os,
    mount_partition,
    _FUSE_MOUNTERS,
    _MOUNT_OPTIONS,
    _DEFAULT_MOUNT_OPTIONS,
    _SKIP_FILESYSTEMS,
    PartitionInfo,
)


class TestFdiskParsing:
    """Test fdisk output parsing."""

    FDISK_MBR_OUTPUT = """\
Disk /dev/loop0: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x12345678

Device       Boot  Start    End Sectors Size Id Type
/dev/loop0p1 *      2048  65535   63488  31M 83 Linux
/dev/loop0p2       65536 131071   65536  32M 82 Linux swap
"""

    FDISK_GPT_OUTPUT = """\
Disk /dev/nbd0: 100 GiB, 107374182400 bytes, 209715200 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: ABCDEF12-3456-7890-ABCD-EF1234567890

Device        Start       End   Sectors  Size Type
/dev/nbd0p1    2048   1050623   1048576  512M EFI System
/dev/nbd0p2 1050624 209713151 208662528 99.5G Linux filesystem
"""

    FDISK_EMPTY_OUTPUT = """\
Disk /dev/loop1: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
"""

    def test_parse_mbr_partitions(self):
        """Parse fdisk output with MBR partition table."""
        mock_result = MagicMock(returncode=0, stdout=self.FDISK_MBR_OUTPUT, stderr="")
        with patch("partition.run_command", return_value=mock_result):
            parts = _detect_via_fdisk("/dev/loop0")

        assert len(parts) == 2
        assert parts[0].device == "/dev/loop0p1"
        assert parts[0].start_sector == 2048
        assert parts[1].device == "/dev/loop0p2"
        assert parts[1].start_sector == 65536

    def test_parse_gpt_partitions(self):
        """Parse fdisk output with GPT partition table."""
        mock_result = MagicMock(returncode=0, stdout=self.FDISK_GPT_OUTPUT, stderr="")
        with patch("partition.run_command", return_value=mock_result):
            parts = _detect_via_fdisk("/dev/nbd0")

        assert len(parts) == 2
        assert parts[0].device == "/dev/nbd0p1"
        assert parts[1].device == "/dev/nbd0p2"

    def test_parse_empty_disk(self):
        """No partitions on empty disk."""
        mock_result = MagicMock(returncode=0, stdout=self.FDISK_EMPTY_OUTPUT, stderr="")
        with patch("partition.run_command", return_value=mock_result):
            parts = _detect_via_fdisk("/dev/loop1")

        assert len(parts) == 0

    def test_fdisk_failure(self):
        """fdisk failure returns empty list."""
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("partition.run_command", return_value=mock_result):
            parts = _detect_via_fdisk("/dev/loop0")

        assert parts == []

    def test_boot_flag_handling(self):
        """Partition with boot flag (*) parsed correctly."""
        mock_result = MagicMock(returncode=0, stdout=self.FDISK_MBR_OUTPUT, stderr="")
        with patch("partition.run_command", return_value=mock_result):
            parts = _detect_via_fdisk("/dev/loop0")

        # First partition has boot flag, start_sector should still be 2048
        assert parts[0].start_sector == 2048


class TestBlkidEnrichment:
    """Test blkid output parsing."""

    def test_ntfs_partition(self):
        """blkid detects NTFS filesystem and label."""
        blkid_output = "DEVNAME=/dev/loop0p1\nTYPE=ntfs\nLABEL=Windows\n"
        mock_result = MagicMock(returncode=0, stdout=blkid_output, stderr="")

        part = PartitionInfo(device="/dev/loop0p1", number=1)
        with patch("partition.run_command", return_value=mock_result):
            _enrich_with_blkid(part)

        assert part.filesystem == "ntfs"
        assert part.label == "Windows"

    def test_ext4_partition(self):
        """blkid detects ext4 filesystem."""
        blkid_output = "DEVNAME=/dev/loop0p1\nTYPE=ext4\nLABEL=root\n"
        mock_result = MagicMock(returncode=0, stdout=blkid_output, stderr="")

        part = PartitionInfo(device="/dev/loop0p1", number=1)
        with patch("partition.run_command", return_value=mock_result):
            _enrich_with_blkid(part)

        assert part.filesystem == "ext4"

    def test_swap_partition(self):
        """blkid detects swap."""
        blkid_output = "DEVNAME=/dev/loop0p2\nTYPE=swap\n"
        mock_result = MagicMock(returncode=0, stdout=blkid_output, stderr="")

        part = PartitionInfo(device="/dev/loop0p2", number=2)
        with patch("partition.run_command", return_value=mock_result):
            _enrich_with_blkid(part)

        assert part.filesystem == "swap"

    def test_lvm_member(self):
        """blkid detects LVM2_member."""
        blkid_output = "DEVNAME=/dev/loop0p3\nTYPE=LVM2_member\n"
        mock_result = MagicMock(returncode=0, stdout=blkid_output, stderr="")

        part = PartitionInfo(device="/dev/loop0p3", number=3)
        with patch("partition.run_command", return_value=mock_result):
            _enrich_with_blkid(part)

        assert part.filesystem == "lvm2_member"

    def test_blkid_failure(self):
        """blkid failure leaves partition unchanged."""
        mock_result = MagicMock(returncode=2, stdout="", stderr="")

        part = PartitionInfo(device="/dev/loop0p1", number=1)
        with patch("partition.run_command", return_value=mock_result):
            _enrich_with_blkid(part)

        assert part.filesystem == ""
        assert part.label == ""


class TestMountOptions:
    """Test forensic mount option mapping."""

    def test_ntfs_options(self):
        opts = _MOUNT_OPTIONS["ntfs"]
        assert "ro" in opts
        assert "noatime" in opts
        assert "noexec" in opts
        assert "show_sys_files" in opts
        assert "streams_interface=windows" in opts

    def test_ext4_options(self):
        opts = _MOUNT_OPTIONS["ext4"]
        assert "ro" in opts
        assert "norecovery" in opts

    def test_xfs_options(self):
        opts = _MOUNT_OPTIONS["xfs"]
        assert "ro" in opts
        assert "norecovery" in opts

    def test_vfat_options(self):
        opts = _MOUNT_OPTIONS["vfat"]
        assert "ro" in opts
        assert "norecovery" not in opts  # vfat has no journal

    def test_default_options(self):
        assert "ro" in _DEFAULT_MOUNT_OPTIONS
        assert "noatime" in _DEFAULT_MOUNT_OPTIONS
        assert "noexec" in _DEFAULT_MOUNT_OPTIONS

    def test_all_options_include_ro(self):
        """Every filesystem option set includes ro."""
        for fs, opts in _MOUNT_OPTIONS.items():
            assert "ro" in opts, f"{fs} missing 'ro' flag"

    def test_all_options_include_noatime(self):
        """Every filesystem option set includes noatime."""
        for fs, opts in _MOUNT_OPTIONS.items():
            assert "noatime" in opts, f"{fs} missing 'noatime' flag"


class TestFilesystemDetectionFallbacks:
    """Multi-method detection for freshly-attached loop/NBD partitions."""

    def test_blkid_probe_used_first(self):
        """Low-level probe (-p) is tried first and bypasses the empty cache."""
        probe = MagicMock(returncode=0, stdout="TYPE=ntfs\nLABEL=Windows\n", stderr="")
        part = PartitionInfo(device="/dev/loop3p1", number=1)
        with patch("partition.run_command", return_value=probe) as rc:
            _enrich_with_blkid(part)
        assert part.filesystem == "ntfs"
        assert part.label == "Windows"
        first_cmd = rc.call_args_list[0].args[0]
        assert first_cmd[:2] == ["blkid", "-p"]

    def test_lsblk_fallback(self):
        """When blkid yields nothing, lsblk resolves the type and label."""
        calls = [
            MagicMock(returncode=2, stdout="", stderr=""),   # blkid -p
            MagicMock(returncode=2, stdout="", stderr=""),   # blkid cache
            MagicMock(returncode=0, stdout="ext4 cloudimg-rootfs\n", stderr=""),
        ]
        part = PartitionInfo(device="/dev/loop3p1", number=1)
        with patch("partition.run_command", side_effect=calls):
            _enrich_with_blkid(part)
        assert part.filesystem == "ext4"
        assert part.label == "cloudimg-rootfs"

    def test_file_magic_fallback(self):
        """file(1) magic is the last resort when everything else is empty."""
        calls = [
            MagicMock(returncode=2, stdout="", stderr=""),   # blkid -p
            MagicMock(returncode=2, stdout="", stderr=""),   # blkid cache
            MagicMock(returncode=0, stdout="\n", stderr=""),  # lsblk (empty)
            MagicMock(returncode=0, stdout="Linux rev 1.0 ext4 filesystem data", stderr=""),
        ]
        part = PartitionInfo(device="/dev/loop3p1", number=1)
        with patch("partition.run_command", side_effect=calls):
            _enrich_with_blkid(part)
        assert part.filesystem == "ext4"

    def test_detection_survives_missing_blkid(self):
        """If blkid isn't installed, detection still falls through to lsblk."""
        calls = [
            FileNotFoundError("blkid"),                      # blkid -p
            FileNotFoundError("blkid"),                      # blkid cache
            MagicMock(returncode=0, stdout="ntfs Windows\n", stderr=""),
        ]
        part = PartitionInfo(device="/dev/loop3p1", number=1)
        with patch("partition.run_command", side_effect=calls):
            _enrich_with_blkid(part)
        assert part.filesystem == "ntfs"

    def test_all_methods_fail_leaves_empty(self):
        """When nothing detects a type, filesystem stays empty (mount auto-tries)."""
        calls = [MagicMock(returncode=2, stdout="", stderr="")] * 4
        part = PartitionInfo(device="/dev/loop3p1", number=1)
        with patch("partition.run_command", side_effect=calls):
            _enrich_with_blkid(part)
        assert part.filesystem == ""


class TestMountAttempts:
    """Mount-attempt ordering and driver fallbacks."""

    def test_ntfs_attempts_cover_drivers(self):
        types = [t for t, _ in _mount_attempts("ntfs")]
        assert "ntfs3" in types and "ntfs-3g" in types
        assert None in types  # auto-detect fallback present

    def test_unknown_fs_auto_detects(self):
        assert _mount_attempts("") == [(None, _DEFAULT_MOUNT_OPTIONS)]

    def test_known_fs_then_auto(self):
        attempts = _mount_attempts("ext4")
        assert attempts[0][0] == "ext4"
        assert attempts[-1][0] is None  # ends with auto-detect

    def test_ufs_sets_ufstype(self):
        """UFS needs ufstype= or the BSD/NetScaler superblock isn't recognised."""
        attempts = _mount_attempts("ufs")
        opt_sets = [opts for t, opts in attempts if t == "ufs"]
        assert any("ufstype=ufs2" in o for o in opt_sets)   # FreeBSD/NetScaler
        assert any("ufstype=44bsd" in o for o in opt_sets)  # older BSD
        assert attempts[-1][0] is None

    def test_hfsplus_force_fallback(self):
        """A journaled HFS+ volume falls back to a forced read-only mount."""
        attempts = _mount_attempts("hfsplus")
        forced = [opts for t, opts in attempts if t == "hfsplus" and "force" in opts]
        assert forced, "expected an hfsplus attempt with force"
        assert all("ro" in opts for t, opts in attempts if t)

    def test_exfat_fuse_fallback(self):
        """exFAT tries the kernel driver, then the exfat-fuse helper."""
        types = [t for t, _ in _mount_attempts("exfat")]
        assert types[0] == "exfat"
        assert "exfat-fuse" in types
        assert types[-1] is None


class TestForceMountSweep:
    """--force adds a 'mount anyway' sweep regardless of OS/filesystem."""

    def test_unknown_fs_force_sweeps_many_types(self):
        normal = _mount_attempts("", force=False)
        forced = _mount_attempts("", force=True)
        assert normal == [(None, _DEFAULT_MOUNT_OPTIONS)]
        forced_types = {t for t, _ in forced}
        # Brute-forces the common drivers across operating systems.
        assert {"ntfs3", "ext4", "xfs", "btrfs", "vfat", "hfsplus", "ufs"} \
            <= forced_types
        assert len(forced) > len(normal)

    def test_force_keeps_detected_type_first(self):
        forced = _mount_attempts("ext4", force=True)
        assert forced[0][0] == "ext4"          # detected type still tried first
        # ...then the sweep follows with other drivers.
        assert any(t == "ntfs3" for t, _ in forced)

    def test_force_does_not_duplicate_attempts(self):
        forced = _mount_attempts("ntfs", force=True)
        assert len(forced) == len(set(forced)), "force sweep should de-dup attempts"

    def test_force_offers_all_fuse_drivers_as_last_resort(self):
        # Without force, a non-APFS/VMFS type has no FUSE binary commands.
        assert _fuse_mount_commands("ext4", "/dev/loop3", Path("/mnt/x")) == []
        # With force, every dedicated FUSE driver is offered as a fallback.
        bins = [c[0] for c in _fuse_mount_commands(
            "ext4", "/dev/loop3", Path("/mnt/x"), force=True)]
        assert "apfs-fuse" in bins and "vmfs-fuse" in bins


class TestForceWholeDiskFallback:
    """--force exposes the whole disk when no usable partition table exists."""

    def test_corrupt_table_exposes_whole_disk(self, tmp_path):
        from partition import expose_partitions

        img = tmp_path / "corrupt.raw"
        img.write_bytes(b"\x00" * 4096)

        with patch("partition._whole_volume_fs", return_value=("", "")), \
             patch("partition.read_partition_table", return_value=[]), \
             patch("partition._enrich_with_blkid"), \
             patch("partition._attach_offset_loop", return_value="/dev/loop9"):
            parts, created = expose_partitions(str(img), force=True)

        assert len(parts) == 1
        assert parts[0].device == "/dev/loop9"
        assert created == ["/dev/loop9"]

    def test_without_force_no_fallback(self, tmp_path):
        from partition import expose_partitions

        img = tmp_path / "corrupt.raw"
        img.write_bytes(b"\x00" * 4096)

        with patch("partition._whole_volume_fs", return_value=("", "")), \
             patch("partition.read_partition_table", return_value=[]), \
             patch("partition._attach_offset_loop", return_value="/dev/loop9"):
            parts, created = expose_partitions(str(img), force=False)

        assert parts == []
        assert created == []


class TestFuseMounters:
    """Standalone FUSE binaries (APFS/VMFS) have no `mount -t` helper."""

    def test_apfs_uses_apfs_fuse_binary(self):
        cmds = _fuse_mount_commands("apfs", "/dev/loop3", Path("/mnt/x"))
        assert cmds and cmds[0][0] == "apfs-fuse"
        assert cmds[0][-2:] == ["/dev/loop3", "/mnt/x"]
        assert "ro" in ",".join(cmds[0])

    def test_vmfs_tries_both_generations(self):
        bins = [c[0] for c in _fuse_mount_commands("vmfs", "/dev/loop3", Path("/mnt/x"))]
        assert bins == ["vmfs-fuse", "vmfs6-fuse"]

    def test_non_fuse_fs_has_no_binary_commands(self):
        assert _fuse_mount_commands("ext4", "/dev/loop3", Path("/mnt/x")) == []
        assert _fuse_mount_commands("ntfs", "/dev/loop3", Path("/mnt/x")) == []


class TestMountPartitionErrorSelection:
    """Reported mount error reflects the detected type, not the force-mode
    sweep over unrelated FUSE drivers."""

    @staticmethod
    def _fake_run(cmd, **kw):
        import subprocess
        if cmd and cmd[0] in ("apfs-fuse", "vmfs-fuse", "vmfs6-fuse"):
            raise FileNotFoundError(cmd[0])          # FUSE binaries "missing"
        raise subprocess.CalledProcessError(         # standard mount fails
            32, cmd, stderr="mount: bad superblock on /dev/loop2")

    def test_non_fuse_type_reports_standard_error(self, tmp_path):
        # An unknown-type partition in force mode sweeps every FUSE driver; a
        # missing swept driver must NOT mask the real "bad superblock" error.
        part = PartitionInfo(device="/dev/loop2", number=1, filesystem="")
        with patch("partition.run_command", side_effect=self._fake_run), \
             patch("partition.ensure_mount_dir"):
            result = mount_partition(part, tmp_path / "p1", force=True)
        assert result.mounted is False
        assert "superblock" in result.mount_error
        assert "vmfs6-fuse" not in result.mount_error

    def test_vmfs_type_reports_its_own_driver(self, tmp_path):
        # For a genuinely-VMFS partition the actionable error is a vmfs driver,
        # never the swept apfs-fuse.
        part = PartitionInfo(device="/dev/loop2", number=1, filesystem="vmfs")
        with patch("partition.run_command", side_effect=self._fake_run), \
             patch("partition.ensure_mount_dir"):
            result = mount_partition(part, tmp_path / "p1", force=True)
        assert result.mounted is False
        assert "vmfs" in result.mount_error
        assert "apfs" not in result.mount_error


class TestMountPartitionDispatch:
    """mount_partition chooses FUSE binaries vs `mount`, and skips pseudo-FS."""

    def test_apfs_invokes_fuse_binary_not_mount(self, tmp_path):
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="apfs")
        with patch("partition.run_command", return_value=MagicMock(returncode=0)) as rc:
            mount_partition(part, tmp_path / "mp")
        assert part.mounted is True
        assert rc.call_args.args[0][0] == "apfs-fuse"

    def test_apfs_fuse_missing_records_error(self, tmp_path):
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="apfs")
        # FUSE binary absent and no kernel apfs driver -> stays unmounted.
        with patch("partition.run_command", side_effect=FileNotFoundError("apfs-fuse")):
            mount_partition(part, tmp_path / "mp")
        assert part.mounted is False
        assert "not installed" in (part.mount_error or "")

    def test_zfs_member_is_skipped(self, tmp_path):
        assert "zfs_member" in _SKIP_FILESYSTEMS
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="zfs_member")
        with patch("partition.run_command") as rc:
            mount_partition(part, tmp_path / "mp")
        assert part.mounted is False
        rc.assert_not_called()

    def test_ufs_falls_through_to_mount(self, tmp_path):
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="ufs")
        with patch("partition.run_command", return_value=MagicMock(returncode=0)) as rc:
            mount_partition(part, tmp_path / "mp")
        assert part.mounted is True
        cmd = rc.call_args.args[0]
        assert cmd[0] == "mount"
        assert "ufstype=ufs2" in cmd[2]


class TestWholeVolumeDetection:
    """Single-volume images (filesystem at offset 0, no partition table)."""

    def test_bare_ntfs_volume(self):
        """blkid TYPE with no PTTYPE => single NTFS volume image."""
        out = "DEVNAME=/path/ewf1\nTYPE=ntfs\nLABEL=Data\n"
        mock = MagicMock(returncode=0, stdout=out, stderr="")
        with patch("partition.run_command", return_value=mock):
            fstype, label = _whole_volume_fs("/path/ewf1")
        assert fstype == "ntfs"
        assert label == "Data"

    def test_partitioned_disk_returns_empty(self):
        """blkid reporting PTTYPE means a partition table - not a bare volume."""
        out = "DEVNAME=/path/ewf1\nPTTYPE=gpt\n"
        mock = MagicMock(returncode=0, stdout=out, stderr="")
        with patch("partition.run_command", return_value=mock):
            fstype, label = _whole_volume_fs("/path/ewf1")
        assert fstype == ""
        assert label == ""

    def test_pttype_wins_over_stray_type(self):
        """A partition table present => not treated as a whole volume."""
        out = "DEVNAME=/path/ewf1\nPTTYPE=dos\nTYPE=ntfs\n"
        mock = MagicMock(returncode=0, stdout=out, stderr="")
        with patch("partition.run_command", return_value=mock):
            fstype, _ = _whole_volume_fs("/path/ewf1")
        assert fstype == ""

    def test_falls_back_to_file_magic(self):
        """When blkid yields nothing, file(1) magic decides."""
        calls = [
            MagicMock(returncode=2, stdout="", stderr=""),          # blkid -p
            MagicMock(returncode=0, stdout="NTFS filesystem data", stderr=""),  # file
        ]
        with patch("partition.run_command", side_effect=calls):
            fstype, _ = _whole_volume_fs("/path/ewf1")
        assert fstype == "ntfs"


class TestGeometryValidation:
    """Reject phantom partitions whose geometry can't fit the media."""

    DISK = 16 * 1024**3  # 16 GiB

    def test_valid_partition(self):
        p = PartitionInfo(number=1, start_bytes=1048576, size_bytes=10 * 1024**3)
        assert _geometry_ok(p, self.DISK) is True

    def test_offset_past_end_rejected(self):
        # The off_wrk03 phantom: offset ~916 GB on a 16 GB image.
        p = PartitionInfo(number=1, start_bytes=983153655808, size_bytes=1024)
        assert _geometry_ok(p, self.DISK) is False

    def test_end_past_disk_rejected(self):
        p = PartitionInfo(number=1, start_bytes=1048576, size_bytes=self.DISK)
        assert _geometry_ok(p, self.DISK) is False

    def test_zero_size_rejected(self):
        p = PartitionInfo(number=1, start_bytes=1048576, size_bytes=0)
        assert _geometry_ok(p, self.DISK) is False

    def test_unknown_disk_size_allows(self):
        """When disk size is unknown (0), only sanity bounds apply."""
        p = PartitionInfo(number=1, start_bytes=1048576, size_bytes=10 * 1024**3)
        assert _geometry_ok(p, 0) is True


class TestInferOS:
    """Best-effort OS inference from detected filesystems."""

    @staticmethod
    def _p(fs, label=""):
        return PartitionInfo(device="/dev/loop0p1", number=1, filesystem=fs, label=label)

    def test_windows_from_ntfs(self):
        assert infer_os([self._p("vfat", "EFI"), self._p("ntfs", "Windows")]) == "Windows"

    def test_linux_from_ext4(self):
        assert infer_os([self._p("ext4", "root")]) == "Linux"

    def test_macos_from_apfs(self):
        assert infer_os([self._p("apfs")]) == "macOS"

    def test_esxi_from_vmfs(self):
        assert infer_os([self._p("vmfs")]) == "VMware ESXi (VMFS datastore)"

    def test_bsd_appliance_from_ufs(self):
        assert "NetScaler" in infer_os([self._p("ufs")])

    def test_zfs_appliance(self):
        assert "ZFS" in infer_os([self._p("zfs_member")])

    def test_unknown_when_no_signal(self):
        assert infer_os([self._p("")]) == "Unknown"
