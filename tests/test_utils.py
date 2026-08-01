"""Tests for utils.py - utility functions."""

import logging
import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from utils import (
    format_bytes,
    generate_mount_id,
    setup_logging,
    ensure_mount_dir,
    cleanup_mount_dir,
    tool_exists,
    find_mounts_under,
    loop_devices_backing,
)


class TestFormatBytes:
    """Test human-readable byte formatting."""

    @pytest.mark.parametrize("value,expected", [
        (0, "0 B"),
        (512, "512 B"),
        (1023, "1023 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1048576, "1.0 MB"),
        (1073741824, "1.0 GB"),
        (1099511627776, "1.0 TB"),
    ])
    def test_format_bytes(self, value, expected):
        assert format_bytes(value) == expected


class TestGenerateMountId:
    """Test mount ID generation."""

    def test_with_case_id_and_name(self):
        """Case ID and image name are included."""
        mid = generate_mount_id("IR-2026-001", "disk")
        assert "IR-2026-001" in mid
        assert "disk" in mid
        # Should have a 6-char random suffix
        parts = mid.split("_")
        assert len(parts[-1]) == 6

    def test_without_case_id(self):
        """No case ID produces EV_ prefix."""
        mid = generate_mount_id(None, "disk")
        # Should contain disk and random
        assert "disk" in mid

    def test_no_case_no_name(self):
        """No case ID or name produces EV_{random}."""
        mid = generate_mount_id(None, "")
        assert mid.startswith("EV_")
        assert len(mid) == 9  # "EV_" + 6 random chars

    def test_special_characters_sanitized(self):
        """Special characters are stripped from case ID."""
        mid = generate_mount_id("IR/2026:001!", "disk image.E01")
        # Only alphanumeric, underscore, and hyphen should remain
        assert re.match(r"^[a-zA-Z0-9_-]+$", mid)

    def test_uniqueness(self):
        """Two calls produce different IDs (random suffix)."""
        id1 = generate_mount_id("CASE", "disk")
        id2 = generate_mount_id("CASE", "disk")
        assert id1 != id2


class TestToolExists:
    """Test tool availability checking."""

    def test_tool_found(self, mock_which):
        """Returns True when tool is on PATH."""
        mock_which.return_value = "/usr/bin/losetup"
        assert tool_exists("losetup") is True

    def test_tool_not_found(self, mock_which):
        """Returns False when tool is not on PATH."""
        mock_which.return_value = None
        assert tool_exists("nonexistent_tool") is False


class TestCheckRoot:
    """Test root privilege checking."""

    def test_is_root(self):
        """Returns True when euid is 0."""
        with patch("utils.check_root", return_value=True) as mock_cr:
            assert mock_cr() is True

    def test_not_root(self):
        """Returns False when euid is non-zero."""
        with patch("utils.check_root", return_value=False) as mock_cr:
            assert mock_cr() is False

    def test_check_root_function_exists(self):
        """check_root is callable."""
        from utils import check_root
        assert callable(check_root)


class TestSetupLogging:
    """Test dual logging setup."""

    def test_creates_log_file(self, tmp_path, monkeypatch):
        """Log file is created in logs/ directory."""
        monkeypatch.setattr("utils.SCRIPT_DIR", tmp_path)
        log_file = setup_logging(verbose=False)
        assert log_file is not None
        assert log_file.exists()
        assert "mountir_" in log_file.name
        assert log_file.suffix == ".log"

    def test_verbose_mode(self, tmp_path, monkeypatch):
        """Verbose mode sets console handler to DEBUG."""
        monkeypatch.setattr("utils.SCRIPT_DIR", tmp_path)
        setup_logging(verbose=True)
        logger = logging.getLogger("MountIR")
        # Should have 2 handlers: file + console
        assert len(logger.handlers) == 2
        console_handler = [h for h in logger.handlers
                          if isinstance(h, logging.StreamHandler)
                          and not isinstance(h, logging.FileHandler)][0]
        assert console_handler.level == logging.DEBUG

    def test_non_verbose_mode(self, tmp_path, monkeypatch):
        """Non-verbose mode sets console handler to INFO."""
        monkeypatch.setattr("utils.SCRIPT_DIR", tmp_path)
        setup_logging(verbose=False)
        logger = logging.getLogger("MountIR")
        console_handler = [h for h in logger.handlers
                          if isinstance(h, logging.StreamHandler)
                          and not isinstance(h, logging.FileHandler)][0]
        assert console_handler.level == logging.INFO


class TestMountDirHelpers:
    """Test directory creation and cleanup."""

    def test_ensure_mount_dir_creates(self, tmp_path):
        """Creates nested directories."""
        target = tmp_path / "a" / "b" / "c"
        result = ensure_mount_dir(target)
        assert target.is_dir()
        assert result == target

    def test_ensure_mount_dir_existing(self, tmp_path):
        """No error on existing directory."""
        target = tmp_path / "existing"
        target.mkdir()
        result = ensure_mount_dir(target)
        assert target.is_dir()
        assert result == target

    def test_cleanup_empty_dir(self, tmp_path):
        """Removes empty directory tree."""
        target = tmp_path / "to_remove"
        (target / "sub").mkdir(parents=True)
        cleanup_mount_dir(target)
        assert not target.exists()

    def test_cleanup_non_empty_dir(self, tmp_path):
        """Skips non-empty directory."""
        target = tmp_path / "has_file"
        target.mkdir()
        (target / "important.dat").write_text("data")
        cleanup_mount_dir(target)
        # Should still exist because it has content
        assert target.exists()


class TestFindMountsUnder:
    """Test parsing /proc/mounts to find mounts under a base (for 'clean')."""

    PROC = (
        "sysfs /sys sysfs rw 0 0\n"
        "/dev/loop3 /mnt/mountir/ev_a/container fuseblk ro 0 0\n"
        "/dev/loop3p1 /mnt/mountir/ev_a/partitions/p1_ntfs ntfs ro 0 0\n"
        "/dev/loop3p3 /mnt/mountir/ev_a/partitions/p3_ext4 ext4 ro 0 0\n"
        "/dev/sda1 /mnt/other ext4 rw 0 0\n"
    )

    def test_finds_only_under_base(self):
        found = find_mounts_under(Path("/mnt/mountir"), proc_mounts=self.PROC)
        assert all(p.startswith("/mnt/mountir") for p in found)
        assert "/mnt/other" not in found
        assert len(found) == 3

    def test_deepest_first(self):
        found = find_mounts_under(Path("/mnt/mountir"), proc_mounts=self.PROC)
        # Partitions (deeper) must come before their container (shallower).
        assert found[-1] == "/mnt/mountir/ev_a/container"

    def test_handles_escaped_spaces(self):
        proc = "/dev/loop0 /mnt/mountir/ev\\040b/container fuseblk ro 0 0\n"
        found = find_mounts_under(Path("/mnt/mountir"), proc_mounts=proc)
        assert found == ["/mnt/mountir/ev b/container"]

    def test_no_matches(self):
        found = find_mounts_under(Path("/mnt/mountir"), proc_mounts="/dev/sda1 / ext4 rw 0 0\n")
        assert found == []


class TestLoopDevicesBacking:
    """Test parsing 'losetup -a' to find loops backing files under a base."""

    LOSETUP = (
        "/dev/loop0: [2049]:12 (/var/lib/snapd/snaps/core.snap)\n"
        "/dev/loop3: [2049]:131 (/mnt/mountir/ev_a/container/ewf1)\n"
        "/dev/loop4: [2049]:140 (/mnt/mountir/ev_b/container/ewf1)\n"
    )

    def test_matches_under_base(self):
        devs = loop_devices_backing(Path("/mnt/mountir"), losetup_output=self.LOSETUP)
        assert devs == ["/dev/loop3", "/dev/loop4"]

    def test_ignores_unrelated(self):
        devs = loop_devices_backing(Path("/mnt/mountir"), losetup_output=self.LOSETUP)
        assert "/dev/loop0" not in devs

    def test_empty_output(self):
        assert loop_devices_backing(Path("/mnt/mountir"), losetup_output="") == []

    def test_offset_loop_suffix(self):
        """Offset/sizelimit loops print a trailing suffix that must still match."""
        output = (
            "/dev/loop3: [2049]:131 (/mnt/mountir/ev_a/container/ewf1)\n"
            "/dev/loop5: [2049]:131 (/mnt/mountir/ev_a/container/ewf1), offset 1048576, sizelimit 32505856\n"
            "/dev/loop6: [2049]:131 (/mnt/mountir/ev_a/container/ewf1), offset 33554432, sizelimit 33554432\n"
        )
        devs = loop_devices_backing(Path("/mnt/mountir"), losetup_output=output)
        assert devs == ["/dev/loop3", "/dev/loop5", "/dev/loop6"]
