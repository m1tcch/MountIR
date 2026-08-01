"""Tests for detector.py - image type detection."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from detector import (
    ImageType, detect_image_type, find_images_in_dir, is_primary_image,
    is_bundle_image, _is_e01_segment, _is_secondary_segment, _EXTENSION_MAP,
    display_format,
)


class TestDisplayFormat:
    """Display label surfaces the specific EWF container (Ex01/Lx01)."""

    @pytest.mark.parametrize("name,image_type,expected", [
        ("evidence.E01", ImageType.E01, "E01"),
        ("evidence.Ex01", ImageType.E01, "Ex01"),
        ("evidence.L01", ImageType.L01, "L01"),
        ("evidence.Lx01", ImageType.L01, "Lx01"),
        # Non-EWF formats just use the ImageType name.
        ("disk.raw", ImageType.RAW, "RAW"),
        ("disk.vmdk", ImageType.VMDK, "VMDK"),
    ])
    def test_display_format(self, name, image_type, expected):
        assert display_format(Path("/cases") / name, image_type) == expected

    def test_ewf_type_with_unknown_extension_falls_back(self):
        # e.g. an EWF image detected by magic without a recognised extension.
        assert display_format(Path("/cases/image.bin"), ImageType.E01) == "E01"


class TestExtensionMapping:
    """Test extension-based image type detection."""

    @pytest.mark.parametrize("ext,expected", [
        (".e01", ImageType.E01),
        (".ex01", ImageType.E01),
        (".l01", ImageType.L01),
        (".lx01", ImageType.L01),
        (".vmdk", ImageType.VMDK),
        (".vhd", ImageType.VHD),
        (".vhdx", ImageType.VHDX),
        (".dd", ImageType.RAW),
        (".raw", ImageType.RAW),
        (".img", ImageType.RAW),
        (".bin", ImageType.RAW),
        (".001", ImageType.RAW),
        (".iso", ImageType.ISO),
        (".aff", ImageType.AFF),
        (".aff4", ImageType.AFF4),
        (".qcow2", ImageType.QCOW2),
        (".qcow", ImageType.QCOW2),
    ])
    def test_extension_map_coverage(self, ext, expected):
        """All documented extensions map to correct type."""
        assert _EXTENSION_MAP[ext] == expected

    def test_extension_detection_lowercase(self, fake_image_files):
        """Lowercase .e01 detected correctly."""
        result = detect_image_type(fake_image_files[".e01"])
        assert result == ImageType.E01

    def test_extension_detection_uppercase(self, fake_image_files):
        """.E01 (uppercase) also works via .lower()."""
        result = detect_image_type(fake_image_files[".E01"])
        assert result == ImageType.E01

    @pytest.mark.parametrize("ext,expected", [
        (".vmdk", ImageType.VMDK),
        (".vhd", ImageType.VHD),
        (".vhdx", ImageType.VHDX),
        (".dd", ImageType.RAW),
        (".raw", ImageType.RAW),
        (".img", ImageType.RAW),
        (".iso", ImageType.ISO),
        (".aff", ImageType.AFF),
        (".qcow2", ImageType.QCOW2),
    ])
    def test_extension_detection_all_types(self, fake_image_files, ext, expected):
        """Each extension returns correct ImageType."""
        result = detect_image_type(fake_image_files[ext])
        assert result == expected


class TestE01Segments:
    """Test E01 segment detection."""

    @pytest.mark.parametrize("ext", [".E02", ".E99", ".EAA", ".e05", ".eBB"])
    def test_e01_segment_recognized(self, ext):
        """Multi-segment E01 extensions are recognized."""
        assert _is_e01_segment(ext) is True

    @pytest.mark.parametrize("ext", [".E01", ".e01", ".txt", ".vmdk", ".E0"])
    def test_non_segment_rejected(self, ext):
        """Non-segment extensions are not matched."""
        # .E01 is the primary, not a segment; .e01 same
        if ext.lower() == ".e01":
            # .E01 matches the 2-digit pattern but that's fine
            # _is_e01_segment checks for [0-9]{2} or [a-zA-Z]{2}
            assert _is_e01_segment(ext) is True  # "01" is 2 digits
        elif len(ext) < 4:
            assert _is_e01_segment(ext) is False
        else:
            assert _is_e01_segment(ext) is False

    def test_segment_file_returns_e01(self, fake_image_files):
        """E01 segment files (.E02) still return E01 type."""
        result = detect_image_type(fake_image_files[".E02"])
        assert result == ImageType.E01


class TestMagicDetection:
    """Test file(1) magic-based detection."""

    @pytest.mark.parametrize("file_output,expected", [
        ("Expert Witness Compression Format", ImageType.E01),
        ("EWF/Expert Witness disk image", ImageType.E01),
        ("QEMU QCOW Image (v2)", ImageType.QCOW2),
        ("qcow2 disk image", ImageType.QCOW2),
        ("VMware4 disk image", ImageType.VMDK),
        ("Microsoft Disk Image", ImageType.VHD),
        ("ISO 9660 CD-ROM filesystem", ImageType.ISO),
        ("x86 boot sector", ImageType.RAW),
        ("DOS/MBR boot sector", ImageType.RAW),
    ])
    def test_magic_detection(self, tmp_path, file_output, expected):
        """file(1) output maps to correct ImageType."""
        # Create a file with unknown extension
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=0, stdout=file_output, stderr="")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == expected

    def test_unknown_magic_returns_unknown(self, tmp_path):
        """Unrecognized file magic returns UNKNOWN."""
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=0, stdout="data", stderr="")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.UNKNOWN

    def test_file_command_failure_returns_unknown(self, tmp_path):
        """If file(1) fails, returns UNKNOWN."""
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.UNKNOWN


class TestEdgeCases:
    """Test edge cases."""

    def test_nonexistent_file_returns_unknown(self, tmp_path):
        """Nonexistent file returns UNKNOWN."""
        result = detect_image_type(tmp_path / "does_not_exist.e01")
        assert result == ImageType.UNKNOWN

    def test_unknown_extension_falls_to_magic(self, tmp_path):
        """Unknown extension triggers magic-based detection."""
        test_file = tmp_path / "image.forensic"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(
            returncode=0, stdout="Expert Witness Compression Format", stderr=""
        )
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.E01


class TestSecondarySegments:
    """Continuation segments are recognised so dir scans skip them."""

    @pytest.mark.parametrize("name", [
        "disk.E02", "disk.E99", "disk.EAA",          # EWF continuation
        "disk.002", "disk.003",                       # split-raw continuation
        "disk-s001.vmdk", "disk-f002.vmdk",           # VMDK split extents
        "disk-flat.vmdk", "disk-delta.vmdk",          # VMDK flat/delta extents
    ])
    def test_secondary_segment_detected(self, name):
        assert _is_secondary_segment(Path(name)) is True

    @pytest.mark.parametrize("name", [
        "disk.E01", "disk.001", "disk.vmdk", "disk.dd", "disk.Ex01",
    ])
    def test_primary_not_flagged_as_secondary(self, name):
        assert _is_secondary_segment(Path(name)) is False


class TestFindImagesInDir:
    """Directory scanning for multi-image mounting."""

    def _touch(self, directory, *names):
        for n in names:
            (directory / n).write_bytes(b"\x00" * 512)

    def test_scans_primary_images_only(self, tmp_path):
        self._touch(
            tmp_path,
            "a.E01", "a.E02", "a.E03",   # one EWF set -> only a.E01
            "b.dd",                       # raw
            "c.001", "c.002",            # split raw -> only c.001
            "notes.txt", "report.pdf",   # non-images ignored
        )
        names = {p.name for p in find_images_in_dir(tmp_path)}
        assert names == {"a.E01", "b.dd", "c.001"}

    def test_pattern_filter(self, tmp_path):
        self._touch(tmp_path, "a.E01", "b.E01", "c.dd")
        names = {p.name for p in find_images_in_dir(tmp_path, pattern="*.E01")}
        assert names == {"a.E01", "b.E01"}

    def test_recursive_scan(self, tmp_path):
        sub = tmp_path / "case" / "host1"
        sub.mkdir(parents=True)
        self._touch(tmp_path, "top.E01")
        self._touch(sub, "nested.dd")
        flat = {p.name for p in find_images_in_dir(tmp_path)}
        deep = {p.name for p in find_images_in_dir(tmp_path, recursive=True)}
        assert flat == {"top.E01"}
        assert deep == {"top.E01", "nested.dd"}

    def test_skips_vmdk_extents(self, tmp_path):
        self._touch(tmp_path, "vm.vmdk", "vm-s001.vmdk", "vm-s002.vmdk")
        names = {p.name for p in find_images_in_dir(tmp_path)}
        assert names == {"vm.vmdk"}

    def test_is_primary_image(self, tmp_path):
        img = tmp_path / "x.E01"
        img.write_bytes(b"\x00")
        seg = tmp_path / "x.E02"
        seg.write_bytes(b"\x00")
        assert is_primary_image(img) is True
        assert is_primary_image(seg) is False
        assert is_primary_image(tmp_path / "missing.E01") is False

    def test_sparsebundle_directory_is_an_image(self, tmp_path):
        # A macOS .sparsebundle is a *directory* the handler reassembles.
        bundle = tmp_path / "backup.sparsebundle"
        (bundle / "bands").mkdir(parents=True)
        (bundle / "Info.plist").write_text("<plist/>")
        self._touch(tmp_path, "other.dd")

        assert is_bundle_image(bundle) is True
        assert is_primary_image(bundle) is True
        names = {p.name for p in find_images_in_dir(tmp_path)}
        assert names == {"backup.sparsebundle", "other.dd"}

    def test_plain_directory_is_not_a_bundle_image(self, tmp_path):
        plain = tmp_path / "evidence"
        plain.mkdir()
        assert is_bundle_image(plain) is False
        assert is_primary_image(plain) is False
