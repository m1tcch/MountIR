"""Tests for mountir.py - CLI argument parsing and helpers."""

import io
import json
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mountir import (
    build_parser, MOUNTIR_VERSION, _apply_json_input, _filter_by_base,
    _collect_images,
)


def _mount_args(image_path, recursive=False, pattern=None):
    """A minimal Namespace for _collect_images()."""
    return Namespace(image_path=image_path, recursive=recursive, pattern=pattern)


class TestCollectImages:
    """_collect_images expands files, globs, and directories."""

    def test_single_file(self, tmp_path):
        f = tmp_path / "a.E01"
        f.write_bytes(b"\x00")
        got = _collect_images(_mount_args([str(f)]))
        assert [p.name for p in got] == ["a.E01"]

    def test_directory_scan(self, tmp_path):
        for n in ("a.E01", "a.E02", "b.dd", "notes.txt"):
            (tmp_path / n).write_bytes(b"\x00")
        got = {p.name for p in _collect_images(_mount_args([str(tmp_path)]))}
        assert got == {"a.E01", "b.dd"}

    def test_sparsebundle_dir_mounted_not_scanned(self, tmp_path):
        # Passing a .sparsebundle directly mounts it (does not recurse into it).
        bundle = tmp_path / "vol.sparsebundle"
        (bundle / "bands").mkdir(parents=True)
        got = _collect_images(_mount_args([str(bundle)]))
        assert [p.name for p in got] == ["vol.sparsebundle"]

    def test_dedup_across_entries(self, tmp_path):
        f = tmp_path / "a.E01"
        f.write_bytes(b"\x00")
        got = _collect_images(_mount_args([str(f), str(f)]))
        assert len(got) == 1

    def test_glob_no_match_yields_nothing(self, tmp_path):
        # A wildcard that matches nothing returns [] (no literal-path attempt).
        got = _collect_images(_mount_args([str(tmp_path / "*.E01")]))
        assert got == []

    def test_missing_explicit_file(self, tmp_path):
        got = _collect_images(_mount_args([str(tmp_path / "missing.E01")]))
        assert got == []


class _Img:
    """Minimal stand-in for a MountedImage (just the fields the filter reads)."""
    def __init__(self, mount_id, mount_base):
        self.mount_id = mount_id
        self.mount_base = mount_base


class TestFilterByBase:
    """list -d/--mount-base filters mounts to those under a given base."""

    def _images(self):
        return [
            _Img("a", "/mnt/mountir"),
            _Img("b", "/mnt/case42"),
            _Img("c", "/mnt/case42/sub"),
        ]

    def test_none_lists_everything(self):
        imgs = self._images()
        assert _filter_by_base(imgs, None) == imgs

    def test_filters_to_matching_base(self):
        ids = [i.mount_id for i in _filter_by_base(self._images(), "/mnt/case42")]
        assert ids == ["b", "c"]  # includes nested base

    def test_trailing_slash_normalised(self):
        ids = [i.mount_id for i in _filter_by_base(self._images(), "/mnt/mountir/")]
        assert ids == ["a"]

    def test_no_match_returns_empty(self):
        assert _filter_by_base(self._images(), "/mnt/nowhere") == []


class TestBuildParser:
    """Test argument parser construction."""

    def test_mount_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "/evidence/disk.E01"])
        assert args.command == "mount"
        # image_path is now a list (multi-image support)
        assert args.image_path == ["/evidence/disk.E01"]
        assert args.mount_base == "/mnt/mountir"
        assert args.case_id == ""
        assert args.no_partitions is False
        assert args.force is False
        assert args.recursive is False
        assert args.pattern is None
        assert args.verbose is False
        assert args.json is False

    def test_mount_multiple_images(self):
        parser = build_parser()
        args = parser.parse_args([
            "mount", "/ev/a.E01", "/ev/b.vmdk", "/ev/c.dd",
        ])
        assert args.image_path == ["/ev/a.E01", "/ev/b.vmdk", "/ev/c.dd"]

    def test_mount_directory_with_scan_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "mount", "/evidence/", "-r", "--pattern", "*.E01",
        ])
        assert args.image_path == ["/evidence/"]
        assert args.recursive is True
        assert args.pattern == "*.E01"

    def test_mount_d_flag_aliases_mount_base(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "/ev/a.E01", "-d", "/mnt/case42"])
        assert args.mount_base == "/mnt/case42"

    def test_mount_force_and_best_effort_alias(self):
        parser = build_parser()
        assert parser.parse_args(["mount", "/ev/a.E01", "--force"]).force is True
        assert parser.parse_args(
            ["mount", "/ev/a.E01", "--best-effort"]).force is True

    def test_mount_with_all_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "mount", "/evidence/disk.vmdk",
            "--mount-base", "/mnt/case001",
            "--case-id", "IR-2026-001",
            "--no-partitions",
            "--force",
            "-v", "--json",
        ])
        assert args.image_path == ["/evidence/disk.vmdk"]
        assert args.mount_base == "/mnt/case001"
        assert args.case_id == "IR-2026-001"
        assert args.no_partitions is True
        assert args.force is True
        assert args.verbose is True
        assert args.json is True

    def test_mount_with_json_input(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "--json-input", "request.json"])
        assert args.json_input == "request.json"

    def test_mount_with_stdin_json(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "--json-input", "-"])
        assert args.json_input == "-"

    def test_unmount_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["unmount", "EV_abc123"])
        assert args.command == "unmount"
        assert args.mount_point == "EV_abc123"

    def test_unmount_all(self):
        parser = build_parser()
        args = parser.parse_args(["unmount", "--all"])
        assert args.command == "unmount"
        assert args.all is True

    def test_list_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"
        assert args.mount_base is None  # default: list everything

    def test_list_with_json(self):
        parser = build_parser()
        args = parser.parse_args(["list", "--json"])
        assert args.json is True

    def test_list_with_base_dir(self):
        parser = build_parser()
        args = parser.parse_args(["list", "-d", "/mnt/case42"])
        assert args.mount_base == "/mnt/case42"

    def test_clean_with_d_flag(self):
        parser = build_parser()
        args = parser.parse_args(["clean", "-d", "/mnt/case42"])
        assert args.command == "clean"
        assert args.mount_base == "/mnt/case42"

    def test_clean_default_base(self):
        parser = build_parser()
        args = parser.parse_args(["clean"])
        assert args.mount_base == "/mnt/mountir"

    def test_check_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert args.command == "check"

    def test_no_command(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestVersion:
    """Test version output."""

    def test_version_string(self):
        assert MOUNTIR_VERSION == "1.0.0"

    def test_version_flag(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


class TestApplyJsonInput:
    """Test _apply_json_input() helper."""

    def test_json_from_file(self, tmp_path):
        """Parse JSON from a file."""
        json_file = tmp_path / "request.json"
        json_file.write_text(json.dumps({
            "image_path": "/evidence/disk.E01",
            "case_id": "IR-2026-001",
            "mount_base": "/mnt/custom",
            "mount_options": {"no_partitions": True},
        }))

        args = Namespace(json_input=str(json_file))
        _apply_json_input(args)

        assert args.image_path == "/evidence/disk.E01"
        assert args.case_id == "IR-2026-001"
        assert args.mount_base == "/mnt/custom"
        assert args.no_partitions is True

    def test_json_from_stdin(self):
        """Parse JSON from stdin."""
        json_data = json.dumps({
            "image_path": "/evidence/disk.vmdk",
            "case_id": "CASE-002",
        })

        args = Namespace(json_input="-")
        with patch("sys.stdin", io.StringIO(json_data)):
            _apply_json_input(args)

        assert args.image_path == "/evidence/disk.vmdk"
        assert args.case_id == "CASE-002"

    def test_json_minimal(self, tmp_path):
        """JSON with only required fields."""
        json_file = tmp_path / "minimal.json"
        json_file.write_text(json.dumps({
            "image_path": "/evidence/disk.dd",
        }))

        args = Namespace(json_input=str(json_file))
        _apply_json_input(args)

        assert args.image_path == "/evidence/disk.dd"
