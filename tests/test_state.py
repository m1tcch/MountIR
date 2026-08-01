"""Tests for state.py - mount state persistence."""

import json
from pathlib import Path

import pytest

from state import StateManager, MountState, MountedImage, MountedPartition


def _make_image(mount_id="EV_test01", image_path="/evidence/test.dd",
                image_type="raw", case_id="TEST-001") -> MountedImage:
    """Create a MountedImage for testing."""
    return MountedImage(
        mount_id=mount_id,
        image_path=image_path,
        image_type=image_type,
        case_id=case_id,
        mount_base="/mnt/mountir",
        container_mount=f"/mnt/mountir/{mount_id}/container",
        block_device="/dev/loop0",
        loop_device="/dev/loop0",
        mounted_at="2026-03-09T10:00:00",
        handler_class="RawHandler",
        partitions=[
            MountedPartition(
                device="/dev/loop0p1",
                number=1,
                filesystem="ext4",
                mount_point=f"/mnt/mountir/{mount_id}/partitions/p1_ext4",
                label="root",
                size_bytes=67108864,
                mounted=True,
            )
        ],
    )


class TestStateManagerLoadSave:
    """Test JSON state file load/save operations."""

    def test_load_empty_when_no_file(self, tmp_state_file):
        """Returns empty state when file doesn't exist."""
        mgr = StateManager(state_file=tmp_state_file)
        state = mgr.load()
        assert state.mounted_images == []
        assert state.version == "1"

    def test_save_and_load_roundtrip(self, tmp_state_file):
        """Save then load produces identical state."""
        mgr = StateManager(state_file=tmp_state_file)
        image = _make_image()
        state = MountState(mounted_images=[image])
        mgr.save(state)

        loaded = mgr.load()
        assert len(loaded.mounted_images) == 1
        assert loaded.mounted_images[0].mount_id == "EV_test01"
        assert loaded.mounted_images[0].image_path == "/evidence/test.dd"
        assert loaded.mounted_images[0].image_type == "raw"
        assert loaded.mounted_images[0].case_id == "TEST-001"

    def test_partition_roundtrip(self, tmp_state_file):
        """Partitions survive serialization."""
        mgr = StateManager(state_file=tmp_state_file)
        image = _make_image()
        mgr.save(MountState(mounted_images=[image]))

        loaded = mgr.load()
        parts = loaded.mounted_images[0].partitions
        assert len(parts) == 1
        assert parts[0].device == "/dev/loop0p1"
        assert parts[0].filesystem == "ext4"
        assert parts[0].label == "root"
        assert parts[0].mounted is True

    def test_corrupt_json_returns_empty(self, tmp_state_file):
        """Corrupt JSON file returns empty state gracefully."""
        tmp_state_file.write_text("not valid json {{{", encoding="utf-8")
        mgr = StateManager(state_file=tmp_state_file)
        state = mgr.load()
        assert state.mounted_images == []

    def test_load_preexisting_data(self, tmp_state_file_with_data):
        """Loads pre-populated state file correctly."""
        mgr = StateManager(state_file=tmp_state_file_with_data)
        state = mgr.load()
        assert len(state.mounted_images) == 1
        assert state.mounted_images[0].mount_id == "EV_abc123"
        assert state.mounted_images[0].image_type == "e01"


class TestStateManagerOperations:
    """Test add/remove/find operations."""

    def test_add_mount(self, tmp_state_file):
        """add_mount appends to state."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_first"))
        mgr.add_mount(_make_image("EV_second"))

        state = mgr.load()
        assert len(state.mounted_images) == 2

    def test_remove_mount(self, tmp_state_file):
        """remove_mount removes by mount_id."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_keep"))
        mgr.add_mount(_make_image("EV_remove"))
        mgr.add_mount(_make_image("EV_also_keep"))

        mgr.remove_mount("EV_remove")
        state = mgr.load()
        assert len(state.mounted_images) == 2
        ids = [img.mount_id for img in state.mounted_images]
        assert "EV_remove" not in ids
        assert "EV_keep" in ids
        assert "EV_also_keep" in ids

    def test_remove_nonexistent_mount(self, tmp_state_file):
        """Removing a nonexistent mount_id is a no-op."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_only"))
        mgr.remove_mount("EV_nonexistent")

        state = mgr.load()
        assert len(state.mounted_images) == 1

    def test_find_by_mount_id(self, tmp_state_file):
        """find_by_mount_id returns correct image."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_target", "/evidence/target.dd"))
        mgr.add_mount(_make_image("EV_other", "/evidence/other.dd"))

        found = mgr.find_by_mount_id("EV_target")
        assert found is not None
        assert found.image_path == "/evidence/target.dd"

    def test_find_by_mount_id_not_found(self, tmp_state_file):
        """find_by_mount_id returns None for missing ID."""
        mgr = StateManager(state_file=tmp_state_file)
        assert mgr.find_by_mount_id("EV_missing") is None

    def test_find_by_path_image_path(self, tmp_state_file):
        """find_by_path matches on image_path."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_one", "/evidence/disk.E01"))

        found = mgr.find_by_path("/evidence/disk.E01")
        assert found is not None
        assert found.mount_id == "EV_one"

    def test_find_by_path_mount_dir(self, tmp_state_file):
        """find_by_path matches on mount directory."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_xyz"))

        found = mgr.find_by_path("/mnt/mountir/EV_xyz")
        assert found is not None
        assert found.mount_id == "EV_xyz"

    def test_find_by_path_not_found(self, tmp_state_file):
        """find_by_path returns None for missing path."""
        mgr = StateManager(state_file=tmp_state_file)
        assert mgr.find_by_path("/nonexistent/path") is None


class TestMultipleImages:
    """Test with multiple mounted images."""

    def test_three_images_lifecycle(self, tmp_state_file):
        """Add 3, list all, remove middle, verify."""
        mgr = StateManager(state_file=tmp_state_file)
        mgr.add_mount(_make_image("EV_aaa"))
        mgr.add_mount(_make_image("EV_bbb"))
        mgr.add_mount(_make_image("EV_ccc"))

        state = mgr.load()
        assert len(state.mounted_images) == 3

        mgr.remove_mount("EV_bbb")
        state = mgr.load()
        assert len(state.mounted_images) == 2
        ids = [img.mount_id for img in state.mounted_images]
        assert ids == ["EV_aaa", "EV_ccc"]
