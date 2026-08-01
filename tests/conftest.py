"""Shared pytest fixtures for MountIR tests."""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def reset_logger():
    """Reset MountIR logger handlers between tests."""
    logger = logging.getLogger("MountIR")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    yield
    logger.handlers.clear()


@pytest.fixture
def tmp_state_file(tmp_path):
    """Provide a temporary state file path."""
    return tmp_path / "test_state.json"


@pytest.fixture
def tmp_state_file_with_data(tmp_state_file):
    """Provide a state file pre-populated with sample data."""
    data = {
        "version": "1",
        "mounted_images": [
            {
                "mount_id": "EV_abc123",
                "image_path": "/evidence/disk.E01",
                "image_type": "e01",
                "case_id": "IR-2026-001",
                "mount_base": "/mnt/mountir",
                "container_mount": "/mnt/mountir/EV_abc123/container",
                "block_device": "",
                "loop_device": "",
                "secondary_loop": "/dev/loop1",
                "raw_image_path": "/mnt/mountir/EV_abc123/container/ewf1",
                "partitions": [
                    {
                        "device": "/dev/loop1p1",
                        "number": 1,
                        "filesystem": "ntfs",
                        "mount_point": "/mnt/mountir/EV_abc123/partitions/p1_ntfs",
                        "label": "Windows",
                        "size_bytes": 53687091200,
                        "mounted": True,
                    }
                ],
                "lvm_vg_names": [],
                "mounted_at": "2026-03-09T10:00:00",
                "handler_class": "EwfHandler",
            }
        ],
    }
    tmp_state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return tmp_state_file


@pytest.fixture
def fake_image_files(tmp_path):
    """Create empty files with various disk image extensions."""
    extensions = [
        ".e01", ".E01", ".l01", ".vmdk", ".vhd", ".vhdx",
        ".dd", ".raw", ".img", ".bin", ".001",
        ".iso", ".aff", ".qcow2", ".qcow",
        ".E02", ".E99", ".EAA",  # E01 segments
        ".txt", ".zip", ".unknown",  # non-image files
    ]
    files = {}
    for ext in extensions:
        f = tmp_path / f"test_image{ext}"
        f.write_bytes(b"\x00" * 512)
        files[ext] = f
    return files


@pytest.fixture
def mock_subprocess_run():
    """Patch subprocess.run with a configurable mock."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        yield mock_run


@pytest.fixture
def mock_which():
    """Patch shutil.which to control tool availability."""
    with patch("shutil.which") as mock:
        mock.return_value = "/usr/bin/tool"  # default: tool exists
        yield mock
