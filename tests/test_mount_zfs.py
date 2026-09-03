"""Tests for the ZFS wiring in mountir.py (_import_zfs_pools + unmount order)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import mountir
from partition import PartitionInfo
from state import MountedImage, MountedPartition
from zfs import PoolCandidate


def _zfs_member(dev):
    return PartitionInfo(device=dev, number=1, filesystem="zfs_member")


class TestImportZfsPools:
    """_import_zfs_pools detects zfs_member vdevs and imports read-only."""

    def test_no_zfs_members_is_noop(self, tmp_path):
        parts = [PartitionInfo(device="/dev/loop3", number=1, filesystem="ext4")]
        with patch("mountir.zfs") as z:
            pools, infos = mountir._import_zfs_pools(parts, tmp_path)
        assert pools == [] and infos == []
        z.scan_pools.assert_not_called()

    def test_members_present_but_zfs_missing_warns(self, tmp_path):
        parts = [_zfs_member("/dev/loop3")]
        with patch("mountir.zfs") as z:
            z.zfs_available.return_value = False
            pools, infos = mountir._import_zfs_pools(parts, tmp_path)
        assert pools == [] and infos == []
        z.scan_pools.assert_not_called()

    def test_import_and_dataset_mapping(self, tmp_path):
        parts = [_zfs_member("/dev/loop3"), _zfs_member("/dev/loop4")]
        with patch("mountir.zfs") as z, \
             patch("mountir.ensure_mount_dir") as emd:
            z.zfs_available.return_value = True
            z.scan_pools.return_value = [PoolCandidate("tank", "7", "ONLINE")]
            z.import_pool.return_value = "tank"
            z.mount_datasets.return_value = [
                ("tank", str(tmp_path / "zfs/tank")),
                ("tank/data", str(tmp_path / "zfs/tank/data")),
            ]
            pools, infos = mountir._import_zfs_pools(parts, tmp_path)

        assert pools == ["tank"]
        assert [i.filesystem for i in infos] == ["zfs", "zfs"]
        assert [i.label for i in infos] == ["tank", "tank/data"]
        assert all(i.mounted for i in infos)
        # imported under <image>/zfs/<pool> as the alternate root
        emd.assert_called_with(tmp_path / "zfs" / "tank")
        # both vdevs are offered to the importer
        assert z.import_pool.call_args.args[2] == ["/dev/loop3", "/dev/loop4"]

    def test_failed_import_yields_no_pool(self, tmp_path):
        parts = [_zfs_member("/dev/loop3")]
        with patch("mountir.zfs") as z, patch("mountir.ensure_mount_dir"):
            z.zfs_available.return_value = True
            z.scan_pools.return_value = [PoolCandidate("tank", "7", "ONLINE")]
            z.import_pool.return_value = ""  # import failed
            pools, infos = mountir._import_zfs_pools(parts, tmp_path)
        assert pools == [] and infos == []
        z.mount_datasets.assert_not_called()


class TestUnmountExportsPoolsFirst:
    """_unmount_single must export pools before detaching their backing loops."""

    def _image(self):
        return MountedImage(
            mount_id="EV_z", image_path="/ev/pool.E01", image_type="e01",
            mount_base="/mnt/mountir", container_mount="/mnt/mountir/EV_z/container",
            partition_loops=[],
            zfs_pools=["tank"],
            partitions=[
                MountedPartition(device="tank", number=300, filesystem="zfs",
                                 mount_point="/mnt/mountir/EV_z/zfs/tank", mounted=True),
                MountedPartition(device="/dev/loop3", number=1, filesystem="ext4",
                                 mount_point="/mnt/mountir/EV_z/partitions/p1_ext4",
                                 mounted=True),
            ],
        )

    def test_pool_exported_and_zfs_dataset_not_umounted(self):
        img = self._image()
        handler = MagicMock()
        handler.unmount.return_value = True
        with patch("mountir.zfs") as z, \
             patch("mountir._umount_path", return_value=True) as um, \
             patch("mountir.get_handler", return_value=handler), \
             patch("mountir.cleanup_mount_dir"), \
             patch("mountir.run_command"):
            z.export_pool.return_value = True
            state_mgr = MagicMock()
            mountir._unmount_single(img, state_mgr)

        z.export_pool.assert_called_once_with("tank")
        umounted = [c.args[0] for c in um.call_args_list]
        # the ext4 partition is umounted; the zfs dataset is left to the export
        assert "/mnt/mountir/EV_z/partitions/p1_ext4" in umounted
        assert "/mnt/mountir/EV_z/zfs/tank" not in umounted
        state_mgr.remove_mount.assert_called_once_with("EV_z")
