"""Tests for the correctness/security fixes and the EverReady parity features.

Covers, in order: scratch-copy cleanup on unmount, safe tar extraction,
split-raw via affuse, AFF-in-.001 detection, manual offsets,
BitLocker unlocking, Volume Shadow Copies, and state-file resilience.
"""

import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import mountir
import partition as partition_mod
import utils
from detector import ImageType, detect_image_type
from handlers.base import MountResult
from handlers.split_raw import SplitRawHandler
from partition import (
    PartitionInfo, bitlocker_credential_args, _redacted,
    shadow_copy_count, unlock_bitlocker, expose_shadow_copies,
    expose_partitions, _MOUNT_OPTIONS,
)
from state import StateManager, MountedImage


# ---------------------------------------------------------------------------
# Scratch copies are handed back to the handler on unmount
# ---------------------------------------------------------------------------
class TestScratchCleanupOnUnmount:
    """OVA/XVA/DMG/split-raw stash a full-size copy; unmount must delete it."""

    def _image(self, raw_image_path):
        return MountedImage(
            mount_id="EV_s", image_path="/ev/vm.ova", image_type="ova",
            mount_base="/mnt/mountir",
            container_mount="/mnt/mountir/EV_s/container",
            block_device="/dev/nbd0",
            raw_image_path=raw_image_path,
            partitions=[],
        )

    def test_raw_image_path_reaches_the_handler(self, tmp_path):
        scratch = tmp_path / "mountir_ova_xyz"
        scratch.mkdir()
        handler = MagicMock()
        handler.unmount.return_value = True
        state_mgr = MagicMock()

        with patch("mountir.get_handler", return_value=handler), \
             patch("mountir.cleanup_mount_dir"):
            mountir._unmount_single(self._image(str(scratch)), state_mgr)

        passed = handler.unmount.call_args[0][0]
        assert passed.raw_image_path == scratch, \
            "handler cannot delete the scratch copy it was never given"

    def test_absent_raw_image_path_stays_none(self, tmp_path):
        handler = MagicMock()
        handler.unmount.return_value = True
        with patch("mountir.get_handler", return_value=handler), \
             patch("mountir.cleanup_mount_dir"):
            mountir._unmount_single(self._image(""), MagicMock())
        assert handler.unmount.call_args[0][0].raw_image_path is None


# ---------------------------------------------------------------------------
# Tar extraction
# ---------------------------------------------------------------------------
def _tar_with(names, tmp_path):
    """Build a tarball containing one empty member per name in *names*.

    A name may instead be a ``(name, linkname)`` pair, which is added as a
    symlink member.
    """
    tar_path = tmp_path / "archive.tar"
    with tarfile.open(tar_path, "w") as tf:
        for entry in names:
            if isinstance(entry, tuple):
                name, linkname = entry
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                tf.addfile(info)
                continue
            info = tarfile.TarInfo(entry)
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
    return tar_path


class TestSafeExtractall:
    """OVA/XVA archives are untrusted input extracted by a root process."""

    def test_normal_members_extract(self, tmp_path):
        tar_path = _tar_with(["disk.vmdk", "vm.ovf"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            utils.safe_extractall(tf, dest)
        assert (dest / "disk.vmdk").exists()

    def test_parent_traversal_is_refused(self, tmp_path):
        tar_path = _tar_with(["../escaped.vmdk"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            with pytest.raises(Exception):
                utils.safe_extractall(tf, dest)
        assert not (tmp_path / "escaped.vmdk").exists()

    # Interpreters without the `filter` kwarg (pre-3.12, and 3.10/3.11 before
    # the backport) fall through to the manual check, so it needs its own
    # coverage -- neither CI interpreter reaches it otherwise.
    @staticmethod
    def _legacy(tf):
        """Wrap *tf* so extractall rejects `filter`, as an old stdlib does."""
        class LegacyTarFile:
            def __getattr__(self, name):
                return getattr(tf, name)

            def extractall(self, path=".", members=None, **kwargs):
                if "filter" in kwargs:
                    raise TypeError(
                        "extractall() got an unexpected keyword argument 'filter'")
                return tf.extractall(path, members)
        return LegacyTarFile()

    def test_legacy_interpreter_still_extracts(self, tmp_path):
        tar_path = _tar_with(["disk.vmdk"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            utils.safe_extractall(self._legacy(tf), dest)
        assert (dest / "disk.vmdk").exists()

    def test_legacy_interpreter_refuses_traversal(self, tmp_path):
        tar_path = _tar_with(["../escaped.vmdk"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            with pytest.raises(ValueError, match="unsafe path"):
                utils.safe_extractall(self._legacy(tf), dest)
        assert not (tmp_path / "escaped.vmdk").exists()

    def test_legacy_interpreter_refuses_absolute_paths(self, tmp_path):
        tar_path = _tar_with(["/etc/cron.d/pwn"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            with pytest.raises(ValueError, match="unsafe path"):
                utils.safe_extractall(self._legacy(tf), dest)

    def test_legacy_interpreter_refuses_an_escaping_symlink(self, tmp_path):
        """A link out of the tree lets a later member be written through it."""
        tar_path = _tar_with([("escape", "/etc"), "escape/cron.d/pwn"], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            with pytest.raises(ValueError, match="unsafe link"):
                utils.safe_extractall(self._legacy(tf), dest)

    def test_legacy_interpreter_refuses_a_relative_escaping_symlink(self, tmp_path):
        tar_path = _tar_with([("escape", "../../etc")], tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            with pytest.raises(ValueError, match="unsafe link"):
                utils.safe_extractall(self._legacy(tf), dest)

    def test_legacy_interpreter_allows_an_internal_symlink(self, tmp_path):
        """Source tarballs legitimately contain links within the tree."""
        tar_path = _tar_with(["lib/real.so.1", ("lib/real.so", "real.so.1")],
                             tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(tar_path) as tf:
            utils.safe_extractall(self._legacy(tf), dest)
        assert (dest / "lib" / "real.so.1").exists()


class TestScratchDirHelpers:
    def test_scratch_dir_honours_mountir_tmpdir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MOUNTIR_TMPDIR", str(tmp_path / "big-disk"))
        scratch = utils.make_scratch_dir("dmg")
        try:
            assert scratch.parent == tmp_path / "big-disk"
            assert utils.is_scratch_dir(scratch)
        finally:
            scratch.rmdir()

    def test_unrelated_dir_is_not_scratch(self, tmp_path):
        assert not utils.is_scratch_dir(tmp_path)


class TestCleanupMountDir:
    """A still-mounted evidence tree must not be walked."""

    def test_does_not_descend_into_a_mountpoint(self, tmp_path):
        mounted = tmp_path / "partitions" / "p1_ntfs"
        mounted.mkdir(parents=True)
        (mounted / "Windows").mkdir()

        with patch("utils.os.path.ismount", lambda p: str(p) == str(mounted)):
            utils.cleanup_mount_dir(tmp_path)

        assert (mounted / "Windows").is_dir(), "walked into a live mount"
        assert tmp_path.is_dir()  # not removed: still non-empty

    def test_removes_an_empty_tree(self, tmp_path):
        target = tmp_path / "EV_x"
        (target / "partitions" / "p1").mkdir(parents=True)
        with patch("utils.os.path.ismount", lambda p: False):
            utils.cleanup_mount_dir(target)
        assert not target.exists()


# ---------------------------------------------------------------------------
# Split raw: affuse instead of a full-size copy
# ---------------------------------------------------------------------------
class TestSplitRawViaAffuse:
    def _segments(self, tmp_path, count=3):
        for i in range(1, count + 1):
            (tmp_path / f"evidence.{i:03d}").write_bytes(b"\x00" * 16)
        return tmp_path / "evidence.001"

    def test_affuse_is_preferred_over_copying(self, tmp_path):
        image = self._segments(tmp_path)
        container = tmp_path / "container"
        container.mkdir()

        def fake_mount(cmd, access_opts, **kwargs):
            (container / "evidence.001.raw").write_bytes(b"")
            return MagicMock(returncode=0)

        with patch("handlers.split_raw.tool_exists", return_value=True), \
             patch("handlers.split_raw.run_fuse_mount", side_effect=fake_mount), \
             patch("handlers.split_raw.make_scratch_dir") as scratch:
            result = SplitRawHandler().mount(image, container)

        assert result.success
        assert result.raw_image_path == container / "evidence.001.raw"
        scratch.assert_not_called()

    def test_falls_back_to_concatenation_without_affuse(self, tmp_path):
        image = self._segments(tmp_path, count=2)
        container = tmp_path / "container"
        container.mkdir()
        scratch = tmp_path / "mountir_split_x"
        scratch.mkdir()

        with patch("handlers.split_raw.tool_exists", return_value=False), \
             patch("handlers.split_raw.make_scratch_dir", return_value=scratch), \
             patch("handlers.raw.run_command") as run:
            run.return_value = MagicMock(returncode=0, stdout="/dev/loop9\n")
            result = SplitRawHandler().mount(image, container)

        assert result.success and result.loop_device == "/dev/loop9"
        combined = scratch / "evidence.raw"
        assert combined.stat().st_size == 32  # both segments concatenated
        assert result.raw_image_path == combined

    def test_affuse_mount_is_released_without_touching_scratch(self, tmp_path):
        container = tmp_path / "container"
        container.mkdir()
        result = MountResult(success=True, mount_point=container,
                             raw_image_path=container / "evidence.001.raw")
        with patch("handlers.split_raw.fuse_unmount", return_value=True) as fu:
            assert SplitRawHandler().unmount(result) is True
        fu.assert_called_once_with(container)


# ---------------------------------------------------------------------------
# .001 is ambiguous: AFF container or split raw?
# ---------------------------------------------------------------------------
class TestAffWithDotOhOneExtension:
    def test_aff_magic_wins_over_split_raw(self, tmp_path):
        image = tmp_path / "evidence.001"
        image.write_bytes(b"AFF10\r\n\x00" + b"\x00" * 64)
        (tmp_path / "evidence.002").write_bytes(b"\x00" * 64)
        assert detect_image_type(image) == ImageType.AFF

    def test_plain_split_raw_is_still_split_raw(self, tmp_path):
        image = tmp_path / "evidence.001"
        image.write_bytes(b"\x00" * 64)
        (tmp_path / "evidence.002").write_bytes(b"\x00" * 64)
        assert detect_image_type(image) == ImageType.SPLIT_RAW

    def test_lone_segment_is_raw(self, tmp_path):
        image = tmp_path / "evidence.001"
        image.write_bytes(b"\x00" * 64)
        assert detect_image_type(image) == ImageType.RAW


# ---------------------------------------------------------------------------
# Manual offset (EverReady's -o)
# ---------------------------------------------------------------------------
class TestByteOffsetParsing:
    @pytest.mark.parametrize("text,expected", [
        ("1048576", 1048576),
        ("2048s", 1048576),
        ("63s", 32256),
        ("1M", 1048576),
        ("2K", 2048),
        ("1G", 1024 ** 3),
    ])
    def test_accepted_forms(self, text, expected):
        assert mountir._byte_offset(text) == expected

    @pytest.mark.parametrize("text", ["", "abc", "-1", "2048 sectors"])
    def test_rejected_forms(self, text):
        with pytest.raises(Exception):
            mountir._byte_offset(text)


class TestExposeAtOffset:
    def test_offset_skips_the_partition_table(self, tmp_path):
        image = tmp_path / "disk.dd"
        image.write_bytes(b"\x00" * 4096)
        with patch("partition._attach_offset_loop", return_value="/dev/loop7") as att, \
             patch("partition._enrich_with_blkid"), \
             patch("partition.read_partition_table") as read_table:
            parts, created = expose_partitions(image, offset=1024)
        read_table.assert_not_called()
        att.assert_called_once_with(str(image), 1024, 4096 - 1024)
        assert created == ["/dev/loop7"]
        assert parts[0].device == "/dev/loop7" and parts[0].start_bytes == 1024

    def test_offset_past_end_of_media_is_refused(self, tmp_path):
        image = tmp_path / "disk.dd"
        image.write_bytes(b"\x00" * 512)
        with patch("partition._attach_offset_loop") as att:
            parts, created = expose_partitions(image, offset=99999)
        assert parts == [] and created == []
        att.assert_not_called()


# ---------------------------------------------------------------------------
# BitLocker (ermount.sh -b parity)
# ---------------------------------------------------------------------------
def _bitlocker_part(device="/dev/loop3"):
    return PartitionInfo(device=device, number=2, filesystem="bitlocker")


class TestBitlockerCredentials:
    def test_flags_map_to_bdemount_options(self):
        assert bitlocker_credential_args(password="hunter2") == ["-p", "hunter2"]
        assert bitlocker_credential_args(recovery_key="1-2-3") == ["-r", "1-2-3"]
        assert bitlocker_credential_args(startup_key="/k.BEK") == ["-s", "/k.BEK"]

    def test_nothing_supplied_is_empty(self):
        assert bitlocker_credential_args() == []

    def test_secrets_are_redacted_for_logging(self):
        cmd = ["bdemount", "-p", "hunter2", "/dev/loop3", "/mnt/bde"]
        assert _redacted(cmd) == [
            "bdemount", "-p", "<redacted>", "/dev/loop3", "/mnt/bde"]

    def test_startup_key_path_is_not_redacted(self):
        cmd = ["bdemount", "-s", "/keys/x.BEK", "/dev/loop3", "/mnt/bde"]
        assert "/keys/x.BEK" in _redacted(cmd)

    def test_env_var_supplies_the_password(self, monkeypatch):
        monkeypatch.setenv("MOUNTIR_BDE_PASSWORD", "from-env")
        args = MagicMock(bde_password="", bde_recovery_key="",
                         bde_startup_key="", bde_key="")
        assert mountir._bitlocker_credentials(args) == ["-p", "from-env"]


class TestUnlockBitlocker:
    def test_no_bitlocker_volumes_is_a_noop(self, tmp_path):
        parts = [PartitionInfo(device="/dev/loop1", number=1, filesystem="ntfs")]
        result = unlock_bitlocker(parts, tmp_path, ["-p", "x"])
        assert result.partitions == [] and result.fuse_mounts == []

    def test_missing_credential_marks_the_volume_locked(self, tmp_path):
        part = _bitlocker_part()
        result = unlock_bitlocker([part], tmp_path, [])
        assert result.partitions == []
        assert "locked" in part.skip_reason

    def test_missing_bdemount_is_explained(self, tmp_path):
        part = _bitlocker_part()
        with patch("partition.tool_exists", return_value=False):
            result = unlock_bitlocker([part], tmp_path, ["-p", "x"])
        assert result.partitions == []
        assert "bdemount" in part.skip_reason

    def test_unlocked_volume_becomes_a_partition(self, tmp_path):
        part = _bitlocker_part()

        def fake_run(cmd, **kwargs):
            target = Path(cmd[-1])
            (target / "bde1").write_bytes(b"")
            return MagicMock(returncode=0)

        with patch("partition.tool_exists", return_value=True), \
             patch("partition.run_command", side_effect=fake_run) as run, \
             patch("partition._attach_offset_loop", return_value="/dev/loop8"), \
             patch("partition._enrich_with_blkid"):
            result = unlock_bitlocker([part], tmp_path, ["-p", "hunter2"])

        assert [p.device for p in result.partitions] == ["/dev/loop8"]
        assert result.loops == ["/dev/loop8"]
        assert result.fuse_mounts == [str(tmp_path / "bde_p2")]
        assert "unlocked" in part.skip_reason
        # The password must not reach the log.
        assert run.call_args.kwargs["log_cmd"].count("hunter2") == 0

    def test_wrong_credential_is_reported_not_raised(self, tmp_path):
        part = _bitlocker_part()
        with patch("partition.tool_exists", return_value=True), \
             patch("partition.run_command", side_effect=RuntimeError("boom")), \
             patch("partition._attach_offset_loop") as att:
            result = unlock_bitlocker([part], tmp_path, ["-p", "wrong"])
        assert result.partitions == []
        assert "credential" in part.skip_reason
        att.assert_not_called()


# ---------------------------------------------------------------------------
# Volume Shadow Copies (ermount.sh VSS parity)
# ---------------------------------------------------------------------------
_VSHADOWINFO = """vshadowinfo 20240113

Volume Shadow Snapshot information:
\tNumber of stores:\t3
"""


class TestShadowCopyCount:
    def test_parses_store_count(self):
        with patch("partition.tool_exists", return_value=True), \
             patch("partition.run_command",
                   return_value=MagicMock(returncode=0, stdout=_VSHADOWINFO)):
            assert shadow_copy_count("/dev/loop3") == 3

    def test_no_stores_line_means_zero(self):
        with patch("partition.tool_exists", return_value=True), \
             patch("partition.run_command",
                   return_value=MagicMock(returncode=1, stdout="")):
            assert shadow_copy_count("/dev/loop3") == 0

    def test_missing_tool_means_zero(self):
        with patch("partition.tool_exists", return_value=False):
            assert shadow_copy_count("/dev/loop3") == 0


class TestExposeShadowCopies:
    def test_each_store_becomes_a_volume(self, tmp_path):
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="ntfs",
                             label="Windows")

        def fake_mount(cmd, access_opts, **kwargs):
            target = Path(cmd[-1])
            for name in ("vss1", "vss2"):
                (target / name).write_bytes(b"")
            return MagicMock(returncode=0)

        loops = iter(["/dev/loop10", "/dev/loop11"])
        with patch("partition.shadow_copy_count", return_value=2), \
             patch("partition.tool_exists", return_value=True), \
             patch("partition.run_fuse_mount", side_effect=fake_mount), \
             patch("partition._attach_offset_loop", side_effect=lambda *a: next(loops)), \
             patch("partition._enrich_with_blkid"):
            result = expose_shadow_copies(part, tmp_path)

        assert [p.device for p in result.partitions] == ["/dev/loop10", "/dev/loop11"]
        assert all(p.filesystem == "ntfs" for p in result.partitions)
        assert result.fuse_mounts == [str(tmp_path / "vss_p1")]

    def test_volume_without_stores_is_skipped(self, tmp_path):
        part = PartitionInfo(device="/dev/loop3", number=1, filesystem="ntfs")
        with patch("partition.shadow_copy_count", return_value=0), \
             patch("partition.run_fuse_mount") as mount:
            result = expose_shadow_copies(part, tmp_path)
        assert result.partitions == []
        mount.assert_not_called()


# ---------------------------------------------------------------------------
# Forensic mount options
# ---------------------------------------------------------------------------
class TestNtfsForensicOptions:
    def test_ntfs_suppresses_journal_replay(self):
        """er2.sh/ermount.sh both pass norecover; journal replay is a write."""
        assert "norecover" in _MOUNT_OPTIONS["ntfs"]

    def test_ntfs_3g_attempt_carries_it(self):
        attempts = partition_mod._mount_attempts("ntfs")
        ntfs3g = [opts for fstype, opts in attempts if fstype == "ntfs-3g"]
        assert ntfs3g and "norecover" in ntfs3g[0]


# ---------------------------------------------------------------------------
# State-file resilience
# ---------------------------------------------------------------------------
class TestStateVersionSkew:
    def test_unknown_fields_are_ignored(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text(
            '{"version": "1", "mounted_images": [{'
            '"mount_id": "EV_a", "image_path": "/ev/a.dd", "image_type": "raw",'
            '"from_the_future": true, "partitions": ['
            '{"device": "/dev/loop0p1", "number": 1, "unknown_part_field": 1}]}]}',
            encoding="utf-8",
        )
        state = StateManager(state_file).load()
        assert [i.mount_id for i in state.mounted_images] == ["EV_a"]
        assert state.mounted_images[0].partitions[0].device == "/dev/loop0p1"


class TestVerifyMountsExactMatching:
    def _mgr(self, tmp_path, images):
        mgr = StateManager(tmp_path / "state.json")
        mgr._cache = None
        mgr.save(type(mgr.load())(mounted_images=images))
        return mgr

    def test_prefix_of_another_mount_is_not_mistaken_for_live(self, tmp_path):
        live = MountedImage(
            mount_id="EV_ab12", image_path="/ev/b.dd", image_type="raw",
            container_mount="/mnt/mountir/EV_ab12/container", partitions=[])
        gone = MountedImage(
            mount_id="EV_ab1", image_path="/ev/a.dd", image_type="raw",
            container_mount="/mnt/mountir/EV_ab1/container", partitions=[])
        mgr = self._mgr(tmp_path, [live, gone])

        proc = "/dev/loop0 /mnt/mountir/EV_ab12/container fuse.ewf ro 0 0\n"
        with patch("state.Path") as path_cls:
            path_cls.return_value.read_text.return_value = proc
            stale = mgr.verify_mounts()

        assert [i.mount_id for i in stale] == ["EV_ab1"]

    def test_loop_device_number_prefix_is_not_a_match(self, tmp_path):
        img = MountedImage(
            mount_id="EV_c", image_path="/ev/c.dd", image_type="raw",
            container_mount="", block_device="/dev/loop1", partitions=[])
        mgr = self._mgr(tmp_path, [img])

        proc = "/dev/loop12 /mnt/other ext4 ro 0 0\n"
        with patch("state.Path") as path_cls:
            path_cls.return_value.read_text.return_value = proc
            stale = mgr.verify_mounts()

        assert [i.mount_id for i in stale] == ["EV_c"]
