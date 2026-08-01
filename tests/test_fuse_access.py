"""Tests for FUSE mount accessibility (``allow_other``).

A FUSE mount is visible only to the UID that made it unless ``allow_other`` is
set. MountIR mounts as root, so without it the analyst's own shell gets EACCES
on the evidence tree -- and confusingly only on the FUSE-backed partitions, since
the kernel mounts (vfat, ext4) alongside them stay readable.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from partition import _FUSE_FALLBACK_MOUNTERS, _FUSE_MOUNTERS, _fuse_mount_commands
from utils import FUSE_ACCESS_OPTS, FUSE_ACCESS_OPTS_LIBYAL, run_fuse_mount


class TestFuseMounterOptions:
    """Every FUSE driver asks for allow_other, and can still mount without it."""

    @staticmethod
    def _entries(table):
        return [(fs, binary, " ".join(args))
                for fs, mounters in table.items() for binary, args in mounters]

    @pytest.mark.parametrize("table", [_FUSE_MOUNTERS, _FUSE_FALLBACK_MOUNTERS])
    def test_first_attempt_for_each_driver_requests_allow_other(self, table):
        for fs, mounters in table.items():
            first_by_binary = {}
            for binary, args in mounters:
                first_by_binary.setdefault(binary, " ".join(args))
            for binary, args in first_by_binary.items():
                assert "allow_other" in args, f"{fs}/{binary} mounts root-only"

    @pytest.mark.parametrize("table", [_FUSE_MOUNTERS, _FUSE_FALLBACK_MOUNTERS])
    def test_every_driver_has_a_plain_ro_fallback(self, table):
        """A build that rejects allow_other must still produce a mount."""
        for fs, mounters in table.items():
            for binary in {b for b, _ in mounters}:
                variants = [" ".join(a) for b, a in mounters if b == binary]
                assert any("allow_other" not in v for v in variants), (
                    f"{fs}/{binary} has no fallback without allow_other")

    def test_all_mounts_stay_read_only(self):
        for _fs, _binary, args in (self._entries(_FUSE_MOUNTERS) +
                                   self._entries(_FUSE_FALLBACK_MOUNTERS)):
            assert "ro" in args.split()[-1].split(",")

    def test_ufs_command_puts_allow_other_first(self):
        mounters = _FUSE_FALLBACK_MOUNTERS["ufs"]
        assert mounters[0] == ("fuse-ufs", ["-o", "ro,allow_other"])

    def test_generated_command_keeps_device_and_mountpoint_last(self):
        cmds = _fuse_mount_commands("apfs", "/dev/loop3", Path("/mnt/x"))
        assert "allow_other" in " ".join(cmds[0])
        assert cmds[0][-2:] == ["/dev/loop3", str(Path("/mnt/x"))]


class TestRunFuseMount:
    """allow_other is an accessibility nicety; never trade a mount for it."""

    CMD = ["ewfmount", "/ev/a.E01", "/mnt/x"]

    def test_option_is_inserted_after_the_binary(self):
        with patch("utils.run_command") as run:
            run_fuse_mount(self.CMD, FUSE_ACCESS_OPTS_LIBYAL)
        assert run.call_args[0][0] == [
            "ewfmount", "-X", "allow_other", "/ev/a.E01", "/mnt/x"]

    def test_standard_option_form(self):
        with patch("utils.run_command") as run:
            run_fuse_mount(["affuse", "/ev/a.aff", "/mnt/x"], FUSE_ACCESS_OPTS)
        assert run.call_args[0][0] == [
            "affuse", "-o", "allow_other", "/ev/a.aff", "/mnt/x"]

    def test_rejected_option_retries_without_it(self):
        attempts = []

        def fake(cmd, capture=False):
            attempts.append(cmd)
            if "allow_other" in cmd:
                raise RuntimeError("fuse: unknown option `allow_other'")
            return "ok"

        with patch("utils.run_command", fake):
            assert run_fuse_mount(self.CMD, FUSE_ACCESS_OPTS_LIBYAL) == "ok"
        assert len(attempts) == 2
        assert attempts[1] == self.CMD

    def test_a_genuine_mount_failure_still_raises(self):
        with patch("utils.run_command", side_effect=RuntimeError("no such file")):
            with pytest.raises(RuntimeError, match="no such file"):
                run_fuse_mount(self.CMD, FUSE_ACCESS_OPTS_LIBYAL)


class TestHandlersRequestAccess:
    """The container mount holds the raw image; it needs to be readable too."""

    @pytest.mark.parametrize("module,tool,opts", [
        ("handlers.ewf", "ewfmount", FUSE_ACCESS_OPTS_LIBYAL),
        ("handlers.aff", "affuse", FUSE_ACCESS_OPTS),
        ("handlers.vmdk", "vmdkmount", FUSE_ACCESS_OPTS_LIBYAL),
        ("handlers.vhd", "vhdimount", FUSE_ACCESS_OPTS_LIBYAL),
    ])
    def test_handler_imports_the_access_helper(self, module, tool, opts):
        import importlib
        mod = importlib.import_module(module)
        assert hasattr(mod, "run_fuse_mount"), (
            f"{tool} handler still mounts without allow_other")
