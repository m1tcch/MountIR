"""Tests for the concurrency and download-integrity fixes.

Covers: state-file read-modify-write under a lock, atomic NBD device claiming,
atomic mount-id claiming, and checksum verification of the libewf tarball.
"""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import bootstrap
import utils
from state import StateManager, MountedImage
from utils import claim_mount_dir, generate_mount_id, nbd_attach


def _image(mount_id):
    return MountedImage(mount_id=mount_id, image_path=f"/ev/{mount_id}.dd",
                        image_type="raw", mount_base="/mnt/mountir")


# ---------------------------------------------------------------------------
# State file: concurrent read-modify-write
# ---------------------------------------------------------------------------
class TestStateReadModifyWrite:
    """Two processes adding a mount must not lose each other's entry."""

    def test_concurrent_add_keeps_both_entries(self, tmp_path):
        state_file = tmp_path / "state.json"
        first = StateManager(state_file)
        second = StateManager(state_file)

        # `first` populates its cache from an empty file, as a long-running
        # process would...
        first.load()
        # ...then a second process records its own mount...
        second.add_mount(_image("EV_second"))
        # ...and only afterwards does the first one write.
        first.add_mount(_image("EV_first"))

        on_disk = StateManager(state_file).load()
        assert {i.mount_id for i in on_disk.mounted_images} == \
            {"EV_first", "EV_second"}

    def test_concurrent_remove_does_not_resurrect(self, tmp_path):
        state_file = tmp_path / "state.json"
        writer = StateManager(state_file)
        writer.add_mount(_image("EV_a"))
        writer.add_mount(_image("EV_b"))

        stale_view = StateManager(state_file)
        stale_view.load()                      # caches both entries
        StateManager(state_file).remove_mount("EV_a")
        stale_view.remove_mount("EV_b")        # must not bring EV_a back

        on_disk = StateManager(state_file).load()
        assert [i.mount_id for i in on_disk.mounted_images] == []

    def test_lock_is_a_sidecar_file(self, tmp_path):
        """The lock must not be the state file: rename() would drop it."""
        mgr = StateManager(tmp_path / "mountir_state.json")
        assert mgr.lock_file != mgr.state_file
        assert mgr.lock_file.parent == mgr.state_file.parent

    def test_unwritable_lock_dir_still_saves(self, tmp_path):
        """An unusable lock must not stop an analyst recording a mount."""
        mgr = StateManager(tmp_path / "state.json")
        with patch.object(type(mgr), "lock_file",
                          new=property(lambda self: Path("/nonexistent/x.lock"))):
            mgr.add_mount(_image("EV_x"))
        assert [i.mount_id for i in StateManager(tmp_path / "state.json")
                .load().mounted_images] == ["EV_x"]

    def test_refresh_rereads_from_disk(self, tmp_path):
        state_file = tmp_path / "state.json"
        mgr = StateManager(state_file)
        mgr.load()
        StateManager(state_file).add_mount(_image("EV_new"))

        assert mgr.load().mounted_images == []          # cached view
        assert [i.mount_id for i in mgr.load(refresh=True).mounted_images] \
            == ["EV_new"]


# ---------------------------------------------------------------------------
# NBD: the attach is the claim
# ---------------------------------------------------------------------------
class TestNbdAttach:
    def test_first_free_device_wins(self):
        with patch("utils.ensure_nbd_module", return_value=True), \
             patch("utils.free_nbd_devices",
                   return_value=["/dev/nbd0", "/dev/nbd1"]), \
             patch("utils.nbd_connect", return_value=True) as connect:
            device = nbd_attach(Path("/ev/disk.vmdk"), format_hint="vmdk")
        assert device == "/dev/nbd0"
        assert connect.call_count == 1
        assert connect.call_args.kwargs["format_hint"] == "vmdk"

    def test_device_taken_by_a_racing_process_moves_on(self):
        """qemu-nbd -c fails on a device someone else claimed - try the next."""
        with patch("utils.ensure_nbd_module", return_value=True), \
             patch("utils.free_nbd_devices",
                   return_value=["/dev/nbd0", "/dev/nbd1", "/dev/nbd2"]), \
             patch("utils.nbd_connect", side_effect=[False, False, True]):
            assert nbd_attach(Path("/ev/disk.qcow2")) == "/dev/nbd2"

    def test_all_devices_taken_returns_none(self):
        with patch("utils.ensure_nbd_module", return_value=True), \
             patch("utils.free_nbd_devices", return_value=["/dev/nbd0"]), \
             patch("utils.nbd_connect", return_value=False):
            assert nbd_attach(Path("/ev/disk.vdi")) is None

    def test_no_free_devices_returns_none(self):
        with patch("utils.ensure_nbd_module", return_value=True), \
             patch("utils.free_nbd_devices", return_value=[]), \
             patch("utils.nbd_connect") as connect:
            assert nbd_attach(Path("/ev/disk.vdi")) is None
        connect.assert_not_called()

    def test_module_load_failure_is_reported(self):
        with patch("utils.ensure_nbd_module", return_value=False), \
             patch("utils.nbd_connect") as connect:
            assert nbd_attach(Path("/ev/disk.vdi")) is None
        connect.assert_not_called()

    def test_read_only_is_the_default(self):
        with patch("utils.ensure_nbd_module", return_value=True), \
             patch("utils.free_nbd_devices", return_value=["/dev/nbd0"]), \
             patch("utils.nbd_connect", return_value=True) as connect:
            nbd_attach(Path("/ev/disk.vmdk"))
        assert connect.call_args.kwargs["read_only"] is True


class TestNbdHandlersUseAtomicAttach:
    """Every qemu-nbd handler goes through nbd_attach, not check-then-connect."""

    @pytest.mark.parametrize("module,hint", [
        ("handlers.qcow", "qcow2"),
        ("handlers.vdi", "vdi"),
        ("handlers.vmdk", "vmdk"),
    ])
    def test_handler_attaches_atomically(self, module, hint, tmp_path):
        import contextlib
        import importlib
        mod = importlib.import_module(module)
        handler_cls = next(
            obj for name, obj in vars(mod).items()
            if name.endswith("Handler") and name != "BaseHandler"
        )
        # VMDK prefers qemu-nbd but falls back to vmdkmount, so it needs
        # qemu-nbd to look present; the others go straight to NBD.
        has_tools = (patch(f"{module}.tool_exists", return_value=True)
                     if hasattr(mod, "tool_exists") else contextlib.nullcontext())
        with has_tools, \
             patch(f"{module}.nbd_attach", return_value="/dev/nbd4") as attach:
            result = handler_cls().mount(tmp_path / "d.img", tmp_path)
        assert result.success and result.block_device == "/dev/nbd4"
        assert attach.call_args.kwargs["format_hint"] == hint

    @pytest.mark.parametrize("is_vhdx,hint", [(False, "vpc"), (True, "vhdx")])
    def test_vhd_handler_attaches_atomically(self, is_vhdx, hint, tmp_path):
        from handlers.vhd import VhdHandler
        with patch("handlers.vhd.tool_exists", return_value=True), \
             patch("handlers.vhd.nbd_attach", return_value="/dev/nbd5") as attach:
            result = VhdHandler(is_vhdx=is_vhdx).mount(tmp_path / "d.vhd", tmp_path)
        assert result.success and result.block_device == "/dev/nbd5"
        assert attach.call_args.kwargs["format_hint"] == hint

    def test_attach_failure_is_a_clean_error(self, tmp_path):
        from handlers.qcow import QcowHandler
        with patch("handlers.qcow.nbd_attach", return_value=None):
            result = QcowHandler().mount(tmp_path / "d.qcow2", tmp_path)
        assert result.success is False and "NBD" in result.error


# ---------------------------------------------------------------------------
# Mount ids: creating the directory is the claim
# ---------------------------------------------------------------------------
class TestClaimMountDir:
    def test_claims_a_fresh_directory(self, tmp_path):
        mount_id, path = claim_mount_dir(tmp_path, "IR-1", "disk")
        assert path == tmp_path / mount_id
        assert path.is_dir()
        assert mount_id.startswith("IR-1_disk_")

    def test_repeated_claims_are_distinct(self, tmp_path):
        ids = {claim_mount_dir(tmp_path, "IR-1", "disk")[0] for _ in range(20)}
        assert len(ids) == 20

    def test_collision_retries_with_a_new_id(self, tmp_path):
        """A taken id must be skipped, not reused - mkdir is the arbiter."""
        calls = []
        real = utils.generate_mount_id

        def fake(case_id=None, image_name="", random_len=6):
            calls.append(random_len)
            # First candidate collides with a directory that already exists.
            return "taken" if len(calls) == 1 else real(case_id, image_name,
                                                        random_len)

        (tmp_path / "taken").mkdir()
        with patch("utils.generate_mount_id", side_effect=fake):
            mount_id, path = claim_mount_dir(tmp_path, "", "disk")

        assert mount_id != "taken" and path.is_dir()
        assert len(calls) == 2

    def test_suffix_widens_as_attempts_fail(self, tmp_path):
        """Retrying at the same odds could spin; the search must converge."""
        lengths = []

        def fake(case_id=None, image_name="", random_len=6):
            lengths.append(random_len)
            return "always-taken"

        (tmp_path / "always-taken").mkdir()
        with patch("utils.generate_mount_id", side_effect=fake):
            with pytest.raises(OSError):
                claim_mount_dir(tmp_path, "", "disk")

        assert lengths[0] == 6
        assert lengths[-1] > lengths[0]

    def test_creates_the_mount_base(self, tmp_path):
        base = tmp_path / "does" / "not" / "exist"
        _mount_id, path = claim_mount_dir(base, "", "disk")
        assert path.is_dir()


class TestGenerateMountId:
    def test_random_length_is_configurable(self):
        mid = generate_mount_id(None, "", random_len=12)
        assert mid.startswith("EV_") and len(mid) == len("EV_") + 12


# ---------------------------------------------------------------------------
# libewf tarball integrity
# ---------------------------------------------------------------------------
_PAYLOAD = b"pretend this is libewf-experimental.tar.gz"
_PAYLOAD_SHA = hashlib.sha256(_PAYLOAD).hexdigest()


def _fake_urlopen(payload=_PAYLOAD):
    response = MagicMock()
    response.read.return_value = payload
    response.__enter__ = lambda self: self
    response.__exit__ = lambda self, *exc: False
    return MagicMock(return_value=response)


class TestDownloadChecksum:
    def test_matching_digest_is_written(self, tmp_path):
        dest = tmp_path / "libewf.tar.gz"
        with patch("urllib.request.urlopen", _fake_urlopen()):
            assert bootstrap._download("https://x/y.tar.gz", dest,
                                       sha256=_PAYLOAD_SHA) is True
        assert dest.read_bytes() == _PAYLOAD

    def test_digest_comparison_is_case_insensitive(self, tmp_path):
        dest = tmp_path / "libewf.tar.gz"
        with patch("urllib.request.urlopen", _fake_urlopen()):
            assert bootstrap._download("https://x/y.tar.gz", dest,
                                       sha256=_PAYLOAD_SHA.upper()) is True

    def test_mismatched_digest_is_refused_and_leaves_no_file(self, tmp_path):
        """A tampered or truncated tarball must not be left for the build."""
        dest = tmp_path / "libewf.tar.gz"
        with patch("urllib.request.urlopen", _fake_urlopen(b"tampered")):
            assert bootstrap._download("https://x/y.tar.gz", dest,
                                       sha256=_PAYLOAD_SHA) is False
        assert not dest.exists()

    def test_no_digest_skips_verification(self, tmp_path):
        dest = tmp_path / "other.tar.gz"
        with patch("urllib.request.urlopen", _fake_urlopen()):
            assert bootstrap._download("https://x/y.tar.gz", dest) is True
        assert dest.exists()


class TestLibewfPinnedDigest:
    def test_the_pinned_version_has_a_digest(self):
        assert bootstrap.libewf_expected_sha256(bootstrap.LIBEWF_VERSION)

    def test_digest_is_a_sha256_hex_string(self):
        digest = bootstrap.libewf_expected_sha256(bootstrap.LIBEWF_VERSION)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_unknown_version_has_no_digest(self):
        assert bootstrap.libewf_expected_sha256("19991231") == ""

    def test_env_var_pins_an_unknown_version(self, monkeypatch):
        monkeypatch.setenv("MOUNTIR_LIBEWF_SHA256", "a" * 64)
        assert bootstrap.libewf_expected_sha256("19991231") == "a" * 64

    def test_env_var_overrides_the_table(self, monkeypatch):
        monkeypatch.setenv("MOUNTIR_LIBEWF_SHA256", "b" * 64)
        assert bootstrap.libewf_expected_sha256(bootstrap.LIBEWF_VERSION) \
            == "b" * 64
