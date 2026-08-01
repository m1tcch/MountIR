"""Tests for the opt-in fuse-ufs (UFS driver) install.

UFS is the one filesystem in the forensic set whose kernel driver is genuinely
optional -- Ubuntu ships it in linux-modules-extra, and the WSL2 kernel omits it
with no module to load. fuse-ufs covers those hosts, but it is a Rust crate, so
the install stays opt-in and must never pull in a toolchain unasked.
"""

from unittest.mock import MagicMock, patch

import bootstrap
from mountir import build_parser


class TestFindCargo:
    """sudo hides the invoking user's rustup toolchain behind secure_path."""

    def test_path_lookup_wins(self):
        with patch("shutil.which", return_value="/usr/bin/cargo"):
            assert bootstrap.find_cargo() == "/usr/bin/cargo"

    def test_falls_back_to_sudo_users_rustup_home(self):
        found = "/home/analyst/.cargo/bin/cargo"
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {"SUDO_USER": "analyst"}, clear=False), \
             patch("pathlib.Path.is_file", return_value=True), \
             patch("os.access", return_value=True):
            assert bootstrap.find_cargo() == found

    def test_none_when_no_toolchain_anywhere(self):
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False):
            assert bootstrap.find_cargo() is None


class TestBuildFuseUfs:
    """Best-effort install: never raises, never installs a toolchain unasked."""

    def test_already_installed_is_a_no_op(self):
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap._run") as run:
            assert bootstrap.build_fuse_ufs() is True
        run.assert_not_called()

    def test_missing_cargo_reports_instead_of_installing_rust(self):
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.find_cargo", return_value=None), \
             patch("bootstrap._run") as run:
            assert bootstrap.build_fuse_ufs() is False
        run.assert_not_called()

    def test_without_root_it_declines(self):
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=None), \
             patch("bootstrap._run") as run:
            assert bootstrap.build_fuse_ufs() is False
        run.assert_not_called()

    @staticmethod
    def _install(run, cargo=(1, 85), force=False):
        """Drive build_fuse_ufs with everything external stubbed out."""
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.find_cargo", return_value="/usr/bin/cargo"), \
             patch("bootstrap.cargo_version", return_value=cargo), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._run", run), \
             patch("bootstrap._tool_on_path", return_value=True):
            return bootstrap.build_fuse_ufs(force=force)

    def test_installs_into_usr_local_so_the_binary_lands_on_path(self):
        run = MagicMock(return_value=True)
        assert self._install(run) is True

        cmd = run.call_args[0][0]
        assert cmd[:3] == ["/usr/bin/cargo", "install", "fuse-ufs"]
        assert "--root" in cmd and cmd[cmd.index("--root") + 1] == "/usr/local"

    def test_dependencies_are_locked_to_the_released_set(self):
        """Unlocked, cargo re-resolves and a transitive MSRV bump breaks it."""
        run = MagicMock(return_value=True)
        self._install(run)
        assert "--locked" in run.call_args[0][0]

    def test_modern_toolchain_installs_the_current_release(self):
        run = MagicMock(return_value=True)
        self._install(run, cargo=(1, 85))
        assert "--version" not in run.call_args[0][0]

    def test_old_toolchain_falls_back_to_the_pinned_release(self):
        """Ubuntu 24.04 ships cargo 1.75; the current release needs 1.85."""
        run = MagicMock(return_value=True)
        assert self._install(run, cargo=(1, 75)) is True

        cmd = run.call_args[0][0]
        assert cmd[cmd.index("--version") + 1] == bootstrap.FUSE_UFS_LEGACY_VERSION

    def test_unknown_cargo_version_attempts_the_current_release(self):
        run = MagicMock(return_value=True)
        self._install(run, cargo=None)
        assert "--version" not in run.call_args[0][0]

    def test_force_passes_cargos_force_flag(self):
        run = MagicMock(return_value=True)
        self._install(run, force=True)
        assert "--force" in run.call_args[0][0]

    def test_cargo_failure_is_reported_not_raised(self):
        assert self._install(MagicMock(return_value=False)) is False

    def test_post_install_check_bypasses_the_tool_cache(self):
        """tool_exists memoises, so a pre-build miss would stick post-build."""
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.find_cargo", return_value="/usr/bin/cargo"), \
             patch("bootstrap.cargo_version", return_value=(1, 85)), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._run", return_value=True), \
             patch("bootstrap._tool_on_path", return_value=True) as on_path:
            assert bootstrap.build_fuse_ufs() is True
        on_path.assert_called_once_with("fuse-ufs")


class TestCargoVersion:
    """Pick a release the toolchain can build instead of failing mid-compile."""

    @staticmethod
    def _cargo(stdout):
        return MagicMock(stdout=stdout, returncode=0)

    def test_parses_apt_cargo(self):
        with patch("subprocess.run", return_value=self._cargo(
                "cargo 1.75.0 (1d8b05cdd 2023-11-20)\n")):
            assert bootstrap.cargo_version("/usr/bin/cargo") == (1, 75)

    def test_parses_rustup_cargo(self):
        with patch("subprocess.run", return_value=self._cargo(
                "cargo 1.89.0 (c24e10642 2025-06-23)\n")):
            assert bootstrap.cargo_version("/root/.cargo/bin/cargo") == (1, 89)

    def test_unparseable_output_is_unknown(self):
        with patch("subprocess.run", return_value=self._cargo("weird\n")):
            assert bootstrap.cargo_version("/usr/bin/cargo") is None

    def test_a_broken_cargo_is_unknown_not_an_exception(self):
        with patch("subprocess.run", side_effect=OSError("boom")):
            assert bootstrap.cargo_version("/usr/bin/cargo") is None

    def test_apt_cargo_is_below_the_modern_threshold(self):
        """Guards the constant itself: 1.75 must select the legacy pin."""
        assert (1, 75) < bootstrap.FUSE_UFS_MODERN_RUST
        assert (1, 85) >= bootstrap.FUSE_UFS_MODERN_RUST


class TestBootstrapOptIn:
    """Plain `mountir setup` must not start installing Rust."""

    @staticmethod
    def _patched(**extra):
        return patch.multiple(
            "bootstrap",
            ensure_venv_ready=MagicMock(return_value=True),
            missing_system_packages=MagicMock(return_value=[]),
            install_system_deps=MagicMock(return_value=True),
            build_apfs_fuse=MagicMock(return_value=True),
            build_libewf=MagicMock(return_value=True),
            _write_marker=MagicMock(),
            _tool_on_path=MagicMock(return_value=False),
            **extra,
        )

    def test_default_setup_skips_fuse_ufs(self):
        build = MagicMock(return_value=True)
        with self._patched(build_fuse_ufs=build):
            bootstrap.run_bootstrap()
        build.assert_not_called()

    def test_opt_in_flag_installs_it(self):
        build = MagicMock(return_value=True)
        with self._patched(build_fuse_ufs=build):
            bootstrap.run_bootstrap(with_fuse_ufs=True)
        build.assert_called_once_with(force=False)

    def test_force_is_passed_through(self):
        build = MagicMock(return_value=True)
        with self._patched(build_fuse_ufs=build):
            bootstrap.run_bootstrap(force=True, with_fuse_ufs=True)
        build.assert_called_once_with(force=True)

    def test_a_failed_optional_install_does_not_fail_setup(self):
        with self._patched(build_fuse_ufs=MagicMock(return_value=False)):
            assert bootstrap.run_bootstrap(with_fuse_ufs=True) is True


class TestSetupCli:
    """The flag reaches run_bootstrap from both setup and its legacy alias."""

    def test_setup_accepts_the_flag(self):
        args = build_parser().parse_args(["setup", "--ufs"])
        assert args.with_fuse_ufs is True

    def test_setup_defaults_to_off(self):
        assert build_parser().parse_args(["setup"]).with_fuse_ufs is False

    def test_install_deps_alias_accepts_it_too(self):
        args = build_parser().parse_args(["install-deps", "--ufs"])
        assert args.with_fuse_ufs is True
