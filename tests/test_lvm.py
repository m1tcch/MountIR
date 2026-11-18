"""Tests for LVM discovery and read-only logical-volume exposure (lvm.py).

The pvs/lvs rows below are real ``--reportformat json`` output from lvm2
2.03.16 for a VG with a fragmented LV (``root``, extended into a
non-adjacent extent run), a contiguous LV (``home``), an LV whose segments
LVM itself merged (``var``) and a two-way striped LV (``data``).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import lvm
import mountir
import utils
from partition import PartitionInfo
from state import MountedImage, StateManager

VG_UUID = "4HkTtE-zoTs-0AtG-OeFC-xpnS-nFZV-4m1NwK"
MIB = 1024 * 1024

PV_ROWS = [
    {"pv_name": "/dev/loop0", "pv_uuid": "r2fnQb", "vg_name": "evvg",
     "vg_uuid": VG_UUID, "pe_start": "1048576", "vg_extent_size": "1048576"},
    {"pv_name": "/dev/loop1", "pv_uuid": "CCbBDP", "vg_name": "evvg",
     "vg_uuid": VG_UUID, "pe_start": "1048576", "vg_extent_size": "1048576"},
    # An orphan PV (no VG) is ignored.
    {"pv_name": "/dev/loop2", "pv_uuid": "x", "vg_name": "", "vg_uuid": "",
     "pe_start": "1048576", "vg_extent_size": "0"},
]


def _lv_row(name, uuid, seg_start, seg_size, devices, segtype="linear",
            stripes="1", stripe_size="0", attr="-wi-------"):
    return {"vg_uuid": VG_UUID, "lv_name": name, "lv_uuid": uuid,
            "lv_attr": attr, "segtype": segtype, "seg_start_pe": seg_start,
            "seg_size_pe": seg_size, "stripes": stripes,
            "stripe_size": stripe_size, "devices": devices}


LV_ROWS = [
    _lv_row("data", "u4", "0", "16", "/dev/loop0(30),/dev/loop1(0)",
            segtype="striped", stripes="2", stripe_size="65536"),
    _lv_row("home", "u2", "0", "12", "/dev/loop0(8)"),
    _lv_row("root", "u1", "0", "8", "/dev/loop0(0)"),
    _lv_row("root", "u1", "8", "8", "/dev/loop0(20)"),
    _lv_row("var", "u3", "0", "8", "/dev/loop1(20)"),
]


@pytest.fixture
def vg():
    (group,) = lvm.build_volume_groups(PV_ROWS, LV_ROWS)
    return group


def _lv(group, name):
    return next(lv for lv in group.lvs if lv.name == name)


@pytest.fixture(autouse=True)
def reset_dm_cache():
    lvm._DM_AVAILABLE = None
    yield
    lvm._DM_AVAILABLE = None


# ---------------------------------------------------------------------------
# Isolation: the host's VGs must never be visible to our LVM commands
# ---------------------------------------------------------------------------
class TestIsolationConfig:
    def test_accepts_only_the_evidence_devices(self):
        cfg = lvm.isolation_config(["/dev/loop1", "/dev/nbd0p2"])
        assert '"a|^/dev/loop1$|"' in cfg
        assert '"a|^/dev/nbd0p2$|"' in cfg
        assert cfg.count('"r|.*|"') == 2  # filter and global_filter
        assert "use_devicesfile=0" in cfg
        assert "metadata_read_only=1" in cfg

    def test_filter_is_anchored(self):
        """/dev/loop12 must not be accepted by a rule for /dev/loop1."""
        import re
        cfg = lvm.isolation_config(["/dev/loop1"])
        rx = re.search(r'"a\|(.+?)\|"', cfg).group(1)
        assert re.fullmatch(rx, "/dev/loop1")
        assert not re.search(rx, "/dev/loop12")
        assert not re.search(rx, "/dev/sda3")

    def test_regex_metacharacters_are_literal(self):
        cfg = lvm.isolation_config(["/dev/mapper/a.b+c"])
        assert "a[.]b[+]c" in cfg

    @pytest.mark.parametrize("bad", [
        '/dev/loop0" ] } global { metadata_read_only=0 } x { y=["',
        "/dev/../etc/shadow", "relative/loop0", "/dev/loop0|", "/dev/loop 0", "",
    ])
    def test_unsafe_device_paths_are_dropped(self, bad):
        cfg = lvm.isolation_config([bad])
        assert '"a|' not in cfg
        assert "metadata_read_only=0" not in cfg

    def test_no_devices_rejects_everything(self):
        assert 'filter=[ "r|.*|" ]' in lvm.isolation_config([])

    def test_activation_is_read_only_and_unmonitored(self):
        cfg = lvm.isolation_config(["/dev/loop1"], read_only_vg="rhel")
        assert 'read_only_volume_list=[ "rhel" ]' in cfg
        assert "monitoring=0" in cfg

    def test_unsafe_vg_name_is_refused(self):
        with pytest.raises(ValueError):
            lvm.isolation_config(["/dev/loop1"], read_only_vg='x" ] } a {')


# ---------------------------------------------------------------------------
# Metadata parsing
# ---------------------------------------------------------------------------
class TestParsing:
    def test_parse_areas(self):
        assert lvm.parse_areas("/dev/loop0(30),/dev/loop1(0)") == [
            ("/dev/loop0", 30), ("/dev/loop1", 0)]
        assert lvm.parse_areas("") == []
        assert lvm.parse_areas("[unknown](0)") == [("[unknown]", 0)]

    def test_build_volume_groups(self, vg):
        assert vg.name == "evvg" and vg.uuid == VG_UUID
        assert vg.extent_size == MIB
        assert vg.pv_starts == {"/dev/loop0": MIB, "/dev/loop1": MIB}
        assert sorted(lv.name for lv in vg.lvs) == ["data", "home", "root", "var"]
        root = _lv(vg, "root")
        assert [s.start_extent for s in root.segments] == [0, 8]
        assert root.extents == 16

    def test_report_rows_tolerates_garbage(self):
        assert lvm._report_rows("not json", "pv") == []
        assert lvm._report_rows('{"report": [{"pv": [{"pv_name": "/dev/x"}]}]}',
                                "pv") == [{"pv_name": "/dev/x"}]

    def test_scan_confines_both_commands(self):
        pvs = MagicMock(returncode=0, stdout='{"report":[{"pv":%s}]}'
                        % __import__("json").dumps(PV_ROWS), stderr="")
        lvs = MagicMock(returncode=0, stdout='{"report":[{"lv":%s}]}'
                        % __import__("json").dumps(LV_ROWS), stderr="")
        with patch("lvm.lvm_available", return_value=True), \
             patch("lvm.run_command", side_effect=[pvs, lvs]) as run:
            vgs = lvm.scan(["/dev/loop0", "/dev/loop1"])
        assert [v.name for v in vgs] == ["evvg"]
        assert run.call_count == 2  # one pvs + one lvs, whatever the VG count
        for call in run.call_args_list:
            cmd = call.args[0]
            assert cmd[1] == "--config" and "a|^/dev/loop0$|" in cmd[2]
            assert "--readonly" in cmd


# ---------------------------------------------------------------------------
# Mapping plans
# ---------------------------------------------------------------------------
class TestPlans:
    def test_contiguous_lv_is_one_run(self, vg):
        runs, reason = lvm.plan_linear(vg, _lv(vg, "home"))
        assert reason == ""
        assert len(runs) == 1
        assert runs[0].device == "/dev/loop0"
        assert runs[0].dev_offset == MIB + 8 * MIB
        assert runs[0].length == 12 * MIB

    def test_fragmented_lv_is_two_runs(self, vg):
        runs, _ = lvm.plan_linear(vg, _lv(vg, "root"))
        assert [(r.lv_offset, r.dev_offset, r.length) for r in runs] == [
            (0, MIB, 8 * MIB), (8 * MIB, MIB + 20 * MIB, 8 * MIB)]

    def test_adjacent_segments_merge_into_one_run(self, vg):
        lv = lvm.LogicalVolume("x", "u", "-wi-------", [
            lvm.Segment(0, 4, "linear", 1, 0, [("/dev/loop1", 10)]),
            lvm.Segment(4, 4, "linear", 1, 0, [("/dev/loop1", 14)]),
        ])
        runs, _ = lvm.plan_linear(vg, lv)
        assert len(runs) == 1 and runs[0].length == 8 * MIB

    def test_striped_lv_is_not_linear(self, vg):
        assert lvm.plan_linear(vg, _lv(vg, "data")) == ([], "")

    def test_missing_pv_is_reported(self, vg):
        lv = lvm.LogicalVolume("x", "u", "-wi-------", [
            lvm.Segment(0, 4, "linear", 1, 0, [("[unknown]", 0)])])
        runs, reason = lvm.plan_linear(vg, lv)
        assert runs == [] and "not in this image" in reason

    def test_dm_table_for_fragmented_lv(self, vg):
        table, reason = lvm.build_dm_table(vg, _lv(vg, "root"))
        assert reason == ""
        assert table == ("0 16384 linear /dev/loop0 2048\n"
                         "16384 16384 linear /dev/loop0 43008\n")

    def test_dm_table_for_striped_lv(self, vg):
        table, _ = lvm.build_dm_table(vg, _lv(vg, "data"))
        assert table == "0 32768 striped 2 128 /dev/loop0 63488 /dev/loop1 2048\n"

    def test_dm_table_rejects_gaps(self, vg):
        lv = lvm.LogicalVolume("x", "u", "-wi-------", [
            lvm.Segment(4, 4, "linear", 1, 0, [("/dev/loop1", 0)])])
        assert lvm.build_dm_table(vg, lv)[0] == ""

    @pytest.mark.parametrize("attr,segtype,kind", [
        ("-wi-a-----", "linear", "direct"),
        ("owi-a-s---", "linear", "direct"),     # snapshot origin
        ("-wi-a-----", "striped", "direct"),
        ("twi-a-tz--", "thin-pool", "pool"),
        ("Vwi-a-tz--", "thin", "activate"),
        ("rwi-a-r---", "raid1", "activate"),
        ("swi-a-s---", "linear", "activate"),   # classic snapshot (COW store)
        ("Cwi-a-C---", "cache", "activate"),
    ])
    def test_classify(self, attr, segtype, kind):
        lv = lvm.LogicalVolume("x", "u", attr, [
            lvm.Segment(0, 1, segtype, 1, 0, [("/dev/loop0", 0)])])
        assert lvm.classify(lv) == kind


class TestDmNaming:
    def test_names_are_per_mount_and_bounded(self, vg):
        a = lvm.dm_name("CASE_disk_aaaaaa", vg, _lv(vg, "root"))
        b = lvm.dm_name("CASE_disk_bbbbbb", vg, _lv(vg, "root"))
        assert a != b and a.startswith("mountir-") and a.endswith("evvg-root")
        long_id = "X" * 500
        assert len(lvm.dm_name(long_id, vg, _lv(vg, "root"))) <= 127
        assert (lvm.dm_name(long_id, vg, _lv(vg, "root"))
                != lvm.dm_name(long_id, vg, _lv(vg, "home")))
        assert len(lvm.dm_uuid_prefix(long_id) + "u" * 32) <= 128


# ---------------------------------------------------------------------------
# Exposure
# ---------------------------------------------------------------------------
def _pvs():
    return [PartitionInfo(device="/dev/loop0", number=1, filesystem="lvm2_member"),
            PartitionInfo(device="/dev/loop1", number=2, filesystem="lvm2_member"),
            PartitionInfo(device="/dev/loop3", number=3, filesystem="ext4")]


def _expose(vgs, dm=False, loops=("/dev/loop10", "/dev/loop11", "/dev/loop12")):
    loops = iter(loops)
    with patch("lvm.lvm_available", return_value=True), \
         patch("lvm.scan", return_value=vgs) as scan, \
         patch("lvm.dm_available", return_value=dm), \
         patch("lvm._attach_offset_loop", side_effect=lambda *a: next(loops)) as att, \
         patch("lvm._dm_create", return_value="/dev/mapper/x") as create, \
         patch("lvm._enrich_with_blkid"):
        parts = _pvs()
        result = lvm.expose_logical_volumes(parts, "EV_abc123")
    return parts, result, scan, att, create


class TestExpose:
    def test_no_pv_does_nothing(self):
        with patch("lvm.scan") as scan:
            result = lvm.expose_logical_volumes(
                [PartitionInfo(device="/dev/loop3", filesystem="ext4")], "EV_x")
        scan.assert_not_called()
        assert result.partitions == []

    def test_only_candidate_devices_are_scanned(self, vg):
        _, _, scan, _, _ = _expose([vg])
        assert scan.call_args.args[0] == ["/dev/loop0", "/dev/loop1"]

    def test_without_device_mapper(self, vg):
        parts, result, _, att, create = _expose([vg], dm=False)
        by = {p.label: p for p in result.partitions}
        # Contiguous LVs get an offset loop on their PV.
        assert by["evvg-home"].device == "/dev/loop10"
        att.assert_any_call("/dev/loop0", MIB + 8 * MIB, 12 * MIB)
        assert by["evvg-var"].device.startswith("/dev/loop1")
        # Fragmented/striped LVs say exactly why they can't be mounted.
        assert "device-mapper" in by["evvg-root"].mount_error
        assert "fragmented" in by["evvg-root"].mount_error
        assert "striped" in by["evvg-data"].mount_error
        create.assert_not_called()
        assert sorted(result.loops) == ["/dev/loop10", "/dev/loop11"]
        # PVs are labelled with their VG rather than shown as bare members.
        assert parts[0].skip_reason == "LVM PV of VG evvg"
        assert all(200 <= p.number < 300 for p in result.partitions)
        assert result.vgs == [{"name": "evvg", "uuid": VG_UUID,
                               "pv_devices": ["/dev/loop0", "/dev/loop1"],
                               "activated_lvs": []}]

    def test_with_device_mapper(self, vg):
        _, result, _, _, create = _expose([vg], dm=True)
        tables = {c.args[2] for c in create.call_args_list}
        assert "0 16384 linear /dev/loop0 2048\n16384 16384 linear /dev/loop0 43008\n" in tables
        assert "0 32768 striped 2 128 /dev/loop0 63488 /dev/loop1 2048\n" in tables
        for c in create.call_args_list:
            assert c.args[1].startswith(lvm.dm_uuid_prefix("EV_abc123"))
            assert not c.args[1].startswith("LVM-")  # LVM's udev rules ignore it
        assert len(result.dm_devices) == 2

    def test_thin_pool_is_skipped_not_failed(self, vg):
        vg.lvs.append(lvm.LogicalVolume("pool", "u9", "twi-a-tz--", [
            lvm.Segment(0, 4, "thin-pool", 1, 0, [("pool_tdata", 0)])]))
        _, result, _, _, _ = _expose([vg])
        pool = next(p for p in result.partitions if p.label == "evvg-pool")
        assert "thin pool" in pool.skip_reason and not pool.mount_error

    def test_lv_on_missing_pv_is_skipped(self, vg):
        vg.lvs = [lvm.LogicalVolume("split", "u8", "-wi-------", [
            lvm.Segment(0, 4, "linear", 1, 0, [("[unknown]", 0)])])]
        _, result, _, att, _ = _expose([vg])
        assert "not in this image" in result.partitions[0].skip_reason
        att.assert_not_called()

    def test_unsafe_names_are_never_used(self, vg):
        vg.lvs = [lvm.LogicalVolume("../../x", "u7", "-wi-------", [
            lvm.Segment(0, 4, "linear", 1, 0, [("/dev/loop0", 0)])])]
        _, result, _, att, _ = _expose([vg])
        assert result.partitions == []
        att.assert_not_called()


class TestActivationFallback:
    def _thin_vg(self, name="rhel"):
        return lvm.VolumeGroup(name=name, uuid=VG_UUID, extent_size=MIB,
                               pv_starts={"/dev/loop0": MIB}, lvs=[
            lvm.LogicalVolume("thin1", "u5", "Vwi-a-tz--", [
                lvm.Segment(0, 4, "thin", 1, 0, [])])])

    def test_refused_when_the_host_has_a_vg_of_the_same_name(self):
        host = [lvm.DmDevice("rhel-root", "LVM-hostvguuidhostlvuuid", "dm-0")]
        with patch("lvm.dm_devices", return_value=host), \
             patch("lvm._lvm") as run:
            _, result, _, _, _ = _expose([self._thin_vg()], dm=True)
        run.assert_not_called()
        assert "name clash" in result.partitions[0].skip_reason

    def test_activates_read_only_and_confined(self):
        node = "/dev/mapper/rhel-thin1"
        with patch("lvm.dm_devices", return_value=[]), \
             patch("lvm._lvm", return_value=MagicMock(returncode=0, stderr="")) as run, \
             patch("lvm.Path.exists", lambda self: str(self) == node):
            _, result, _, _, _ = _expose([self._thin_vg()], dm=True)
        tool, devices, args = run.call_args.args
        assert tool == "lvchange" and devices == ["/dev/loop0"]
        assert args == ["-ay", "-K", "rhel/thin1"]
        assert run.call_args.kwargs["read_only_vg"] == "rhel"
        assert result.partitions[0].device == node
        assert result.vgs[0]["activated_lvs"] == ["thin1"]

    def test_needs_device_mapper(self):
        _, result, _, _, _ = _expose([self._thin_vg()], dm=False)
        assert "device-mapper" in result.partitions[0].mount_error

    def test_duplicate_vg_names_in_one_image_are_refused(self):
        a, b = self._thin_vg(), self._thin_vg()
        b.uuid = "other"
        assert "more than one VG" in lvm._vg_collides(a, [a, b], [])


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
class TestTeardown:
    REC = {"name": "rhel", "uuid": VG_UUID, "pv_devices": ["/dev/loop0"],
           "activated_lvs": ["thin1"]}

    def test_removes_own_tables_in_reverse(self):
        with patch("lvm.dm_remove", return_value=True) as rm:
            assert lvm.teardown(["a", "b"], [])
        assert [c.args[0] for c in rm.call_args_list] == ["b", "a"]

    def test_deactivation_is_confined_to_the_images_devices(self):
        with patch("lvm._lvm", return_value=MagicMock(returncode=0)) as run, \
             patch("lvm.tool_exists", return_value=True), \
             patch("lvm.dm_devices", return_value=[]):
            assert lvm.teardown([], [self.REC])
        tool, devices, args = run.call_args.args
        assert (tool, devices, args) == ("vgchange", ["/dev/loop0"], ["-an", "rhel"])

    def test_leftovers_only_removed_when_they_sit_on_our_devices(self):
        uuid = "LVM-" + VG_UUID.replace("-", "")
        devs = [lvm.DmDevice("rhel-ours", uuid + "aaa", "dm-1"),
                lvm.DmDevice("rhel-not", uuid + "bbb", "dm-2")]
        deps = {"rhel-ours": ["loop0"], "rhel-not": ["sda3"]}
        removed = []

        def fake_rm(name):
            removed.append(name)
            devs[:] = [d for d in devs if d.name != name]
            return True

        with patch("lvm.dm_devices", side_effect=lambda: list(devs)), \
             patch("lvm._dm_deps", side_effect=lambda n: deps[n]), \
             patch("lvm.dm_remove", side_effect=fake_rm):
            assert not lvm._remove_vg_leftovers(VG_UUID, ["/dev/loop0"])
        assert removed == ["rhel-ours"]

    def test_stacked_leftovers_are_removed_top_down(self):
        uuid = "LVM-" + VG_UUID.replace("-", "")
        devs = [lvm.DmDevice("vg-thin", uuid + "t", "dm-3"),
                lvm.DmDevice("vg-pool", uuid + "p", "dm-2")]
        deps = {"vg-thin": ["dm-2"], "vg-pool": ["loop0"]}

        def fake_rm(name):
            # The pool is busy until the thin LV on top of it is gone.
            if name == "vg-pool" and any(d.name == "vg-thin" for d in devs):
                return False
            devs[:] = [d for d in devs if d.name != name]
            return True

        with patch("lvm.dm_devices", side_effect=lambda: list(devs)), \
             patch("lvm._dm_deps", side_effect=lambda n: deps[n]), \
             patch("lvm.dm_remove", side_effect=fake_rm):
            assert lvm._remove_vg_leftovers(VG_UUID, ["/dev/loop0"])
        assert devs == []

    def test_legacy_state_is_deactivated_confined(self):
        with patch("lvm._lvm") as run:
            lvm.deactivate_legacy(["ubuntu-vg"], ["/dev/loop4", "bogus path"])
        assert run.call_args.args == ("vgchange", ["/dev/loop4"], ["-an", "ubuntu-vg"])

    def test_legacy_without_devices_does_nothing(self):
        with patch("lvm._lvm") as run:
            lvm.deactivate_legacy(["ubuntu-vg"], [])
        run.assert_not_called()


class TestUnmountIntegration:
    def _mounted(self, **kw):
        return MountedImage(mount_id="EV_abc123", image_path="/e/disk.dd",
                            image_type="raw", partition_loops=["/dev/loop0",
                                                               "/dev/loop10"], **kw)

    def test_lvm_released_before_loops_are_detached(self, tmp_path):
        order = []
        mounted = self._mounted(lvm_vgs=[TestTeardown.REC], lvm_dm_devices=["t"])
        with patch("mountir.lvm.teardown",
                   side_effect=lambda *a: order.append("lvm") or True) as td, \
             patch("mountir.run_command",
                   side_effect=lambda cmd, **k: order.append(cmd[-1])), \
             patch("mountir.get_handler"):
            mountir._unmount_single(mounted, StateManager(tmp_path / "s.json"))
        td.assert_called_once_with(["t"], [TestTeardown.REC])
        assert order[:3] == ["lvm", "/dev/loop10", "/dev/loop0"]

    def test_legacy_entry_uses_confined_deactivation(self, tmp_path):
        mounted = self._mounted(lvm_vg_names=["rhel"])
        with patch("mountir.lvm.deactivate_legacy") as legacy, \
             patch("mountir.lvm.teardown") as td, \
             patch("mountir.run_command"), patch("mountir.get_handler"):
            mountir._unmount_single(mounted, StateManager(tmp_path / "s.json"))
        td.assert_not_called()
        names, devices = legacy.call_args.args
        assert names == ["rhel"] and "/dev/loop0" in devices


class TestStateAndClean:
    def test_lvm_fields_round_trip(self, tmp_path):
        mgr = StateManager(tmp_path / "s.json")
        mgr.add_mount(MountedImage(mount_id="EV_1", image_path="/x", image_type="raw",
                                   lvm_vgs=[TestTeardown.REC], lvm_dm_devices=["d"]))
        (img,) = StateManager(tmp_path / "s.json").load().mounted_images
        assert img.lvm_vgs == [TestTeardown.REC] and img.lvm_dm_devices == ["d"]

    def test_stacked_loops_are_found_for_clean(self):
        out = ("/dev/loop0: [2049]:1 (/mnt/mountir/EV_1/container/ewf1), offset 1048576\n"
               "/dev/loop10: [5]:2 (/dev/loop0), offset 9437184, sizelimit 12582912\n"
               "/dev/loop11: [5]:3 (/dev/loop10)\n"
               "/dev/loop5: [5]:4 (/dev/sda)\n")
        devs = utils.loop_devices_backing(Path("/mnt/mountir"), losetup_output=out)
        assert devs == ["/dev/loop0", "/dev/loop10", "/dev/loop11"]

    def test_orphan_dm_devices_match_by_mount_id(self):
        devs = [lvm.DmDevice("a", lvm.dm_uuid_prefix("EV_1") + "x", "dm-0"),
                lvm.DmDevice("b", lvm.dm_uuid_prefix("EV_2") + "x", "dm-1"),
                lvm.DmDevice("c", "LVM-abc", "dm-2")]
        with patch("lvm.dm_devices", return_value=devs):
            assert lvm.orphan_dm_devices(["EV_1"]) == ["a"]
            assert lvm.orphan_dm_devices([]) == []

    def test_clean_detaches_higher_loops_first(self):
        assert sorted(["/dev/loop2", "/dev/loop10", "/dev/loop9"],
                      key=mountir._loop_sort_key, reverse=True) == [
            "/dev/loop10", "/dev/loop9", "/dev/loop2"]
