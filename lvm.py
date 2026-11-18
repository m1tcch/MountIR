#!/usr/bin/env python3
"""LVM2 volume-group discovery and read-only logical-volume exposure.

Why MountIR does not just run ``vgchange -ay``
----------------------------------------------
The obvious approach -- ``pvs`` to find the volume group, ``vgchange -ay`` to
activate it, ``vgchange -an`` on unmount -- is wrong for evidence in ways that
matter:

* **Name collisions with the analyst's host.** Distribution installers name the
  VG after the distro (``rhel``, ``centos``, ``ubuntu-vg``, ``fedora``), so an
  image of a RHEL server examined on a RHEL workstation carries a VG named the
  same as the one holding the workstation's own root filesystem. LVM refuses to
  activate the duplicate, and ``vgchange -an rhel`` at unmount targets the
  *host's* VG. Two images from the same build mounted in one batch collide with
  each other the same way.
* **The devices file.** lvm2 >= 2.03.12 with ``use_devicesfile=1`` (the RHEL 9 /
  Fedora default) only looks at devices listed in ``system.devices``, so the
  loop devices MountIR attaches are invisible and LVM is never detected.
* **No device-mapper.** Activation needs the kernel's device-mapper. The WSL2
  kernel and many containers don't have it, so activation fails even for the
  plain single-segment LVs that make up most real disks.

What this module does instead
-----------------------------
Every LVM command runs with an **isolating** ``--config``: the device filter
accepts *only* the evidence devices of this image, the devices file is off,
and ``metadata_read_only`` forbids any metadata write. The host's own VGs are
never visible to these commands, so they can't collide with or be touched by
them.

Metadata is read once (one ``pvs`` and one ``lvs`` call, JSON report) and each
LV is then exposed in the least invasive way that works:

1. **Contiguous LV** (one run of extents on one PV, the common case): a
   read-only **offset loop** over that byte range of the PV. Needs neither
   device-mapper nor any LVM state, so it works on WSL2.
2. **Fragmented or striped LV** (e.g. after ``lvextend``): a private read-only
   **device-mapper table** built from the metadata (``linear``/``striped``
   targets) under a MountIR-owned name and UUID. LVM's udev rules ignore
   non-``LVM-`` UUIDs, and the name embeds the mount id, so identically-named
   VGs from different images, or from the host, never clash.
3. **Thin / RAID / mirror / cache / snapshot LVs**: these need LVM's own
   activation logic. MountIR runs ``lvchange -ay`` under the isolating config
   with ``read_only_volume_list`` and monitoring off, but only when the VG's
   name can't collide with anything already in device-mapper; otherwise the
   LV is reported as skipped with the reason.

LVs on a PV that isn't in this image (a VG spanning several disks), thin
pools, and LVs that would need device-mapper on a kernel without it are
reported as skipped, each with its reason, never as a silent omission.

Evidence-supplied metadata is untrusted: VG/LV names and device paths are
checked against strict patterns before they are put into an LVM config
string or a device-mapper name.
"""

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from partition import PartitionInfo, _attach_offset_loop, _enrich_with_blkid
from utils import logger, run_command, tool_exists

# Partition numbers 2xx are LVM logical volumes (see README "Partition numbers").
LV_NUMBER_BASE = 200

# Device-mapper UUID prefix for tables MountIR builds itself. ``clean`` finds
# orphans by it; LVM's udev rules leave non-"LVM-" UUIDs alone.
DM_UUID_PREFIX = "MOUNTIR-"

_SECTOR = 512
_DM_NAME_MAX = 127
_LVM_TIMEOUT = 60

# LVM itself only allows these characters in VG/LV names. Evidence metadata can
# be hand-crafted, so they're enforced here too before a name is put into a
# --config string or a dm table.
_LVM_NAME_RE = re.compile(r"^[A-Za-z0-9+_.][A-Za-z0-9+_.-]{0,127}$")
# Device paths we hand to LVM's filter: plain /dev nodes, no traversal.
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$")
# One entry of the lvs "devices" field: "/dev/loop7(1280)".
_AREA_RE = re.compile(r"^(?P<dev>.+)\((?P<pe>\d+)\)$")

# lv_attr[0] values whose data is a plain mapping of PV extents.
_DIRECT_ATTRS = {"-", "o"}  # plain LV, snapshot origin
_DIRECT_SEGTYPES = {"linear", "striped"}
# Pools hold other LVs' data; there is no filesystem in them to mount.
_POOL_ATTRS = {"t": "thin pool", "d": "VDO pool"}


# ---------------------------------------------------------------------------
# Metadata model
# ---------------------------------------------------------------------------
@dataclass
class Segment:
    start_extent: int
    extents: int
    segtype: str
    stripes: int
    stripe_size: int                  # bytes
    areas: List[Tuple[str, int]]      # (pv device, starting PE)


@dataclass
class LogicalVolume:
    name: str
    uuid: str
    attr: str
    segments: List[Segment] = field(default_factory=list)

    @property
    def extents(self) -> int:
        return sum(s.extents for s in self.segments)


@dataclass
class VolumeGroup:
    name: str
    uuid: str
    extent_size: int                                  # bytes
    pv_starts: Dict[str, int] = field(default_factory=dict)  # pv device -> pe_start bytes
    lvs: List[LogicalVolume] = field(default_factory=list)


@dataclass
class LvmExposure:
    """What :func:`expose_logical_volumes` set up, for mounting and teardown."""
    partitions: List[PartitionInfo] = field(default_factory=list)  # one per LV
    loops: List[str] = field(default_factory=list)   # offset loops (detach on unmount)
    dm_devices: List[str] = field(default_factory=list)  # our dm tables (remove on unmount)
    vgs: List[dict] = field(default_factory=list)    # state records, see _vg_record


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------
def _safe_devices(devices: Iterable[str]) -> List[str]:
    """Drop anything that isn't a plain /dev path (keeps the filter injection-free)."""
    out: List[str] = []
    for dev in devices:
        dev = str(dev or "")
        if not dev:
            continue
        if _DEVICE_RE.fullmatch(dev) and ".." not in dev:
            if dev not in out:
                out.append(dev)
        else:
            logger.debug("Not passing unexpected device path to LVM: %r", dev)
    return out


def _filter_regex(dev: str) -> str:
    # LVM's regex engine has no reliable escape inside a config string, so
    # metacharacters the device pattern allows become one-char classes.
    return "^" + dev.replace(".", "[.]").replace("+", "[+]") + "$"


def isolation_config(devices: Sequence[str], read_only_vg: str = "") -> str:
    """``--config`` text that confines an LVM command to *devices*.

    * ``filter``/``global_filter`` accept only the evidence devices, so the
      host's VGs (and any other image's) are invisible to the command.
    * ``use_devicesfile=0`` stops the devices file hiding the loop devices.
    * ``metadata_read_only`` forbids any write of LVM metadata to the evidence.
    * ``backup``/``archive`` off keeps evidence metadata out of /etc/lvm.
    * ``read_only_volume_list`` (activation only) makes the activated LVs
      read-only in device-mapper, and ``monitoring=0`` keeps dmeventd from
      attempting RAID repair or thin-pool autoextend.
    """
    accepts = ", ".join(f'"a|{_filter_regex(d)}|"' for d in _safe_devices(devices))
    rules = f"[ {accepts + ', ' if accepts else ''}\"r|.*|\" ]"
    cfg = (
        f"devices {{ use_devicesfile=0 filter={rules} global_filter={rules} }} "
        "global { metadata_read_only=1 } "
        "backup { backup=0 archive=0 }"
    )
    if read_only_vg:
        if not _LVM_NAME_RE.fullmatch(read_only_vg):
            raise ValueError(f"refusing unsafe VG name {read_only_vg!r}")
        cfg += (f' activation {{ read_only_volume_list=[ "{read_only_vg}" ] '
                "monitoring=0 }")
    return cfg


def _lvm(tool: str, devices: Sequence[str], args: List[str],
         read_only_vg: str = "") -> subprocess.CompletedProcess:
    cmd = [tool, "--config", isolation_config(devices, read_only_vg)] + args
    return run_command(cmd, check=False, timeout=_LVM_TIMEOUT)


def lvm_available() -> bool:
    return tool_exists("pvs") and tool_exists("lvs")


_DM_AVAILABLE: Optional[bool] = None


def dm_available() -> bool:
    """True when the kernel device-mapper is usable (cached per process)."""
    global _DM_AVAILABLE
    if _DM_AVAILABLE is None:
        ok = False
        if tool_exists("dmsetup"):
            try:
                r = run_command(["dmsetup", "version"], check=False, timeout=10)
                ok = r.returncode == 0 and "Driver version" in r.stdout
            except Exception:
                ok = False
        _DM_AVAILABLE = ok
        if not ok:
            logger.debug("device-mapper is not available on this kernel")
    return _DM_AVAILABLE


# ---------------------------------------------------------------------------
# Metadata scan
# ---------------------------------------------------------------------------
def _report_rows(stdout: str, kind: str) -> List[dict]:
    """Rows of an ``--reportformat json`` report (empty on anything unexpected)."""
    try:
        data = json.loads(stdout or "{}")
    except ValueError:
        logger.debug("LVM %s report was not JSON", kind)
        return []
    rows: List[dict] = []
    for report in data.get("report", []) or []:
        rows.extend(r for r in report.get(kind, []) or [] if isinstance(r, dict))
    return rows


def _int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_areas(devices_field: str) -> List[Tuple[str, int]]:
    """Parse lvs ``devices`` (``/dev/loop0(30),/dev/loop1(0)``) into (dev, PE)."""
    areas: List[Tuple[str, int]] = []
    for item in (devices_field or "").split(","):
        item = item.strip()
        if not item:
            continue
        m = _AREA_RE.match(item)
        if not m:
            areas.append((item, -1))
            continue
        areas.append((m.group("dev"), int(m.group("pe"))))
    return areas


def build_volume_groups(pv_rows: List[dict], lv_rows: List[dict]) -> List[VolumeGroup]:
    """Assemble VolumeGroups from ``pvs``/``lvs`` JSON rows (pure, testable)."""
    vgs: Dict[str, VolumeGroup] = {}
    for row in pv_rows:
        vg_uuid = (row.get("vg_uuid") or "").strip()
        vg_name = (row.get("vg_name") or "").strip()
        pv_name = (row.get("pv_name") or "").strip()
        if not vg_uuid or not vg_name or not pv_name:
            continue  # orphan PV (not in any VG)
        vg = vgs.get(vg_uuid)
        if vg is None:
            vg = vgs[vg_uuid] = VolumeGroup(
                name=vg_name, uuid=vg_uuid,
                extent_size=_int(row.get("vg_extent_size")))
        vg.pv_starts[pv_name] = _int(row.get("pe_start"))

    lvs: Dict[Tuple[str, str], LogicalVolume] = {}
    for row in lv_rows:
        vg = vgs.get((row.get("vg_uuid") or "").strip())
        lv_uuid = (row.get("lv_uuid") or "").strip()
        if vg is None or not lv_uuid:
            continue
        key = (vg.uuid, lv_uuid)
        lv = lvs.get(key)
        if lv is None:
            lv = lvs[key] = LogicalVolume(
                name=(row.get("lv_name") or "").strip(), uuid=lv_uuid,
                attr=(row.get("lv_attr") or "").strip())
            vg.lvs.append(lv)
        lv.segments.append(Segment(
            start_extent=_int(row.get("seg_start_pe")),
            extents=_int(row.get("seg_size_pe")),
            segtype=(row.get("segtype") or "").strip(),
            stripes=max(1, _int(row.get("stripes"), 1)),
            stripe_size=_int(row.get("stripe_size")),
            areas=parse_areas(row.get("devices") or ""),
        ))
    for lv in lvs.values():
        lv.segments.sort(key=lambda s: s.start_extent)
    return list(vgs.values())


def scan(devices: Sequence[str]) -> List[VolumeGroup]:
    """Read the LVM metadata on *devices* (and only *devices*).

    Two commands in total regardless of the number of VGs or LVs. ``--readonly``
    reads on-disk metadata without taking LVM locks or talking to
    device-mapper, so this works on kernels without dm too.
    """
    devices = _safe_devices(devices)
    if not devices or not lvm_available():
        return []
    common = ["--readonly", "--reportformat", "json", "--units", "b", "--nosuffix"]
    try:
        pvs = _lvm("pvs", devices, common + [
            "-o", "pv_name,pv_uuid,vg_name,vg_uuid,pe_start,vg_extent_size"])
        if pvs.returncode != 0 and not pvs.stdout.strip():
            logger.debug("pvs failed: %s", (pvs.stderr or "").strip())
            return []
        pv_rows = _report_rows(pvs.stdout, "pv")
        if not any(r.get("vg_uuid") for r in pv_rows):
            return []
        lvs = _lvm("lvs", devices, common + [
            "-o", "vg_uuid,lv_name,lv_uuid,lv_attr,segtype,seg_start_pe,"
                  "seg_size_pe,stripes,stripe_size,devices"])
        lv_rows = _report_rows(lvs.stdout, "lv")
    except FileNotFoundError:
        logger.debug("lvm2 is not installed")
        return []
    except Exception as e:
        logger.warning("LVM metadata scan failed: %s", e)
        return []
    vgs = build_volume_groups(pv_rows, lv_rows)
    for vg in vgs:
        logger.info("Found LVM volume group %s (%d LV%s on %s)", vg.name,
                    len(vg.lvs), "" if len(vg.lvs) == 1 else "s",
                    ", ".join(sorted(vg.pv_starts)))
    return vgs


# ---------------------------------------------------------------------------
# Mapping plans
# ---------------------------------------------------------------------------
@dataclass
class Run:
    """A contiguous byte range of one PV mapped into the LV."""
    lv_offset: int
    length: int
    device: str
    dev_offset: int


def plan_linear(vg: VolumeGroup, lv: LogicalVolume) -> Tuple[List[Run], str]:
    """Byte runs of a linear LV, adjacent runs merged. ``([], reason)`` if not linear."""
    runs: List[Run] = []
    expected = 0
    for seg in lv.segments:
        if seg.start_extent != expected:
            return [], "metadata has a gap between segments"
        expected += seg.extents
        if seg.stripes != 1 or len(seg.areas) != 1:
            return [], ""
        dev, pe = seg.areas[0]
        if dev not in vg.pv_starts or pe < 0:
            return [], _missing_pv_reason(dev)
        run = Run(lv_offset=seg.start_extent * vg.extent_size,
                  length=seg.extents * vg.extent_size, device=dev,
                  dev_offset=vg.pv_starts[dev] + pe * vg.extent_size)
        prev = runs[-1] if runs else None
        if (prev and prev.device == run.device
                and prev.dev_offset + prev.length == run.dev_offset):
            prev.length += run.length
        else:
            runs.append(run)
    return runs, ""


def _missing_pv_reason(dev: str) -> str:
    return (f"its physical volume ({dev}) is not in this image; the VG spans "
            "another disk")


def build_dm_table(vg: VolumeGroup, lv: LogicalVolume) -> Tuple[str, str]:
    """Device-mapper table text for a linear/striped LV, or ``("", reason)``."""
    ext = vg.extent_size // _SECTOR
    if ext <= 0:
        return "", "VG reports no extent size"
    lines: List[str] = []
    expected = 0
    for seg in lv.segments:
        if seg.start_extent != expected:
            return "", "metadata has a gap between segments"
        expected += seg.extents
        start, length = seg.start_extent * ext, seg.extents * ext
        targets: List[str] = []
        for dev, pe in seg.areas:
            if dev not in vg.pv_starts or pe < 0:
                return "", _missing_pv_reason(dev)
            if not _DEVICE_RE.fullmatch(dev):
                return "", f"unexpected PV device path {dev!r}"
            targets.append(f"{dev} {vg.pv_starts[dev] // _SECTOR + pe * ext}")
        if seg.stripes == 1 and len(targets) == 1:
            lines.append(f"{start} {length} linear {targets[0]}")
            continue
        chunk = seg.stripe_size // _SECTOR
        if (len(targets) != seg.stripes or chunk <= 0
                or seg.extents % seg.stripes):
            return "", "inconsistent stripe metadata"
        lines.append(f"{start} {length} striped {seg.stripes} {chunk} "
                     + " ".join(targets))
    return "\n".join(lines) + "\n", ""


def classify(lv: LogicalVolume) -> str:
    """``direct``, ``pool`` or ``activate`` -- how an LV can be exposed."""
    kind = lv.attr[:1] or "-"
    if kind in _POOL_ATTRS:
        return "pool"
    if kind in _DIRECT_ATTRS and lv.segments and all(
            s.segtype in _DIRECT_SEGTYPES for s in lv.segments):
        return "direct"
    return "activate"


# ---------------------------------------------------------------------------
# Device-mapper
# ---------------------------------------------------------------------------
def _mount_tag(mount_id: str) -> str:
    """Short stable tag for a mount id (dm names/UUIDs have length limits)."""
    return hashlib.sha256(mount_id.encode()).hexdigest()[:12]


def dm_uuid_prefix(mount_id: str) -> str:
    return f"{DM_UUID_PREFIX}{_mount_tag(mount_id)}-"


def dm_name(mount_id: str, vg: VolumeGroup, lv: LogicalVolume) -> str:
    base = f"mountir-{_mount_tag(mount_id)}-{vg.name}-{lv.name}"
    base = re.sub(r"[^A-Za-z0-9_+.-]", "_", base)
    if len(base) <= _DM_NAME_MAX:
        return base
    # Two long LV names could truncate alike; the LV UUID keeps them apart.
    tail = "-" + hashlib.sha256(lv.uuid.encode()).hexdigest()[:8]
    return base[:_DM_NAME_MAX - len(tail)] + tail


def _dm_create(name: str, uuid: str, table: str) -> Optional[str]:
    cmd = ["dmsetup", "create", name, "--readonly", "--uuid", uuid]
    logger.debug("Running: %s <<< %r", " ".join(cmd), table)
    try:
        r = subprocess.run(cmd, input=table, capture_output=True, text=True,
                           timeout=_LVM_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning("dmsetup create %s failed: %s", name, e)
        return None
    if r.returncode != 0:
        logger.warning("dmsetup create %s failed: %s", name, (r.stderr or "").strip())
        return None
    node = f"/dev/mapper/{name}"
    if not Path(node).exists():
        # No udev (containers, some WSL setups): have libdm create the node.
        run_command(["dmsetup", "mknodes", name], check=False, timeout=15)
    return node if Path(node).exists() else None


def dm_remove(name: str) -> bool:
    try:
        r = run_command(["dmsetup", "remove", "--retry", name],
                        check=False, timeout=_LVM_TIMEOUT)
    except Exception as e:
        logger.warning("Could not remove device-mapper table %s: %s", name, e)
        return False
    if r.returncode != 0:
        logger.warning("Could not remove device-mapper table %s: %s",
                       name, (r.stderr or "").strip())
        return False
    logger.debug("Removed device-mapper table %s", name)
    return True


@dataclass
class DmDevice:
    name: str
    uuid: str
    kernel: str  # dm-N


def dm_devices() -> List[DmDevice]:
    """Every device-mapper device on the host (empty when dm is unavailable)."""
    if not tool_exists("dmsetup"):
        return []
    try:
        r = run_command(["dmsetup", "info", "-c", "--noheadings", "--separator",
                         "|", "-o", "name,uuid,blkdevname"], check=False, timeout=15)
    except Exception:
        return []
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3 and parts[0] and parts[0] != "No devices found":
            out.append(DmDevice(parts[0], parts[1], parts[2]))
    return out


def _dm_deps(name: str) -> List[str]:
    """Kernel names of the block devices a dm device sits on (``loop7``, ``dm-3``)."""
    try:
        r = run_command(["dmsetup", "deps", "-o", "devname", name],
                        check=False, timeout=15)
    except Exception:
        return []
    return re.findall(r"\(([^()]+)\)", r.stdout) if r.returncode == 0 else []


def _lvm_dm_name(vg_name: str, lv_name: str) -> str:
    """The dm name LVM gives an activated LV (``-`` doubled in each part)."""
    return f"{vg_name.replace('-', '--')}-{lv_name.replace('-', '--')}"


def _vg_collides(vg: VolumeGroup, all_vgs: List[VolumeGroup],
                 existing: List[DmDevice]) -> str:
    """Why activating *vg* through LVM could clash with something, or ``""``."""
    if sum(1 for other in all_vgs if other.name == vg.name) > 1:
        return f"this image holds more than one VG named {vg.name}"
    # Devices of this same VG (udev autoactivation) are not a clash.
    prefix = vg.name.replace("-", "--") + "-"
    for dev in existing:
        if dev.name.startswith(prefix) and not dev.uuid.startswith(
                "LVM-" + vg.uuid.replace("-", "")):
            return f"device-mapper already has {dev.name} (a VG named {vg.name})"
    return ""


# ---------------------------------------------------------------------------
# Exposure
# ---------------------------------------------------------------------------
def _vg_record(vg: VolumeGroup, devices: List[str], activated: List[str]) -> dict:
    return {"name": vg.name, "uuid": vg.uuid, "pv_devices": devices,
            "activated_lvs": activated}


def expose_logical_volumes(partitions: List[PartitionInfo],
                           mount_id: str) -> LvmExposure:
    """Find VGs on the exposed *partitions* and expose every LV read-only.

    PVs are marked with a skip reason naming their VG; each LV becomes a new
    ``PartitionInfo`` (numbered from 200) that the caller mounts like any other
    volume. LVs that can't be exposed carry a ``skip_reason`` or
    ``mount_error`` saying why.
    """
    result = LvmExposure()
    # Unidentified devices go along too: blkid may be missing or stale, and
    # LVM's own label scan is the authority on what is a PV.
    candidates = [p for p in partitions
                  if p.device and p.filesystem in ("lvm2_member", "")]
    if not any(p.filesystem == "lvm2_member" for p in candidates):
        return result
    if not lvm_available():
        logger.warning("LVM physical volume(s) present but lvm2 is not "
                       "installed - install lvm2 (mountir setup) to mount the LVs")
        for p in candidates:
            if p.filesystem == "lvm2_member":
                p.skip_reason = "LVM PV (lvm2 not installed)"
        return result

    devices = _safe_devices(p.device for p in candidates)
    vgs = scan(devices)
    if not vgs:
        logger.warning("LVM physical volume(s) present but no volume group "
                       "could be read from them")
        return result

    by_pv = {pv: vg for vg in vgs for pv in vg.pv_starts}
    for p in candidates:
        vg = by_pv.get(p.device)
        if vg is not None:
            p.skip_reason = f"LVM PV of VG {vg.name}"

    use_dm = None  # probed lazily: a contiguous-only VG never needs it
    existing_dm: Optional[List[DmDevice]] = None
    number = LV_NUMBER_BASE

    for vg in vgs:
        vg_devices = sorted(vg.pv_starts)
        activated: List[str] = []
        if not _LVM_NAME_RE.fullmatch(vg.name):
            logger.warning("Skipping VG with unsafe name %r", vg.name)
            continue

        for lv in vg.lvs:
            if not _LVM_NAME_RE.fullmatch(lv.name):
                logger.warning("Skipping LV with unsafe name %r in VG %s",
                               lv.name, vg.name)
                continue
            part = PartitionInfo(
                device=f"{vg.name}/{lv.name}", number=number,
                size_bytes=lv.extents * vg.extent_size,
                label=f"{vg.name}-{lv.name}", pt_name=f"{vg.name}/{lv.name}",
            )
            number += 1
            result.partitions.append(part)
            kind = classify(lv)

            if kind == "pool":
                part.skip_reason = (f"{_POOL_ATTRS[lv.attr[:1]]} - holds other "
                                    "LVs, not a filesystem")
                continue

            if kind == "direct":
                runs, reason = plan_linear(vg, lv)
                if "not in this image" in reason:
                    part.skip_reason = f"LV incomplete: {reason}"
                    logger.warning("LV %s/%s skipped: %s", vg.name, lv.name, reason)
                    continue
                if reason:
                    part.mount_error = f"cannot map LV: {reason}"
                    continue
                if len(runs) == 1:
                    # Contiguous: a plain offset loop, no device-mapper needed.
                    run = runs[0]
                    loop = _attach_offset_loop(run.device, run.dev_offset, run.length)
                    if not loop:
                        part.mount_error = "could not attach an offset loop"
                        continue
                    result.loops.append(loop)
                    part.device = loop
                    part.backing_loop = loop
                    part.window_bytes = run.length
                    logger.info("Exposed LV %s/%s -> %s (offset loop on %s)",
                                vg.name, lv.name, loop, run.device)
                    continue
                if use_dm is None:
                    use_dm = dm_available()
                if not use_dm:
                    what = "striped" if not runs else f"fragmented ({len(runs)} extent runs)"
                    part.mount_error = (f"LV is {what} and needs device-mapper, "
                                        "which this kernel does not provide")
                    logger.warning("LV %s/%s: %s", vg.name, lv.name, part.mount_error)
                    continue
                table, reason = build_dm_table(vg, lv)
                if not table:
                    part.mount_error = f"cannot map LV: {reason}"
                    continue
                name = dm_name(mount_id, vg, lv)
                node = _dm_create(name, dm_uuid_prefix(mount_id)
                                  + lv.uuid.replace("-", ""), table)
                if not node:
                    part.mount_error = "device-mapper table creation failed"
                    continue
                result.dm_devices.append(name)
                part.device = node
                logger.info("Exposed LV %s/%s -> %s (private dm table, %d "
                            "segment(s))", vg.name, lv.name, node, len(lv.segments))
                continue

            # kind == "activate": thin / RAID / mirror / cache / snapshot.
            if use_dm is None:
                use_dm = dm_available()
            if not use_dm:
                part.mount_error = ("LV type needs LVM activation (device-mapper), "
                                    "which this kernel does not provide")
                continue
            if existing_dm is None:
                existing_dm = dm_devices()
            clash = _vg_collides(vg, vgs, existing_dm)
            if clash:
                part.skip_reason = (f"needs LVM activation, refused to avoid a "
                                    f"name clash: {clash}")
                logger.warning("LV %s/%s not activated: %s", vg.name, lv.name, clash)
                continue
            node = _activate_lv(vg, lv, vg_devices)
            if not node:
                part.mount_error = "read-only LVM activation failed"
                continue
            activated.append(lv.name)
            part.device = node

        result.vgs.append(_vg_record(vg, vg_devices, activated))

    for part in result.partitions:
        if part.device.startswith("/dev/") and not (part.skip_reason or part.mount_error):
            # The preset VG-LV label is kept (blkid only fills an empty one):
            # it is what the analyst navigates by.
            _enrich_with_blkid(part)
    return result


def _activate_lv(vg: VolumeGroup, lv: LogicalVolume,
                 devices: List[str]) -> Optional[str]:
    """Activate one LV read-only through LVM, confined to the evidence devices."""
    try:
        r = _lvm("lvchange", devices, ["-ay", "-K", f"{vg.name}/{lv.name}"],
                 read_only_vg=vg.name)
    except Exception as e:
        logger.warning("lvchange failed for %s/%s: %s", vg.name, lv.name, e)
        return None
    node = f"/dev/mapper/{_lvm_dm_name(vg.name, lv.name)}"
    if r.returncode != 0 or not Path(node).exists():
        logger.warning("Read-only activation of %s/%s failed: %s", vg.name,
                       lv.name, (r.stderr or "").strip() or "no device node")
        return None
    logger.info("Activated LV %s/%s read-only via LVM -> %s", vg.name, lv.name, node)
    return node


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
def _remove_vg_leftovers(vg_uuid: str, pv_devices: List[str]) -> bool:
    """Remove dm devices of evidence VG *vg_uuid* that still sit on our devices.

    Covers LVs our own activation left behind and LVs the host's udev
    autoactivation brought up when the PV loop appeared. A device is only
    removed when everything under it is one of *pv_devices* or another device
    of the same VG, so a host VG that happens to share the UUID (an image of
    the analyst's own disk) is never touched.
    """
    prefix = "LVM-" + vg_uuid.replace("-", "")
    ours = {Path(d).name for d in pv_devices}
    for _ in range(8):  # stacked LVs (thin over pool over tdata) go top-down
        candidates = [d for d in dm_devices() if d.uuid.startswith(prefix)]
        if not candidates:
            return True
        kernels = {d.kernel for d in candidates}
        progress = False
        for dev in candidates:
            deps = _dm_deps(dev.name)
            if deps and all(dep in ours or dep in kernels for dep in deps):
                progress |= dm_remove(dev.name)
        if not progress:
            break
    left = [d.name for d in dm_devices() if d.uuid.startswith(prefix)]
    if left:
        logger.warning("Left device-mapper device(s) of VG %s in place: %s",
                       vg_uuid, ", ".join(left))
    return not left


def teardown(dm_names: Sequence[str], vgs: Sequence[dict]) -> bool:
    """Undo :func:`expose_logical_volumes` (offset loops are the caller's)."""
    ok = True
    for name in reversed(list(dm_names or [])):
        if not dm_remove(name):
            ok = False
    for rec in vgs or []:
        name, uuid = rec.get("name", ""), rec.get("uuid", "")
        devices = _safe_devices(rec.get("pv_devices") or [])
        if rec.get("activated_lvs") and name and devices:
            try:
                r = _lvm("vgchange", devices, ["-an", name])
                if r.returncode != 0:
                    logger.warning("vgchange -an %s: %s", name,
                                   (r.stderr or "").strip())
            except Exception as e:
                logger.warning("Could not deactivate VG %s: %s", name, e)
        if uuid and devices and tool_exists("dmsetup"):
            if not _remove_vg_leftovers(uuid, devices):
                ok = False
        if name:
            logger.debug("Released LVM volume group %s", name)
    return ok


def deactivate_legacy(vg_names: Sequence[str], devices: Sequence[str]) -> None:
    """Deactivate VGs recorded by an older MountIR (names only, no UUIDs).

    The old code activated by bare name; deactivating the same way could take
    down a host VG of the same name, so the command is confined to the image's
    own devices.
    """
    devices = _safe_devices(devices)
    if not devices:
        logger.warning("Not deactivating legacy LVM VG(s) %s: no recorded "
                       "devices to confine the command to", ", ".join(vg_names))
        return
    for name in vg_names:
        if not _LVM_NAME_RE.fullmatch(name or ""):
            continue
        try:
            _lvm("vgchange", devices, ["-an", name])
        except Exception as e:
            logger.warning("Could not deactivate VG %s: %s", name, e)


def orphan_dm_devices(mount_ids: Iterable[str]) -> List[str]:
    """Names of MountIR dm tables belonging to *mount_ids* (for ``clean``)."""
    prefixes = tuple(dm_uuid_prefix(m) for m in mount_ids if m)
    if not prefixes:
        return []
    return [d.name for d in dm_devices() if d.uuid.startswith(prefixes)]
