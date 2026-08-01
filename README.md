# MountIR

```
    __  ___                  __  ________
   /  |/  /___  __  ______  / /_/  _/ __ \
  / /|_/ / __ \/ / / / __ \/ __// // /_/ /
 / /  / / /_/ / /_/ / / / / /__/ // _, _/
/_/  /_/\____/\__,_/_/ /_/\__/___/_/ |_|
```

**Forensic-grade disk image mounting for incident response.**

MountIR mounts disk images **read-only** so analysts can browse evidence
filesystems without altering them. It auto-detects the image format, mounts the
container, enumerates partitions (including LVM), and applies forensic mount
flags (`ro,noatime,noexec,norecovery`). It tracks every mount in a state file so
cleanup is reliable, and speaks JSON for pipeline orchestration.

> ⚠️ MountIR is a **Linux** tool and requires **root/sudo**. All mounts are
> read-only by default to preserve forensic integrity.

---

## Supported formats

| Format | Extensions | Primary tool | Fallback | Verified |
| --- | --- | --- | --- | --- |
| **E01 / L01** | `.e01`, `.l01` | `ewfmount` | – | ✅ |
| **Ex01 / Lx01** *(EWF v2)* | `.ex01`, `.lx01` | `ewfmount` † | – | ✅ |
| **DD / Raw / IMG** | `.dd`, `.raw`, `.img`, `.bin`, `.001` | `losetup` | – | ✅ |
| **VMDK** | `.vmdk` | `qemu-nbd` | `vmdkmount` | ✅ |
| **VHD / VHDX** | `.vhd`, `.vhdx` | `qemu-nbd` | `vhdimount` | ✅ |
| **QCOW2** | `.qcow2`, `.qcow` | `qemu-nbd` | – | ✅ |
| **VDI** *(VirtualBox)* | `.vdi` | `qemu-nbd` | – | ✅ |
| **AFF** | `.aff` | `affuse` | – | ✅ |
| **ISO** | `.iso` | `mount -o loop` | – | |

**✅ Verified** = confirmed mounted end-to-end against **real evidence images**:

- **E01** — validated on both a single-volume **NTFS** image (no partition
  table) and a partitioned **ext4** Linux image.
- **Ex01** *(EWF v2)* — validated end-to-end on a partitioned **XFS** Linux
  server image with a FUSE-enabled modern libewf.
- **DD / Raw / IMG** — validated via the `losetup` raw path, including a
  multi-filesystem disk (btrfs + ext4 + exFAT + NTFS); mounting each of those
  volumes depends on the host having their drivers.
- **VMDK** and **VDI** — validated on the same Android-x86 (LineageOS) guest
  exported to both formats; **ext4** volume mounted via `qemu-nbd`.
- **VHD** and **QCOW2** — validated on the same FreeBSD 15.1 UFS guest exported
  to both formats; GPT read, **ESP (vfat)** mounted, `freebsd-boot`/
  `freebsd-swap` correctly skipped. Mounting the **UFS** root additionally needs
  a UFS driver on the host — see [Filesystem drivers](#filesystem-drivers).
- **AFF** — validated on single-volume **NTFS** images via `affuse`.

Unmarked formats are implemented and covered by the unit-test suite, but have
not yet been confirmed against real-world samples — treat them as supported but
unverified until you've validated one in your environment.

> **† EWF v2 (Ex01/Lx01) needs modern libewf.** The distro `ewf-tools` package
> is the frozen 2014 *legacy* libewf line (`20140807`), which only reads EWF v1
> (E01/L01). `mountir setup` builds the maintained libyal release from source
> (pinned to `20240506`) so `ewfmount` can also open EnCase v7 Ex01/Lx01
> containers — see [Built from source](#built-from-source).

Detection uses the file extension first, then falls back to `file(1)` magic
bytes, so correctly-formatted images with the wrong extension still mount.
Multi-segment EWF sets (`.E01`/`.E02`/…) and split raw (`.001`/`.002`/…) are
handled automatically — just point MountIR at the first segment.

**Logical evidence files** (`.L01`/`.Lx01`) hold a reconstructed file/folder
tree rather than a disk image, so MountIR mounts them with `ewfmount -f files`:
the acquired files appear directly under the container mount and there is no
partition table to enumerate. Physical images (`.E01`/`.Ex01`) instead expose a
raw device (`ewf1`) that partition detection then walks.

<details>
<summary>Additional formats the engine also handles</summary>

AFF4 (`.aff4`), OVA (`.ova`), Apple DMG (`.dmg`) and sparseimage/sparsebundle,
and Xen XVA (`.xva`). These ship with handlers but are outside the core IR set
above; tool availability varies by distro.
</details>

---

## Features

- **Read-only by default** — forensic mount flags `ro,noatime,noexec,norecovery`
  applied per filesystem.
- **Browsable without `sudo`** — mounts need root, but *reading* the evidence
  afterwards shouldn't. A FUSE mount is visible only to the UID that created it
  unless `allow_other` is set, so a root-made mount would make every `ls` need
  `sudo` — and confusingly only on the FUSE-backed volumes, while the kernel
  mounts beside them stayed readable. MountIR passes `allow_other` to every FUSE
  driver it drives (`ewfmount`, `affuse`, `vmdkmount`, `vhdimount`, `apfs-fuse`,
  `vmfs-fuse`, `fuse-ufs`), falling back to a root-only mount if a build refuses
  the option rather than failing the mount.
- **Batch / directory mounting** — point MountIR at several images, shell globs,
  or a whole folder and it mounts each one (skipping continuation segments and
  VMDK extents so multi-part sets mount once).
- **Best-effort `--force` mode** — survives corrupt/absent partition tables and
  brute-forces the filesystem type regardless of OS, the scaffold for edge
  devices, odd appliances, and unfamiliar disk types.
- **Automatic format detection** via extension + `file(1)` magic.
- **Robust filesystem detection** — probes each partition with `blkid -p`
  (low-level, works on freshly-attached loop devices), falling back to `lsblk`
  and `file(1)` magic, then mounts with driver fallbacks (e.g. `ntfs3` →
  `ntfs-3g`) and a final auto-detect attempt. Reports a best-effort **OS guess**
  (Windows / Linux / macOS).
- **Partition detection** with `fdisk`/`blkid`, plus **LVM** discovery and
  activation. Slices the partition table marks as non-filesystem (`freebsd-boot`
  bootcode, `freebsd-swap`, Linux swap, BIOS boot, MSR, extended containers) are
  reported as **skipped**, not as mount failures, so the warning count means
  what it says.
- **Oversized-filesystem recovery** — when a filesystem's superblock claims more
  space than its partition-table entry allows, every driver refuses the mount
  outright. MountIR reads the claimed extent from the superblock (ext2/3/4,
  btrfs, XFS, exFAT, NTFS) and re-exposes the partition over that full range,
  capped at the end of the media, so the volume mounts. The widened window is
  logged and listed in the summary — it can overlap neighbouring partitions.
- **Actionable mount errors** — the real diagnosis is reported instead of
  mount(8)'s "see dmesg" boilerplate: a missing driver is named as such (with
  how to install it), a filesystem that outgrows the media is named as
  truncation, and an otherwise-opaque failure carries the kernel's own
  ring-buffer message.
- **State tracking** — every mount is recorded so `unmount` and `list` are
  reliable, and stale mounts (e.g. after a reboot) are flagged. `clean`
  scavenges orphaned mounts from the mount base.
- **JSON I/O** for orchestration (Whirlpool).
- **Self-bootstrapping** — on first run MountIR pulls every dependency it can
  (see below).

---

## Requirements

- **Linux** (Debian/Ubuntu recommended for automatic dependency install).
- **Python 3.8+**.
- **root / sudo** for `mount` and `unmount`.

### Why root is required

Mounting evidence is a privileged kernel operation — `mount(2)`, loop devices
(`losetup`), the NBD module (`qemu-nbd`/`modprobe nbd`), `kpartx`, and LVM all
need `CAP_SYS_ADMIN`. There is **no way around this**: `mount` and `unmount`
must run as root, and aliasing or symlinking `mountir` changes only the command
*name*, not the privileges — you will still run `sudo mountir mount …`.

The read-only commands **`list`** and **`check`** do **not** need root.

| Command | Root needed? |
| --- | --- |
| `mount`, `unmount`, `clean` | ✅ yes (`sudo`) |
| `setup` / `install-deps` | ✅ yes (installs apt packages) |
| `list`, `check` | ❌ no |

---

## Installation & first run

```bash
# Clone or copy the project so the package directory is named "MountIR"
cd /opt   # (anywhere on your PATH-able tree)
git clone <repo> MountIR

# First run pulls ALL dependencies automatically (Python + system tools):
sudo python3 MountIR/mountir.py setup
```

**On its first invocation MountIR bootstraps itself.** It will:

1. **Create a project-local virtualenv** (`.venv/`) and install the pinned
   Python dependencies **into it** — never into the system/root interpreter, so
   it won't pollute the OS Python or trip PEP 668
   (`externally-managed-environment`) on modern Debian/Ubuntu.
2. **Re-launch itself inside that venv** so the dependencies load from there.
3. `apt-get install` any missing system forensic tools (E01, qemu, AFF, …).

The venv lives in the project directory and is reused on later runs (deps are
only installed when the venv is first created or via `setup`). A marker
(`/var/lib/mountir/.bootstrapped`, falling back to the project directory) records
that the system-tool step has run, so it only happens once. You can also trigger
the whole thing explicitly at any time:

```bash
sudo python3 mountir.py setup     # re-run the full dependency install
python3 mountir.py check          # report what is / isn't installed
```

**Opting out of auto-bootstrap:** pass `--no-setup` or set the environment
variable `MOUNTIR_NO_BOOTSTRAP=1`. MountIR then runs against the current
interpreter and skips both the venv and the system-tool install — in that case
install `colorama` yourself (optional; output just won't be coloured without it).

## Run `mountir` as a system command

So you can call `mountir` from anywhere instead of `python3 /path/to/mountir.py`,
put it on your `PATH`. **Recommended:** symlink the entry point into
`/usr/local/bin` (already on every user's `PATH`):

```bash
sudo chmod +x /opt/MountIR/mountir.py   # a fresh `git clone` already sets this;
                                        # a mode-preserving copy can drop it
sudo ln -s /opt/MountIR/mountir.py /usr/local/bin/mountir
```

> **Tip:** deploy from a `git clone` (not a copy). A mode-preserving `rsync -p`/
> `cp -p` can strip the executable bit and leave `mountir` as "command not
> found"; a clone keeps it, and updates are just `sudo git -C /opt/MountIR pull`.

The script's shebang (`#!/usr/bin/env python3`) and `__file__` resolution handle
the rest — the symlink resolves back to the real project, finds its `.venv`, and
re-launches inside it automatically. Now:

```bash
sudo mountir mount /evidence/disk.E01     # mount/unmount need root
mountir list                              # list/check do not
mountir check
```

> **You still need `sudo` for `mount`/`unmount`.** The symlink only renames the
> command; it can't grant privileges. See [Why root is required](#why-root-is-required).

### Optional: a `mountir` that elevates itself

If you'd rather not type `sudo` for mounts, install a small wrapper that elevates
only when needed. Replace the symlink above with:

```bash
sudo tee /usr/local/bin/mountir >/dev/null <<'EOF'
#!/usr/bin/env bash
# Run privileged subcommands under sudo automatically.
case "$1" in
  mount|unmount|setup|install-deps)
    [ "$(id -u)" -ne 0 ] && exec sudo /opt/MountIR/mountir.py "$@" ;;
esac
exec /opt/MountIR/mountir.py "$@"
EOF
sudo chmod +x /usr/local/bin/mountir /opt/MountIR/mountir.py
```

Now `mountir mount /evidence/disk.E01` prompts for `sudo` itself, while
`mountir list` / `check` run unprivileged. (A passwordless alternative is a
`sudoers` `NOPASSWD` rule for the script — only if your environment allows it.)

> **Shell `alias` won't work for this** — aliases aren't expanded after `sudo`,
> and they only exist in interactive shells. Use a symlink or wrapper in
> `/usr/local/bin` as above.

---

## Dependencies

All dependencies are **pinned**. Python deps live in `requirements.txt`
(runtime) and `requirements-dev.txt` (tests), and are installed into the
project-local `.venv/` by the first-run bootstrap (or `mountir setup`).

### Python packages

| Package | Version | Purpose |
| --- | --- | --- |
| `colorama` | `0.4.6` | Cross-platform coloured terminal output |
| `pytest` *(dev)* | `9.0.3` | Test runner (`requirements-dev.txt`) |

`mountir setup` installs these into `.venv/` for you. To manage them manually:

```bash
python3 -m pip install -r requirements.txt        # runtime
python3 -m pip install -r requirements-dev.txt     # + tests
```

### System packages (apt)

Installed automatically by `mountir setup`. The canonical mapping lives in
[`bootstrap.py`](bootstrap.py) (`SYSTEM_PACKAGES`):

| Tool(s) | apt package | Used for |
| --- | --- | --- |
| `ewfmount` | `ewf-tools` | E01 / L01 (apt is the 2014 legacy line; Ex01/Lx01 need [modern libewf](#built-from-source)) |
| `qemu-nbd` | `qemu-utils` | VMDK, VHD/VHDX, QCOW2, VDI (primary) |
| `affuse` | `afflib-tools` | AFF |
| `vmdkmount` | `libvmdk-utils` | VMDK (fallback) |
| `vhdimount` | `libvhdi-utils` | VHD/VHDX (fallback) |
| `kpartx` | `kpartx` | Partition device mapping |
| `pvs` | `lvm2` | LVM detection / activation |
| `fusermount` | `fuse` | FUSE unmounting |
| `ntfs-3g` | `ntfs-3g` | NTFS mounting |
| `vmfs-fuse` | `vmfs-tools` | VMware **VMFS3/5** datastores |
| `vmfs6-fuse` | `vmfs6-tools` | VMware **VMFS6** datastores (ESXi 6.5+; not in every distro's repos) |
| `mount.exfat-fuse` | `exfat-fuse` | exFAT on kernels without `CONFIG_EXFAT_FS` |
| `mmls` | `sleuthkit` | Partition layout |
| `fdisk`, `blkid`, `losetup`, `mount` | `util-linux` | Loop devices, partitions, mounting |
| `file` | `file` | Magic-byte format detection |

Manual install on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install ewf-tools qemu-utils afflib-tools libvmdk-utils \
                     libvhdi-utils kpartx lvm2 fuse ntfs-3g sleuthkit \
                     util-linux file
```

### Filesystem drivers

Mounting a *container* (E01, VMDK, QCOW2, …) and mounting the *filesystems*
inside it are separate problems: MountIR can always open the container, but the
volume only mounts if this host has a driver for that filesystem. MountIR checks
`/proc/filesystems`, tries `modprobe` (many distros ship `ufs`/`exfat` as
modules that are only loaded on first use), then falls back to a FUSE driver —
and when nothing can mount it, says so by name instead of reporting a generic
failure.

| Filesystem | In-kernel | Userspace fallback | Notes |
| --- | --- | --- | --- |
| ext2/3/4, XFS, btrfs, vfat, ISO9660 | ✅ everywhere | – | |
| NTFS | `ntfs3` (5.15+) | `ntfs-3g` | |
| exFAT | `exfat` (5.4+) | `mount.exfat-fuse` | |
| **UFS** *(FreeBSD, pfSense, NetScaler)* | `ufs` — **optional module** | `fuse-ufs` | opt-in, see below |
| APFS | – | `apfs-fuse` | built from source |
| VMFS3/5/6 | – | `vmfs-fuse`, `vmfs6-fuse` | |

**UFS needs a driver you may not have.** The Linux `ufs` driver is not built
into every kernel. On Ubuntu it lives in `linux-modules-extra-$(uname -r)`; the
**Microsoft WSL2 kernel omits it entirely and ships no loadable modules at all**,
so a FreeBSD image mounts its ESP but not its UFS root there. Either run on a
kernel that has it:

```bash
sudo apt-get install linux-modules-extra-$(uname -r) && sudo modprobe ufs
```

or install the userspace driver, which MountIR then uses automatically:

```bash
sudo mountir setup --ufs
```

This is **opt-in** rather than part of the normal `mountir setup`, because
[`fuse-ufs`](https://github.com/asomers/fuse-ufs) is a Rust crate and building
it needs a cargo toolchain — too heavy a dependency to install unasked. MountIR
uses the cargo you already have (including the one `sudo` hides in your own
`~/.cargo/bin`) and installs the binary to `/usr/local/bin/fuse-ufs`. If no
cargo is found it tells you so instead of installing a toolchain behind your
back:

```bash
sudo apt-get install cargo        # or rustup, from https://rustup.rs
sudo mountir setup --ufs
```

`mountir check` reports which provider each filesystem will actually use —
`[kernel]` or the helper binary — so you can confirm UFS before you need it.

### Built from source

Two drivers aren't in apt (or are too old there), so `mountir setup` builds them
from source into `/usr/local/bin` — best-effort, so a failed optional build
warns but never aborts setup:

| Tool | Source | Adds |
| --- | --- | --- |
| `apfs-fuse` | [sgan81/apfs-fuse](https://github.com/sgan81/apfs-fuse) | read-only APFS (macOS) — no apt package exists |
| `ewfmount` *(libewf)* | [libyal/libewf](https://github.com/libyal/libewf) | EWF v2 **Ex01/Lx01** — apt ships only the 2014 legacy line |
| `fuse-ufs` † | [asomers/fuse-ufs](https://github.com/asomers/fuse-ufs) | UFS1/UFS2 on kernels without the `ufs` driver — **opt-in**, `mountir setup --ufs` |

> **† `fuse-ufs` is opt-in.** It is a Rust crate, so it needs a cargo toolchain
> — a heavy dependency to install unprompted. Plain `mountir setup` skips it and
> just notes that UFS relies on the kernel driver.

The from-source `ewfmount` lands in `/usr/local/bin` and shadows the apt one.
The build links **FUSE** (via `libfuse-dev`) so `ewfmount` can actually *mount*,
not just read: `mountir setup` builds from a clean tree, forces the reliable
**fuse2** path (libewf's fuse3 autodetect can produce a mount-incapable binary),
and **verifies the built `ewfmount` links FUSE before reporting success** — a
FUSE-less build is treated as a failure with the fix, never silently accepted.
The libewf build is **pinned to `20240506`** for forensic reproducibility (you
want to know exactly which tool version touched the evidence). To pull a
different release, set the version and force a rebuild over the existing install:

```bash
sudo MOUNTIR_LIBEWF_VERSION=20240506 mountir setup --force
```

> ⚠️ Bumping libewf is deliberate: a newer upstream release may change tool
> behaviour or fail to build. The pin is the tested default — only override it
> if you specifically need another version.

`mountir check` reports the `ewfmount` version, whether it's **modern *and*
FUSE-capable** (so Ex01/Lx01 can actually mount, not merely be read — a
FUSE-less build is flagged as broken), the **exact binary path** MountIR will
invoke, and per-driver filesystem coverage including **VMFS3/5** vs **VMFS6**.

> **MountIR always uses the newest `ewfmount` it can find.** A source-built
> modern `ewfmount` lands in `/usr/local/bin` alongside the frozen apt build in
> `/usr/bin`. Because `sudo` resets `PATH` to its `secure_path`, the legacy
> `/usr/bin` build can end up first on `PATH` and silently fail to open an
> Ex01/Lx01 image. To avoid that, MountIR scans every `ewfmount` on the system,
> picks the highest version, and invokes it by full path — so EWF2 images mount
> with the modern build regardless of `PATH`/`secure_path` ordering. When you
> hand it an Ex01/Lx01 image but only a legacy build is present, it warns up
> front with the fix (`mountir setup`) instead of failing opaquely.

---

## Usage

Invoke MountIR in any of these equivalent ways:

```bash
sudo python3 mountir.py <command> ...        # direct
sudo python3 -m MountIR.mountir <command> ... # as a module (run from parent dir)
sudo mountir <command> ...                    # if symlinked onto PATH
```

### Mount a forensic disk image

```bash
sudo mountir mount <image|dir|glob> [<more> ...] \
  [-d|--mount-base DIR] [-r|--recursive] [--pattern GLOB] [--force] \
  [--case-id ID] [--no-partitions] \
  [--json-input FILE] [-v] [--json]
```

The positional argument accepts **one or more** images, shell globs, and/or
**directories**. A directory is scanned for every recognised image inside it, so
a whole evidence folder mounts in one command (continuation segments such as
`.E02`/`.002` and VMDK split extents are skipped so a multi-part set mounts once,
from its first file). Each image is mounted independently under its own
`<mount-base>/<mount-id>` tree; a failure on one image is logged and the rest
still mount.

| Option | Description |
| --- | --- |
| `-d`, `--mount-base`, `--dir DIR` | Base directory for mount points (default `/mnt/mountir`) |
| `-r`, `--recursive` | When a directory is given, scan it **recursively** for images |
| `--pattern GLOB` | When scanning a directory, only mount files matching this glob (e.g. `'*.E01'`) |
| `--force`, `--best-effort` | **Mount anyway**: survive a corrupt/absent partition table and brute-force the filesystem type regardless of OS (see [Best-effort mounting](#best-effort-mounting----force)) |
| `--case-id ID` | Case identifier, used in mount-point naming |
| `--no-partitions` | Mount the container only; skip partition detection |
| `--json-input FILE` | Read the mount request from a JSON file (`-` = stdin) |
| `-v`, `--verbose` | Verbose logging |
| `--json` | Emit machine-readable JSON to stdout (a single image emits one object; several emit `{"mounts": [...]}`) |

```bash
# A single image
sudo mountir mount /evidence/laptop.E01

# Every image in a folder (recursively), into a custom base dir
sudo mountir mount /evidence/case42/ -r -d /mnt/case42

# Only the EnCase sets in a folder
sudo mountir mount /evidence/ --pattern '*.E01'

# Several images at once
sudo mountir mount /evidence/a.Ex01 /evidence/b.vmdk /evidence/c.dd
```

#### Best-effort mounting (`--force`)

`--force` (alias `--best-effort`) is for **damaged, exotic, or unknown** media —
edge devices, odd appliances, corrupt acquisitions:

- A **corrupt or missing partition table** no longer aborts the image: the whole
  disk is exposed as a single read-only loop device so it can be mounted or
  carved.
- The filesystem type is **brute-forced regardless of OS** — every known driver
  (NTFS, ext, XFS, Btrfs, exFAT/FAT, HFS+, UFS, APFS/VMFS via FUSE) is tried
  read-only, plus dirty-volume flags for journaled volumes that weren't cleanly
  unmounted.
- Anything that still can't be mounted has its **raw block device reported** in
  the summary so you can image or carve it directly.

All `--force` mounts remain strictly **read-only**; it widens *what* MountIR will
attempt, never *how* it touches the evidence.

### Unmount a mounted image

```bash
sudo mountir unmount <mount-id-or-path> [-v] [--json]
sudo mountir unmount --all                      # unmount everything
```

### List mounted images

```bash
mountir list [-d|--mount-base DIR] [-v] [--json]
```

By default `list` shows every tracked mount. Pass `-d DIR` to show only the
images mounted under that base directory (matching how you mounted them with
`mount -d DIR`).

### Clean up orphaned mounts

```bash
sudo mountir clean                       # release & remove everything under /mnt/mountir
sudo mountir clean -d /mnt/case42        # clean a custom base
sudo mountir clean --mount-base DIR      # (long form of -d)
```

Unmounts anything still mounted under the base (deepest-first, with a lazy
fallback), detaches the backing loop devices, removes the leftover directories,
and prunes stale state entries. It refuses to run against system paths like `/`
or `/mnt` unless you pass `--force`.

### Check / install dependencies

```bash
mountir check            # report tool availability
sudo mountir setup       # install all dependencies (Python + system tools)
```

---

## Example

```bash
# Mount an EnCase Ex01 image for case IR-2026-001
sudo mountir mount /evidence/laptop.Ex01 --case-id IR-2026-001 -v

# See what is mounted
mountir list

# Tear it down when finished
sudo mountir unmount IR-2026-001_laptop_a1b2c3
```

### Mount layout

Each mount is created under `--mount-base` in a self-describing tree:

```
/mnt/mountir/<mount-id>/
├── container/                 # FUSE/raw container (e.g. ewf1)
└── partitions/
    ├── p1_ntfs_Windows/       # partition 1, NTFS, label "Windows"
    └── p2_ext4_root/          # partition 2, ext4, label "root"
```

---

## JSON orchestration

`mount --json-input` accepts a request document (file or stdin) so MountIR can be
driven by upstream tools such as Whirlpool:

```json
{
  "image_path": "/evidence/disk.E01",
  "case_id": "IR-2026-001",
  "mount_base": "/mnt/case001",
  "mount_options": { "no_partitions": false }
}
```

`mount --json` and `list --json` emit structured results on stdout (human-
readable status always goes to stderr, keeping stdout clean for pipelines).

---

## State & logs

| Artifact | Location (preferred → fallback) |
| --- | --- |
| Mount state | `/var/lib/mountir/mountir_state.json` → project dir |
| Bootstrap marker | `/var/lib/mountir/.bootstrapped` → project dir |
| Logs | `../logs/mountir_<timestamp>.log` → `./logs` → `/tmp` |

`list` cross-checks `/proc/mounts` and flags entries that are no longer mounted
as `[STALE]`; clear them with `unmount --all`.

---

## Troubleshooting & cleanup

### "Failed to FUSE-unmount" / unmount leaves things behind

The most common cause is a **shell or process sitting inside the mount** — you
can't unmount a filesystem while something is using it. If your prompt is inside
`/mnt/mountir/<id>/…`, that's the culprit.

```bash
cd ~                                  # leave the mount FIRST
sudo mountir unmount --all            # now it can release cleanly
```

MountIR now falls back to a **lazy unmount** when a mount is busy, so cleanup
generally succeeds even if something is still attached (you'll see a
`Lazy-unmounted busy …` warning). Always `cd` out anyway — it's the real fix.

### Cleaning up stale mounts under the mount base

The easy way — let MountIR scavenge its own mount base:

```bash
cd ~                                  # don't be inside the mount
sudo mountir clean                    # release & remove everything under /mnt/mountir
mountir list                          # should now be empty
```

`clean` unmounts deepest-first (lazily if busy), detaches backing loop devices,
removes the leftover directories, and prunes stale state. It only touches the
mount base you give it and refuses system paths unless `--force` is passed.

#### Manual cleanup (other tools / paths MountIR doesn't track)

First, **look before you delete:**

```bash
findmnt -R /mnt                       # tree of everything mounted under /mnt
```

> ⚠️ Do **not** touch system mounts such as `/mnt/wsl`, `/mnt/wslg`, or
> `/mnt/c` (WSL/host). Only clean up mount points you created for evidence.

```bash
# Unmount deepest-first (partitions before their container)
sudo umount -R /mnt/<dir> 2>/dev/null || sudo umount -l /mnt/<dir>/container

# Detach any loop devices still pointing at the image
losetup -a                            # find the /dev/loopN for your image
sudo losetup -d /dev/loopN

# Remove empty mount-point dirs (rmdir refuses if still mounted — that's a safety net)
sudo rmdir /mnt/<dir>/partitions/* 2>/dev/null
sudo rmdir /mnt/<dir>/{partitions,container} /mnt/<dir>
```

Use `rmdir` (not `rm -rf`) on mount-point directories: it fails safely if a path
is still mounted, so you can't accidentally delete into a live evidence mount.
Confirm a path is unmounted with `mountpoint -q /mnt/<dir>/container`.

---

## Testing

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

The suite is hermetic (subprocess/`shutil.which` are mocked), so it runs on any
platform without the forensic tools installed. To skip the first-run bootstrap
while developing, set `MOUNTIR_NO_BOOTSTRAP=1`.

---

## Project layout

```
MountIR/
├── mountir.py        # CLI entry point (mount / unmount / list / check / setup)
├── bootstrap.py      # dependency declarations + first-run install
├── detector.py       # format detection (extension + magic)
├── handlers/         # one mount handler per format
├── partition.py      # partition + LVM detection / mounting
├── state.py          # JSON mount-state persistence
├── utils.py          # logging, subprocess, tool checks, NBD/FUSE helpers
├── requirements.txt  # pinned runtime deps
├── requirements-dev.txt
├── .venv/            # project virtualenv (created on first run; git-ignored)
└── tests/            # pytest suite
```

---

## Safety notes

- Every mount uses `ro` plus `noatime,noexec,norecovery`; NTFS/HFS recovery is
  suppressed so the source image is never written to.
- MountIR never writes to the evidence image. Temporary conversions (DMG,
  split-raw, etc.) are written to throwaway `mountir_*` temp directories and
  cleaned up on unmount.
- Always `unmount` (or `unmount --all`) before detaching evidence media.
```
