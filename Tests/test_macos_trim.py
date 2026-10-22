#!/usr/bin/env python3
"""End-to-end test of "Unmount with TRIM" on macOS, on scratch disk images only.

Creates a zero-filled disk image, so that the blocks TRIM releases can be
counted, attaches it through DiskImages2 (which punches holes in the image file
on UNMAP), partitions it and creates a normal VeraCrypt volume on the partition.
Each scenario formats the volume with newfs_exfat through the virtual device,
populates it, reads the allocation bitmap with an independent exFAT reader (the
oracle) and runs `veracrypt --unmount --trim`. It then checks on the host that
only free clusters changed, that they read as zeros and were freed in the image
file, that both header groups are unchanged, that the reported amount is right,
and that the filesystem passes fsck_exfat with every file intact. Refusal
scenarios check that nothing changed and that the volume is left mounted or
unmounted as the error message says.

Needs root and a TRIM-capable build (FUSE-T, or macFUSE with the FSKit backend;
the macFUSE kernel extension is refused and reported as SKIP). Never touches a
device that is not part of an image this test attached itself or of the volume
image VeraCrypt has just attached for it. --list and --oracle-selftest need no
root: the self-test checks the oracle against statfs, the directory tree, file
contents and fsck_exfat on plain exFAT images.

  sudo python3 Tests/test_macos_trim.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt" [--quick]
  python3 Tests/test_macos_trim.py --oracle-selftest [--random 20 --seed 1]
"""

import argparse
import errno
import fcntl
import hashlib
import itertools
import os
import plistlib
import random
import re
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

# Common/Volumes.h: a normal volume's data area starts after the primary header
# group and ends before the backup header group, the last 128 KiB of the host
HEADER_GROUP = 128 * 1024
DATA_OFFSET = 128 * 1024
HEADERS = 2 * HEADER_GROUP
RECORD_DIR = "/var/run/veracrypt"  # Core/Unix/CoreUnix.cpp: the mount records of device-hosted volumes
SECTOR = 512                       # digest granularity; DiskImages2 zero-fills 512-byte UNMAPs
IMAGE_BLOCK = 4096                 # DiskImages2 punches holes in the image file per 4 KiB
DI2_EDGE_CHUNK = 16384             # DiskImages2 zero-fills an unaligned UNMAP edge by rewriting its 16 KiB chunk, which stays allocated
TRIM_EXTENT = 1 << 30              # Core/Unix/CoreUnix.cpp MaxTrimExtentLength: VeraCrypt splits longer free runs
DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT = 0x40046418, 0x40086419     # sys/disk.h
F_PREALLOCATE, F_ALLOCATEALL, F_PEOFPOSMODE = 42, 4, 3            # sys/fcntl.h
CHUNK = 8 << 20
# Created by macOS, not by the scenarios; .fseventsd/no_log and .metadata_never_index
# stop the remounts from writing logs and indexes, which keeps the host unchanged
SYSTEM_NAMES = {".fseventsd", ".Spotlight-V100", ".Trashes", ".metadata_never_index", ".TemporaryItems"}
AUTH = ["--stdin", "--pim=1", "--keyfiles="]
# Core/Unix/CoreUnix.cpp, as root: the volume image VeraCrypt attaches as the virtual device lies in
# its auxiliary FUSE mount, $TMPDIR/.veracrypt_aux_mnt<N> (macFUSE; the test sets TMPDIR) or
# /private/tmp/.veracrypt_aux_root_<uid>-<random>/.veracrypt_aux_mnt-<random> (FUSE-T)
AUX_IMAGE = re.compile(r"/private/tmp/\.veracrypt_aux_(mnt\d+|root_\d+-\w{12}/\.veracrypt_aux_mnt-\w{12})/volume\.dmg")


class Failure(Exception):
    pass


class Skip(Exception):
    """Ends the whole run."""


class SkipScenario(Exception):
    pass


def sh(args, check=True, stdin=None, env=None, timeout=900):
    args = [str(a) for a in args]
    # Without --text as its first argument VeraCrypt opens GUI dialogs; veracrypt() adds it
    if os.path.basename(args[0]).lower() == "veracrypt" and args[1:2] != ["--text"]:
        raise Failure("refusing to run VeraCrypt without --text: %s" % args)
    result = subprocess.run(args, input=stdin, env=env, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise Failure("%s failed (%d):\n%s%s" % (" ".join(args), result.returncode,
                                                 result.stdout, result.stderr))
    return result


def veracrypt(binary, args, **kwargs):
    """Runs VeraCrypt in text mode, with every option as its own argument."""
    argv = [str(binary), "--text", "--non-interactive"] + [str(a) for a in args]
    if any(a.startswith("--") and re.search(r"\s", a) for a in argv):
        raise Failure("refusing to run VeraCrypt with %s: every option must be its own argument" % argv[1:])
    return sh(argv, **kwargs)


def list_entry(stdout, path):
    """The virtual device and mount point (None without a filesystem) that --list prints for path.
    Main/UserInterface.cpp ListMountedVolumes prints a mount point with spaces in quotes and
    doubles a quote in it (Platform/StringConverter.cpp QuoteSpaces)."""
    for m in re.finditer(r"^\d+: (\S+) +(\S+) +(.+?) *$", stdout, re.M):
        if m.group(1) == path:
            mountpoint = m.group(3)
            if mountpoint.startswith("'"):
                mountpoint = mountpoint[1:-1].replace("''", "'")
            return m.group(2), None if mountpoint == "-" else mountpoint
    return None, None


def plist(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=120)
    if result.returncode:
        raise Failure("%s failed: %s" % (" ".join(map(str, args)), result.stderr.decode(errors="replace")))
    return plistlib.loads(result.stdout)


def raw(device):
    return "/dev/r" + device[5:] if device.startswith("/dev/disk") else device


def device_size(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        block = struct.unpack("<I", fcntl.ioctl(fd, DKIOCGETBLOCKSIZE, bytes(4)))[0]
        return block * struct.unpack("<Q", fcntl.ioctl(fd, DKIOCGETBLOCKCOUNT, bytes(8)))[0], block
    finally:
        os.close(fd)


def reader(fd):
    """read(offset, length) on a device or file, at multiples of 512 bytes."""
    def read(offset, length):
        data = os.pread(fd, length, offset)
        if len(data) != length:
            raise Failure("short read at %d" % offset)
        return data
    return read


def merge(ranges):
    """Sorted, merged (start, end) ranges."""
    out = []
    for start, end in sorted(r for r in ranges if r[1] > r[0]):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def overlap(a, b):
    """Bytes in both lists of merged ranges."""
    total, i, j = 0, 0, 0
    while i < len(a) and j < len(b):
        total += max(0, min(a[i][1], b[j][1]) - max(a[i][0], b[j][0]))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def inward(ranges, block):
    return merge(((s + block - 1) // block * block, e // block * block) for s, e in ranges)


def subtract(a, b):
    """Merged ranges a without merged ranges b."""
    out, j = [], 0
    for start, end in a:
        while j < len(b) and b[j][1] <= start:
            j += 1
        k = j
        while k < len(b) and b[k][0] < end:
            if b[k][0] > start:
                out.append((start, b[k][0]))
            start = max(start, b[k][1])
            k += 1
        if start < end:
            out.append((start, end))
    return out


def expected_holes(ranges):
    """Image-file ranges that must be unallocated after VeraCrypt unmaps ranges: the 4 KiB-inward
    part of each extent, less the chunk around every unaligned edge of any extent, as a later
    extent's edge rewrite can allocate again the blocks that an earlier extent punched."""
    c = DI2_EDGE_CHUNK
    edges = {e for start, end in ranges for e in list(range(start, end, TRIM_EXTENT)) + [end]}
    return subtract(inward(ranges, IMAGE_BLOCK), merge((e // c * c, e // c * c + c) for e in edges if e % IMAGE_BLOCK))


def runs(numbers):
    """(first, count) of consecutive runs in sorted integers."""
    out = []
    for n in numbers:
        if out and out[-1][0] + out[-1][1] == n:
            out[-1] = (out[-1][0], out[-1][1] + 1)
        else:
            out.append((n, 1))
    return out


# ---------------------------------------------------------------------------
# The oracle: an exFAT reader written from the exFAT specification (Microsoft,
# "exFAT file system specification", sections 3, 4, 6 and 7), deliberately
# independent of Core/Unix/ExfatFreeSpace.h. It reads the boot region, the
# active FAT and allocation bitmap, and the whole directory tree, so that the
# bitmap can be checked against the clusters the tree actually uses.

class ExfatError(Exception):
    pass


class Exfat:
    def __init__(self, read):
        self.read = read
        boot = read(0, 512)
        if boot[3:11] != b"EXFAT   " or boot[510:512] != b"\x55\xaa":
            raise ExfatError("no exFAT boot sector")
        if not 9 <= boot[108] <= 12 or boot[108] + boot[109] > 25:
            raise ExfatError("sector or cluster size out of range")
        self.sector = 1 << boot[108]
        self.cluster = self.sector << boot[109]
        region = read(0, 12 * self.sector)
        checksum = 0                                      # section 3.4
        for i, byte in enumerate(region[:11 * self.sector]):
            if i not in (106, 107, 112):
                checksum = (((checksum & 1) << 31) + (checksum >> 1) + byte) & 0xFFFFFFFF
        if set(struct.unpack_from("<%dI" % (self.sector // 4), region, 11 * self.sector)) != {checksum}:
            raise ExfatError("boot region checksum mismatch")
        (self.volume_sectors, fat_offset, fat_length, heap, self.count, self.root_cluster,
         _, _, self.flags) = struct.unpack_from("<QIIIIIIHH", boot, 72)
        self.fats = boot[110]
        if self.fats not in (1, 2) or not 0 < self.count <= 0xFFFFFFF5:
            raise ExfatError("invalid FAT count or cluster count")
        self.active = self.flags & 1 if self.fats == 2 else 0
        self.heap = heap * self.sector
        self.problems = []
        self.owner = {}
        self.tree = {}
        entries = (self.count + 2) * 4
        self.fat_tables = [struct.unpack_from("<%dI" % (self.count + 2), read(
            (fat_offset + k * fat_length) * self.sector, -(-entries // self.sector) * self.sector))
            for k in range(self.fats)]
        self.fat = self.fat_tables[self.active]

        root = self.chain(self.root_cluster)
        self.root_bytes = len(root) * self.cluster
        self.claim(root, "<root directory>")
        self.bitmaps, self.upcase_length = [], None
        self.walk(root)

        active = [b for b in self.bitmaps if b[0] == self.active]
        if len(active) != 1:
            raise ExfatError("%d allocation bitmaps for FAT %d" % (len(active), self.active))
        for ident, first, length in self.bitmaps:
            clusters = self.chain(first, length, fat=self.fat_tables[min(ident, self.fats - 1)])
            self.claim(clusters, "<allocation bitmap %d>" % ident)
            if ident == self.active:
                self.bitmap_length, self.bitmap_clusters = length, clusters
                bitmap = self.read_clusters(clusters)
        if self.bitmap_length * 8 < self.count:
            raise ExfatError("allocation bitmap shorter than the cluster heap")
        # Bit n stands for cluster n + 2; 1 means allocated (section 7.1.5)
        self.bits = bytes(bitmap[n >> 3] >> (n & 7) & 1 for n in range(self.count))
        self.free_runs, n = [], self.bits.find(0)
        while n != -1:
            end = self.bits.find(1, n)
            end = self.count if end == -1 else end
            self.free_runs.append((n, end - n))
            n = self.bits.find(0, end) if end < self.count else -1
        self.free_bytes = sum(k for _, k in self.free_runs) * self.cluster
        self.free_but_used = sorted(c for c in self.owner if not self.bits[c - 2])
        self.lost = [n + 2 for n in range(self.count) if self.bits[n] and n + 2 not in self.owner]
        if self.free_but_used:
            c = self.free_but_used[0]
            self.problems.append("%d clusters in use but free in the bitmap, first %d of %s"
                                 % (len(self.free_but_used), c, self.owner[c]))
        if self.lost:
            self.problems.append("%d allocated clusters belong to nothing, first %s" % (len(self.lost), self.lost[:4]))

    def offset(self, cluster):
        return self.heap + (cluster - 2) * self.cluster

    def read_clusters(self, clusters):
        return b"".join(self.read(self.offset(c), k * self.cluster) for c, k in runs(clusters))

    def chain(self, first, length=None, contiguous=False, fat=None):
        need = None if length is None else -(-length // self.cluster)
        if contiguous:
            out = list(range(first, first + need))
        else:
            fat, out, c = fat or self.fat, [], first
            while c != 0xFFFFFFFF:
                if not 2 <= c < self.count + 2 or len(out) > self.count:
                    raise ExfatError("cluster chain from %d leaves the heap or loops" % first)
                out.append(c)
                c = fat[c]
        if out and not (2 <= out[0] and out[-1] < self.count + 2):
            raise ExfatError("contiguous allocation at %d leaves the heap" % first)
        if need is not None and len(out) != need:
            self.problems.append("chain from %d has %d clusters for %d bytes" % (first, len(out), length))
        return out

    def claim(self, clusters, path):
        for c in clusters:
            if c in self.owner:
                self.problems.append("cluster %d belongs to %s and %s" % (c, self.owner[c], path))
            self.owner[c] = path

    def walk(self, root):
        stack = [("", root)]
        while stack:
            parent, clusters = stack.pop()
            data = self.read_clusters(clusters)
            i = 0
            while i + 32 <= len(data) and data[i]:          # 0x00 ends the directory
                kind = data[i]
                if not kind & 0x80 or kind & 0x40:            # unused, deleted, or a stray secondary
                    i += 32
                elif kind == 0x81 and not parent:             # allocation bitmap (7.1)
                    self.bitmaps.append((data[i + 1] & 1,) + struct.unpack_from("<IQ", data, i + 20))
                    i += 32
                elif kind == 0x82 and not parent:             # up-case table (7.2)
                    first, self.upcase_length = struct.unpack_from("<IQ", data, i + 20)
                    self.claim(self.chain(first, self.upcase_length), "<up-case table>")
                    i += 32
                elif kind == 0x83 and not parent:             # volume label
                    i += 32
                elif kind == 0x85 or kind & 0x20:             # file (7.4) or benign primary
                    count = data[i + 1]
                    self.entry_set(parent, data[i:i + 32 * (count + 1)], stack)
                    i += 32 * (count + 1)
                else:
                    self.problems.append("unknown critical entry %#x in /%s" % (kind, parent))
                    i += 32

    def entry_set(self, parent, es, stack):
        if es[0] != 0x85:                                     # generic primary template (6.3)
            flags, first, length = struct.unpack_from("<H", es, 2)[0], *struct.unpack_from("<IQ", es, 20)
            if flags & 1 and first:
                self.claim(self.chain(first, length, flags & 2), "<entry %#x in /%s>" % (es[0], parent))
            return
        if len(es) < 64 or es[32] != 0xC0:
            self.problems.append("file entry without stream extension in /%s" % parent)
            return
        checksum = 0                                          # 6.3.3
        for i, byte in enumerate(es):
            if i not in (2, 3):
                checksum = (((checksum & 1) << 15) + (checksum >> 1) + byte) & 0xFFFF
        attributes = struct.unpack_from("<H", es, 4)[0]
        flags, name_length = es[33], es[35]
        valid, first, size = struct.unpack_from("<Q", es, 40)[0], *struct.unpack_from("<IQ", es, 52)
        name = b"".join(es[k + 2:k + 32] for k in range(64, len(es), 32) if es[k] == 0xC1)
        name = name[:2 * name_length].decode("utf-16-le", "surrogatepass")     # NameLength counts UTF-16 units
        path = parent + "/" + name if parent else name
        if checksum != struct.unpack_from("<H", es, 2)[0]:
            self.problems.append("entry set checksum mismatch for %s" % path)
        try:
            clusters = self.chain(first, size, flags & 2) if flags & 1 and first else []
            for k in range(64, len(es), 32):                  # other secondaries (6.4): vendor allocations
                if es[k] not in (0xC0, 0xC1) and es[k] & 0x80 and es[k + 1] & 1:
                    self.claim(self.chain(*struct.unpack_from("<IQ", es, k + 20), es[k + 1] & 2), path + ":%#x" % es[k])
        except ExfatError as e:
            self.problems.append("%s: %s" % (path, e))
            clusters = []
        self.claim(clusters, path)
        self.tree[path] = SimpleNamespace(dir=bool(attributes & 0x10), size=size, valid=valid,
                                          nofat=bool(flags & 2), clusters=clusters)
        if attributes & 0x10:
            stack.append((path, clusters))

    def digest(self, path):
        """SHA-256 of a file's content: on-disk bytes up to ValidDataLength, zeros after (7.6.4)."""
        entry, h, pos = self.tree[path], hashlib.sha256(), 0
        for c, k in runs(entry.clusters):
            for off in range(0, k * self.cluster, CHUNK):
                if pos >= entry.size:
                    break
                take = min(CHUNK, k * self.cluster - off, entry.size - pos)
                disk = max(0, min(take, entry.valid - pos))
                h.update(self.read(self.offset(c) + off, -(-disk // self.sector) * self.sector)[:disk] if disk else b"")
                h.update(bytes(take - disk))
                pos += take
        return h.hexdigest() if pos == entry.size else None

    def free_ranges(self):
        """Free clusters as (start, end) byte offsets in the filesystem."""
        return [(self.offset(n + 2), self.offset(n + 2 + k)) for n, k in self.free_runs]

    def unsupported(self):
        """Why VeraCrypt's parser documents it refuses this filesystem, or None: from the
        limits stated in Core/Unix/ExfatFreeSpace.h, not from its code."""
        if self.fats != 1 or self.flags & 1:
            return "two FATs (TexFAT)"
        if self.flags & 6:
            return "marked dirty or media failure"
        if not -(-self.count // 8) <= self.bitmap_length < -(-self.count // 8) + self.cluster:
            return "allocation bitmap length"
        if self.upcase_length is None or not 16 <= self.upcase_length <= 131072:
            return "up-case table length"
        if self.root_bytes > 256 << 20:
            return "root directory larger than 256 MiB"
        return None


def snapshot(root, everything=False):
    """{relative path: None for a directory, (size, sha256) for a file}, without the
    files macOS creates by itself unless `everything`. macOS stores exFAT names in NFC
    and returns them in NFD; the paths are in NFC, as on disk."""
    out = {}
    for parent, dirs, files in os.walk(root):
        rel = os.path.relpath(parent, root)
        if not everything:
            dirs[:] = [d for d in dirs if not d.startswith("._") and (rel != "." or d not in SYSTEM_NAMES)]
            files = [f for f in files if not f.startswith("._") and (rel != "." or f not in SYSTEM_NAMES)]
        for d in dirs:
            out[unicodedata.normalize("NFC", os.path.normpath(os.path.join(rel, d)))] = None
        for f in files:
            path = unicodedata.normalize("NFC", os.path.join(parent, f))
            h = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                while True:
                    data = os.read(fd, CHUNK)
                    if not data:
                        break
                    h.update(data)
            finally:
                os.close(fd)
            out[os.path.relpath(path, unicodedata.normalize("NFC", root))] = (os.lstat(path).st_size, h.hexdigest())
    return out


def tree_difference(want, got):
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    changed = sorted(p for p in set(want) & set(got) if want[p] != got[p])
    parts = ["%s %d: %s" % (what, len(paths), ", ".join(paths[:3])) for what, paths in
             (("missing", missing), ("unexpected", extra), ("changed", changed)) if paths]
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Scenario generators. Each one populates a mounted filesystem through `Fs`;
# the expected tree is taken from the filesystem afterwards.

class Fs:
    def __init__(self, root, rng):
        self.root, self.rng, self.deleted = root, rng, set()
        st = os.statvfs(root)
        self.cluster, self.capacity = st.f_frsize, st.f_blocks * st.f_frsize

    def path(self, rel):
        return os.path.join(self.root, rel)

    def quiet(self):
        os.makedirs(self.path(".fseventsd"), exist_ok=True)
        for rel in (".fseventsd/no_log", ".metadata_never_index"):
            os.close(os.open(self.path(rel), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644))

    def open(self, rel, flags):
        os.makedirs(os.path.dirname(self.path(rel)), exist_ok=True)
        return os.open(self.path(rel), os.O_WRONLY | os.O_NOFOLLOW | flags, 0o644)

    def write(self, rel, size, offset=0, flags=os.O_CREAT | os.O_EXCL):
        """Writes size random bytes at offset; returns False when the volume filled up."""
        fd = self.open(rel, flags)
        try:
            pos = offset
            while pos < offset + size:
                pos += os.pwrite(fd, os.urandom(min(CHUNK, offset + size - pos)), pos)
            os.fsync(fd)
            return True
        except OSError as e:
            if e.errno != errno.ENOSPC:
                raise
            return False
        finally:
            os.close(fd)

    def append(self, rel, size):
        return self.write(rel, size, os.stat(self.path(rel)).st_size, os.O_CREAT)

    def truncate(self, rel, size):
        os.truncate(self.path(rel), size)

    def prealloc(self, rel, size):
        fd = self.open(rel, os.O_CREAT)
        try:
            fcntl.fcntl(fd, F_PREALLOCATE, struct.pack("<IiqqQ", F_ALLOCATEALL, F_PEOFPOSMODE, 0, size, 0))
            os.fsync(fd)
        finally:
            os.close(fd)

    def remove(self, rel):
        os.remove(self.path(rel))
        self.deleted.add(rel)

    def rmtree(self, rel):
        # macOS lists exFAT names in NFD but finds them for unlink in NFC only (shutil.rmtree fails)
        for parent, dirs, files in os.walk(self.path(rel), topdown=False):
            parent = unicodedata.normalize("NFC", parent)
            for n in files + dirs:
                path = os.path.join(parent, unicodedata.normalize("NFC", n))
                self.deleted.add(os.path.relpath(path, self.root))
                try:
                    (os.rmdir if n in dirs else os.remove)(path)
                except FileNotFoundError:
                    if not n.startswith("._"):      # AppleDouble files go with their file
                        raise
        os.rmdir(self.path(rel))
        self.deleted.add(rel)

    def rename(self, old, new):
        os.makedirs(os.path.dirname(self.path(new)), exist_ok=True)
        os.rename(self.path(old), self.path(new))
        self.deleted.add(old)

    def fill(self, prefix, size):
        """Files of `size` bytes, then single clusters into one more file, until ENOSPC.
        Returns the names in the order written."""
        names = []
        while True:
            names.append("%s%04d" % (prefix, len(names)))
            if not self.write(names[-1], size):
                break
        names.append("%s%04d" % (prefix, len(names)))
        self.write(names[-1], 0)
        while self.append(names[-1], self.cluster):
            pass
        return names


SCENARIOS = []
DEFAULTS = dict(quick=False, cluster=4096, size=64 << 20, newfs=[], after_newfs=None, fs="exfat", host="image",
                block=512, hold=None, mount=[], expect=None, corrupt=False, prop=None)


def scenario(name, **options):
    def register(populate):
        doc = options.pop("doc", None) or populate.__doc__.strip().splitlines()[0]
        SCENARIOS.append(dict(DEFAULTS, name=name, doc=doc, populate=populate, **options))
        return populate
    return register


def files(o):
    return {p: e for p, e in o.tree.items() if not e.dir}


def fragmented(clusters):
    return any(b != a + 1 for a, b in zip(clusters, clusters[1:]))


def standard(fs):
    """Files of 0, 1, cluster - 1, cluster and cluster + 1 bytes, multi-cluster files with half of them deleted, a deleted directory tree"""
    c = fs.cluster
    for s in (0, 1, c - 1, c, c + 1):
        fs.write("size-%d" % s, s)
    budget = (fs.capacity - 12 * c) // 3          # room for the directories with 32 MiB clusters
    for i in range(8):
        size = (i % 3 + 1) * c + 7 * i
        if size > budget:
            break
        budget -= size + c
        fs.write("data/%d" % i, size)
    for i in range(0, 8, 2):
        if os.path.exists(fs.path("data/%d" % i)):
            fs.remove("data/%d" % i)
    fs.write("gone/sub/x", min(2 * c + 3, budget))
    fs.rmtree("gone")


def edge_sizes_present(o):
    sizes = {e.size for e in files(o).values()}
    want = {0, 1, o.cluster - 1, o.cluster, o.cluster + 1}
    return want <= sizes, "file sizes %s" % sorted(want - sizes)


def large_free_run(o):
    ok, detail = edge_sizes_present(o)
    longest = max([k for _, k in o.free_runs] or [0]) * o.cluster
    return ok and longest > 1 << 30, "%s, longest free run %d bytes" % (detail, longest)


for _name, _c, _quick in (("512", 512, True), ("4k", 4096, True), ("128k", 131072, False), ("1m", 1 << 20, False)):
    scenario("cluster-" + _name, quick=_quick, cluster=_c, prop=edge_sizes_present)(standard)
scenario("cluster-32k", cluster=32768, size=1280 << 20, prop=large_free_run,
         doc="Standard files with 32 KiB clusters on 1.25 GiB, leaving a free run larger than 1 GiB, "
             "which VeraCrypt splits into extents of at most 1 GiB")(standard)
# macOS does not mount exFAT with 32 MiB clusters on 1.25 GiB (1.125 GiB works), too small for a 1 GiB free run
scenario("cluster-32m", cluster=32 << 20, size=1 << 30, prop=edge_sizes_present,
         doc="Standard files with 32 MiB clusters, the exFAT maximum")(standard)


@scenario("empty", prop=lambda o: (len(o.free_runs) <= 2 and o.free_bytes > 0.9 * o.count * o.cluster,
                                   "%d free runs, %d free bytes" % (len(o.free_runs), o.free_bytes)))
def empty(fs):
    """Freshly formatted filesystem: the whole cluster heap but the metadata is free"""


@scenario("full", quick=True, prop=lambda o: (o.free_bytes == 0, "%d bytes free" % o.free_bytes))
def full(fs):
    """Filled to ENOSPC, nothing deleted: nothing to trim, the host must stay unchanged"""
    fs.fill("fill/", 1 << 20)


def free_edges_present(o):
    r, n = o.free_runs, o.count
    middle = [k for first, k in r if n // 10 <= first < 9 * n // 10]
    return (bool(r) and r[0][0] < n // 10 and r[0][1] >= 64 and middle == [1] and sum(r[-1]) == n,
            "free runs %s ... %s of %d clusters" % (r[:3], r[-2:], n))


@scenario("free-edges", prop=free_edges_present)
def free_edges(fs):
    """Full but for a free run at the start of the cluster heap, exactly one free cluster in the middle and free runs up to its very end"""
    fs.write("first", 64 * fs.cluster)
    names = fs.fill("fill/", 1 << 20)
    fs.remove("first")
    fs.truncate(names[len(names) // 2], (1 << 20) - fs.cluster)
    for rel in names[-3:]:
        fs.remove(rel)


@scenario("many-runs", quick=True, prop=lambda o: (len(o.free_runs) > 300, "%d free runs" % len(o.free_runs)))
def many_runs(fs):
    """More than 300 separate free runs, more than one DKIOCUNMAP request of 256 extents"""
    for i in range(640):
        fs.write("r/%03d" % i, fs.cluster)
    for i in range(0, 640, 2):
        fs.remove("r/%03d" % i)


def fragmentation_present(o):
    chained = [p for p, e in files(o).items() if not e.nofat and fragmented(e.clusters)]
    contiguous = [p for p, e in files(o).items() if e.nofat and len(e.clusters) > 1]
    return bool(chained and contiguous), "%d fragmented FAT-chained, %d NoFatChain files" % (len(chained), len(contiguous))


@scenario("fragmented", quick=True, prop=fragmentation_present)
def fragmentation(fs):
    """Interleaved appends to eight files, half deleted (FAT-chained survivors), and large contiguous files"""
    for i in range(8):
        fs.write("frag/%d" % i, 0)
    for _ in range(24):
        for i in range(8):
            fs.append("frag/%d" % i, fs.rng.randint(1, 3) * fs.cluster - fs.rng.randint(0, 100))
    for i in range(1, 8, 2):
        fs.remove("frag/%d" % i)
    for i in range(3):
        fs.write("big/%d" % i, (3 << 20) + i)
    fs.remove("big/1")


def unwritten_present(o):
    c = o.cluster
    unwritten = [p for p, e in files(o).items() if e.valid < e.size]
    shrunk = sorted(e.size for p, e in files(o).items() if re.fullmatch(r"t/\d", p))
    return bool(unwritten) and shrunk == [0, 1, c - 1, c, c + 1, 5 * c + 3], \
        "%d files with ValidDataLength < DataLength, truncated sizes %s" % (len(unwritten), shrunk)


@scenario("unwritten", quick=True, prop=unwritten_present)
def unwritten(fs):
    """Allocated but unwritten clusters (growing ftruncate, F_PREALLOCATE, write past a gap) between freed runs; files shrunk to 0, 1, c - 1, c, c + 1 and 5c + 3 bytes"""
    c = fs.cluster
    fs.write("pad/0", 16 * c)
    fs.write("grow", 3 * c + 5)
    fs.truncate("grow", 40 * c)
    fs.write("pad/1", 16 * c)
    fs.write("prealloc", c // 2)
    fs.prealloc("prealloc", 32 * c)
    fs.write("pad/2", 16 * c)
    fs.write("gap", c, offset=24 * c + 17)
    fs.write("pad/3", 16 * c)
    for i in range(4):
        fs.remove("pad/%d" % i)
    sizes = (0, 1, c - 1, c, c + 1, 5 * c + 3)
    for i in range(len(sizes)):
        fs.write("t/%d" % i, 12 * c + 7)
        fs.write("n/%d" % i, 2 * c)
    for i, size in enumerate(sizes):
        fs.truncate("t/%d" % i, size)


LONG_NAME = ("Ünïcödé-日本語-\U0001F600-" * 20)[:120]


def directories_present(o):
    dirs = {p: e for p, e in o.tree.items() if e.dir}
    split = [p for p, e in dirs.items() if len(e.clusters) > 1 and fragmented(e.clusters)]
    depth = max(p.count("/") for p in o.tree)
    long_names = [p for p in o.tree if len(p.rsplit("/", 1)[-1].encode("utf-16-le")) > 200]
    return bool(split and depth >= 20 and long_names), \
        "fragmented directories %d, depth %d, long names %d" % (len(split), depth, len(long_names))


@scenario("directories", quick=True, prop=directories_present)
def directories(fs):
    """A fragmented multi-cluster directory, deep nesting, long Unicode names, renames, moves, deleted trees"""
    c = fs.cluster
    for i in range(160):                    # 160 entry sets of 3 entries: 15 clusters of 4 KiB
        fs.write("wide/entry-%03d" % i, 0)
        if i % 20 == 0:
            fs.write("between/%d" % i, 2 * c)   # takes the clusters after each directory cluster
    deep = "/".join("level%02d" % i for i in range(24))
    fs.write(deep + "/leaf", c + 1)
    fs.write("names/" + LONG_NAME, 3 * c)
    fs.write("names/" + "n" * 251 + ".txt", c - 1)         # 255 UTF-16 units, the exFAT maximum
    fs.write("names/" + LONG_NAME[:60] + "-2", 1)
    fs.rename("names/" + LONG_NAME[:60] + "-2", "moved/" + LONG_NAME[:50] + "-moved")
    fs.rename("wide/entry-007", "wide/renamed-007")
    fs.rename("between", "moved/between")
    fs.write("doomed/a/b/c", 5 * c)
    fs.write("doomed/a/d", 2 * c + 1)
    fs.rmtree("doomed")
    for i in range(0, 160, 3):
        if i != 7:
            fs.remove("wide/entry-%03d" % i)
    fs.remove("moved/between/40")


def end_second_bitmap_chain(device):
    """newfs_exfat -n 2 leaves the FAT entry of the second allocation bitmap 0, which
    fsck_exfat rejects; ends the chain in both FATs, as the bitmap has one cluster."""
    fd = os.open(device, os.O_RDWR)
    try:
        fat_offset, fat_length = struct.unpack_from("<II", os.pread(fd, 512, 0), 80)
        for k in range(2):
            sector = bytearray(os.pread(fd, 512, (fat_offset + k * fat_length) * 512))
            if struct.unpack_from("<I", sector, 12)[0] != 0:
                raise Failure("unexpected TexFAT layout from newfs_exfat")
            struct.pack_into("<I", sector, 12, 0xFFFFFFFF)
            os.pwrite(fd, bytes(sector), (fat_offset + k * fat_length) * 512)
        os.fsync(fd)
    finally:
        os.close(fd)


# Standard files on special filesystems, or with an expected refusal or skip
for _name, _doc, _options in (
        ("veracrypt-exfat", "Standard files on the exFAT filesystem VeraCrypt itself creates (--filesystem=exFAT, full format)",
         dict(cluster=None, fs="veracrypt")),
        ("texfat", "Standard files on exFAT with two FATs (TexFAT): VeraCrypt must skip TRIM",
         dict(newfs=["-n", "2"], after_newfs=end_second_bitmap_chain, expect=("skipped", "TRIM_EXFAT_UNSUPPORTED"),
              prop=lambda o: (o.fats == 2, "%d FATs" % o.fats))),
        ("refuse-open-file", "A file kept open: TRIM_VOLUME_IN_USE, the volume and its filesystem stay mounted",
         dict(quick=True, hold="file", expect=("refused", "TRIM_VOLUME_IN_USE"))),
        ("refuse-device-open", "The virtual device held open: the filesystem is unmounted, the volume stays attached",
         dict(hold="device", expect=("dismount-failed", "TRIM_VOLUME_IN_USE"))),
        ("refuse-read-only", "Mounted read-only: TRIM_UNSUPPORTED_PROTECTION, still mounted",
         dict(mount=["--mount-options=ro"], expect=("refused", "TRIM_UNSUPPORTED_PROTECTION"))),
        ("refuse-file-container", "A file container: TRIM_UNSUPPORTED_HOST, still mounted",
         dict(cluster=None, fs="veracrypt", host="container", size=48 << 20, expect=("refused", "TRIM_UNSUPPORTED_HOST"))),
        ("skip-fsck", "A cluster of a kept file cleared in the bitmap: fsck_exfat fails, TRIM is skipped, nothing changes",
         dict(quick=True, corrupt=True, expect=("skipped", "TRIM_FILESYSTEM_CHECK_FAILED"),
              prop=lambda o: (len(o.free_but_used) == 1, "%d in-use clusters free in the bitmap" % len(o.free_but_used)))),
        ("refuse-non-exfat", "FAT (newfs_msdos) instead of exFAT: TRIM_UNSUPPORTED_FILESYSTEM, still mounted",
         dict(cluster=None, fs="msdos", expect=("refused", "TRIM_UNSUPPORTED_FILESYSTEM")))):
    scenario(_name, doc=_doc, **_options)(standard)


@scenario("host-4k", cluster=512, block=4096, prop=lambda o: (len(o.free_runs) > 100, "%d free runs" % len(o.free_runs)),
          doc="Host with 4096-byte blocks (legacy attach), clusters as small as the volume allows: extents rounded "
              "to host blocks; a partial check, as the legacy attach ignores UNMAP")
def host_4k(fs):
    for i in range(300):
        fs.write("r/%03d" % i, fs.rng.choice((1, 3, 9, 17)) * fs.cluster)
    for i in range(0, 300, 2):
        fs.remove("r/%03d" % i)


scenario("whole-disk", quick=True, host="whole", prop=edge_sizes_present,
         doc="Standard files on a volume created on the whole disk, with no partition map")(standard)


def random_operations(fs):
    """Seeded random mix of writes, appends, truncations, preallocations, gaps, renames, moves and deletions"""
    rng, c, serial = fs.rng, fs.cluster, itertools.count()
    sizes, dirs = {}, [""]          # the files later operations may touch, and the directories

    def room(more):
        return sum(-(-n // c) * c for n in sizes.values()) + more < fs.capacity // 2

    def new(parents=None, limit=500):
        # Paths must stay under PATH_MAX (1024 bytes) with the mount point in front: a parent
        # of fewer than limit bytes plus a name of at most 204 bytes. renamedir uses a smaller
        # limit, as the moved directory brings its subtree along
        parent = rng.choice([d for d in parents or dirs if len(d.encode()) < limit])
        return os.path.join(parent, rng.choice(("f", "Ünï-", "日本-", "\U0001F600", "long-" * 40)) + str(next(serial)))

    def size():
        return rng.choice((0, 1, c - 1, c, c + 1, 2 * c + 1, rng.randrange(1, 24 * c)))

    for _ in range(rng.randint(30, 120)):
        op = rng.choice(("write", "write", "write", "append", "truncate", "delete", "delete", "mkdir",
                         "rmtree", "rename", "renamedir", "prealloc", "gap"))
        path = rng.choice(sorted(sizes)) if sizes else None
        if op in ("write", "gap", "prealloc"):
            new_path, n = new(), size()
            offset = rng.randrange(c, 16 * c) if op == "gap" else 0
            if room(offset + n + (16 * c if op == "prealloc" else 0)):
                fs.write(new_path, n, offset)
                if op == "prealloc":
                    # Not added to sizes, so no later operation touches this file: a write into
                    # the preallocated space once failed with EINVAL on macOS exFAT (data written
                    # anyway), which a later check could not reproduce. Add the file to sizes
                    # once such writes are confirmed to succeed, also through the VeraCrypt device
                    fs.prealloc(new_path, rng.randrange(c, 16 * c))
                else:
                    sizes[new_path] = offset + n
        elif op == "mkdir" and len(dirs) < 40:
            dirs.append(new())
            os.makedirs(fs.path(dirs[-1]))
        elif op in ("rmtree", "renamedir") and len(dirs) > 1:
            old = rng.choice(dirs[1:])
            inside = lambda p, old=old: p == old or p.startswith(old + "/")
            if op == "rmtree":
                fs.rmtree(old)
                dirs = [d for d in dirs if not inside(d)]
                sizes = {p: n for p, n in sizes.items() if not inside(p)}
            else:
                to = new([d for d in dirs if not inside(d)], 300)
                fs.rename(old, to)
                dirs = [to + d[len(old):] if inside(d) else d for d in dirs]
                sizes = {(to + p[len(old):] if inside(p) else p): n for p, n in sizes.items()}
        elif path and op == "append" and room(2 * c):
            n = size()
            fs.append(path, n)
            sizes[path] += n
        elif path and op == "truncate":
            before, sizes[path] = sizes[path], rng.randrange(0, sizes[path] + 4 * c)
            if room(0):
                fs.truncate(path, sizes[path])
            else:
                sizes[path] = before
        elif path and op == "delete":
            fs.remove(path)
            del sizes[path]
        elif path and op == "rename":
            to = new()
            fs.rename(path, to)
            sizes[to] = sizes.pop(path)


def random_scenario(seed, index):
    return dict(DEFAULTS, name="random-%d-%d" % (seed, index), doc=random_operations.__doc__, populate=random_operations,
                quick=True, cluster=random.Random("%d:%d" % (seed, index)).choice((512, 4096, 32768, 131072)))


def corrupt_bitmap(o, device):
    """Marks the last cluster of the largest kept file free in the bitmap; returns the cluster."""
    path = max((p for p, e in files(o).items() if e.clusters and "/" in p and not p.startswith(".")),
               key=lambda p: o.tree[p].size)
    cluster = o.tree[path].clusters[-1]
    byte = (cluster - 2) >> 3
    where = o.offset(o.bitmap_clusters[byte // o.cluster]) + byte % o.cluster
    sector = where // 512 * 512
    fd = os.open(device, os.O_RDWR)
    try:
        data = bytearray(os.pread(fd, 512, sector))
        data[where - sector] &= ~(1 << ((cluster - 2) & 7)) & 0xFF
        os.pwrite(fd, bytes(data), sector)
        os.fsync(fd)
    finally:
        os.close(fd)
    print("  cleared the bitmap bit of cluster %d (%s)" % (cluster, path))
    return cluster


def analyze(device):
    fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return Exfat(reader(fd))
    finally:
        os.close(fd)


def fsck(device, kind):
    tool = "/sbin/fsck_msdos" if kind == "msdos" else "/sbin/fsck_exfat"
    result = sh([tool, "-n", device], check=False)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def create_image(path, size, allocate=False):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, size)
        # APFS may allocate the sparse tail of a file when a hole is punched before it,
        # which would hide what TRIM released; a fully written image keeps st_blocks exact
        if allocate:
            zeros = bytes(CHUNK)
            for pos in range(0, size, CHUNK):
                os.pwrite(fd, zeros[:min(CHUNK, size - pos)], pos)
            os.fsync(fd)
    finally:
        os.close(fd)


def image_record(img):
    for image in plist(["hdiutil", "info", "-plist"]).get("images", []):
        if os.path.realpath(image.get("image-path", "")) == os.path.realpath(img):
            return image
    return None


def entities(img):
    image = image_record(img)
    return image, {e.get("dev-entry") for e in (image or {}).get("system-entities", [])}


def attach(img, block=512):
    """Attaches img and returns its whole disk; DiskImages2 for 512-byte blocks, as only
    it passes UNMAP on to the image file. The legacy framework has the block size option."""
    if block == 512:
        sh(["diskutil", "image", "attach", "--noMount", img])
    else:
        sh(["hdiutil", "attach", "-nomount", "-blocksize", block, "-imagekey", "diskimage-class=CRawDiskImage", img])
    image, devices = entities(img)
    disks = [d for d in devices if re.fullmatch(r"/dev/disk\d+", d or "")]
    if not image or len(disks) != 1 or bool(image.get("diskimages2")) != (block == 512):
        raise Failure("%s is not attached as expected: %s" % (img, image))
    return disks[0]


def detach(img):
    """Detaches img if attached; returns an error text or None."""
    image, devices = entities(img)
    disks = [d for d in devices if re.fullmatch(r"/dev/disk\d+", d or "")]
    for disk in disks:
        result = sh(["hdiutil", "detach", disk], check=False)
        if result.returncode:
            # Shown, as a forced detach can leave VeraCrypt a volume whose host is gone
            print("  hdiutil detach %s failed, forcing it: %s" % (disk, (result.stdout + result.stderr).strip()))
            time.sleep(2)
            sh(["hdiutil", "detach", "-force", disk], check=False)
    return "%s is still attached" % img if entities(img)[0] else None


# ---------------------------------------------------------------------------
# No-root validation of the oracle and the scenario generators on plain images

def selftest_scenario(s, tmp, seed, check):
    if s["fs"] == "msdos" or s["host"] == "container":
        print("SKIP %s: no exFAT image to check" % s["name"])
        return
    print("\n== %s: %s" % (s["name"], s["doc"]))
    started = time.time()
    img, mnt = tmp / ("%s.img" % s["name"]), tmp / "mnt"
    mnt.mkdir(exist_ok=True)
    create_image(img, s["size"])
    try:
        disk = attach(img)
        device = raw(disk)
        args = ["-b", s["cluster"]] if s["cluster"] else []
        sh(["newfs_exfat", "-R"] + args + s["newfs"] + [device])
        if s["after_newfs"]:
            s["after_newfs"](device)
        sh(["diskutil", "unmount", disk], check=False)          # in case Disk Arbitration mounted it
        sh(["diskutil", "mount", "-mountPoint", mnt, disk])
        fs = Fs(str(mnt), random.Random("%d:%s" % (seed, s["name"])))
        fs.quiet()
        s["populate"](fs)
        os.sync()
        expected = snapshot(str(mnt))
        sh(["diskutil", "unmount", mnt])
        o = analyze(device)
        corrupted = corrupt_bitmap(o, device) if s["corrupt"] else None
        if corrupted:
            o = analyze(device)
        clean, output = fsck(device, "exfat")
        if corrupted:
            check.expect("fsck_exfat rejects the corrupted bitmap", not clean, output[-300:])
            check.expect("oracle finds exactly the corrupted cluster", o.free_but_used == [corrupted], str(o.free_but_used[:4]))
        else:
            check.expect("fsck_exfat -n clean", clean, output[-300:])
            check.expect("oracle: bitmap and directory tree agree", not o.problems, "; ".join(o.problems[:3]))
        if s["cluster"]:
            check.expect("oracle cluster size", o.cluster == s["cluster"] == fs.cluster, "%d %d" % (o.cluster, fs.cluster))
        if s["prop"]:
            ok, detail = s["prop"](o)
            check.expect("scenario property", ok, detail)
        if o.unsupported():
            print("  note: VeraCrypt's parser refuses this filesystem: %s" % o.unsupported())
        sh(["diskutil", "mount", "readOnly", "-mountPoint", mnt, disk])
        try:
            st = os.statvfs(str(mnt))
            check.expect("oracle free bytes equal statfs", o.free_bytes == st.f_bfree * st.f_frsize,
                         "oracle %d, statfs %d" % (o.free_bytes, st.f_bfree * st.f_frsize))
            everything = snapshot(str(mnt), everything=True)
            fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW)
            o.read = reader(fd)
            try:
                mine = {p: (None if e.dir else (e.size, o.digest(p))) for p, e in o.tree.items()}
            finally:
                os.close(fd)
            check.expect("oracle tree, sizes and contents equal the mounted filesystem", mine == everything,
                         tree_difference(everything, mine))
            check.expect("remounted tree equals the populated tree", snapshot(str(mnt)) == expected,
                         tree_difference(expected, snapshot(str(mnt))))
        finally:
            sh(["diskutil", "unmount", mnt], check=False)
        print("  %d clusters of %d bytes, %d free runs, %d free bytes, %d entries, %.1f s" % (
            o.count, o.cluster, len(o.free_runs), o.free_bytes, len(o.tree), time.time() - started))
    finally:
        if os.path.ismount(str(mnt)):
            sh(["diskutil", "unmount", "force", mnt], check=False)
        problem = detach(img)
        if problem:
            check.expect("detach " + img.name, False, problem)
        else:
            img.unlink()


def unit_checks():
    """Checks of the helpers that the self-test runs do not reach."""
    assert merge([(5, 9), (0, 2), (2, 4), (8, 12), (20, 20)]) == [(0, 4), (5, 12)]
    assert overlap([(0, 10), (20, 30)], [(5, 25)]) == 10
    assert inward([(1, 8193), (10000, 10100)], 4096) == [(4096, 8192)]
    assert subtract([(0, 10), (20, 30)], [(5, 22), (25, 26)]) == [(0, 5), (22, 25), (26, 30)]
    # The cluster-512 failure: both unaligned edges keep their 16 KiB chunks allocated
    assert expected_holes([(0xc00, 0x10400)]) == [(0x4000, 0x10000)]
    # Neighbours in one chunk: the unaligned start of the second takes back the aligned first;
    # the aligned third must still be a hole, so an untrimmed aligned run still fails
    assert expected_holes([(0x4000, 0x6000), (0x6200, 0x8000), (0x10000, 0x20000)]) == [(0x10000, 0x20000)]
    # A run longer than TRIM_EXTENT is split into extents; the split point is an edge too
    assert expected_holes([(0x200, 0x200 + TRIM_EXTENT + 0x8000)]) == \
        [(0x4000, TRIM_EXTENT), (TRIM_EXTENT + 0x4000, TRIM_EXTENT + 0x8000)]
    assert runs([2, 3, 4, 7, 9, 10]) == [(2, 3), (7, 1), (9, 2)]
    units = dict(BYTE="B", KB="KiB", MB="MiB", GB="GiB", TB="TiB", PB="PiB")
    assert [size_to_string(n, units) for n in (1024, 1 << 20, (1 << 20) + 1, (99 << 20) + 1)] == \
        ["1024 B", "1024 KiB", "1.0 MiB", "99 MiB"]
    sectors = [b"\0" * 8, b"a" * 8, b"b" * 8, b"\0" * 8]
    assert changed_sectors(b"".join(sectors), b"".join(sectors[:2] + [b"c" * 8, sectors[3]])) == [2]
    listing = ("1: /dev/disk7s1 /dev/disk12 '/Volumes/NO NAME'\n2: /dev/disk8s1 /dev/disk13 - \n"
               "3: /dev/disk9s1 /dev/disk14 /Volumes/X\n5: /dev/disk1s1 /dev/disk2 /Volumes/X\t\n"
               # Core/Unix/MacOSX/CoreMacOSX.cpp ClearDiskImageInfo: the disk image is gone
               "6: /dev/disk3s1 -  - \n4: /dev/disk10s1 /dev/disk15 '/Volumes/it''s A'")
    assert list_entry(listing, "/dev/disk7s1") == ("/dev/disk12", "/Volumes/NO NAME")
    assert list_entry(listing, "/dev/disk8s1") == ("/dev/disk13", None)
    assert list_entry(listing, "/dev/disk9s1") == ("/dev/disk14", "/Volumes/X")
    assert list_entry(listing, "/dev/disk10s1") == ("/dev/disk15", "/Volumes/it's A")
    assert list_entry(listing, "/dev/disk1s1") == ("/dev/disk2", "/Volumes/X\t")
    assert list_entry(listing, "/dev/disk3s1") == ("-", None)
    assert list_entry(listing, "/dev/disk11s1") == (None, None)


def size_to_string(size, units):
    """UserInterface::SizeToString."""
    for power, unit in ((5, "PB"), (4, "TB"), (3, "GB"), (2, "MB")):
        if size > 99 * 1024 ** power:
            return "%d %s" % (size // 1024 ** power, units[unit])
        if size > 1024 ** power:
            return "%.1f %s" % (size / 1024 ** power, units[unit])
    return "%d %s" % (size // 1024, units["KB"]) if size > 1024 else "%d %s" % (size, units["BYTE"])


# ---------------------------------------------------------------------------
# Host state

ZERO = hashlib.blake2b(bytes(SECTOR), digest_size=8).digest()


def digests(path, size):
    """An 8-byte digest per 512-byte sector of the whole host."""
    out, fd = [], os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        for pos in range(0, size, CHUNK):
            data = memoryview(reader(fd)(pos, min(CHUNK, size - pos)))
            out.append(b"".join(hashlib.blake2b(data[i:i + SECTOR], digest_size=8).digest()
                                for i in range(0, len(data), SECTOR)))
    finally:
        os.close(fd)
    return b"".join(out)


def changed_sectors(before, after):
    out, step = [], 8 * 4096
    for base in range(0, len(before), step):
        if before[base:base + step] != after[base:base + step]:
            out += [i // 8 for i in range(base, min(base + step, len(before)), 8) if before[i:i + 8] != after[i:i + 8]]
    return out


def zero_sectors(d, start, end):
    return d[start // SECTOR * 8:end // SECTOR * 8] == ZERO * ((end - start) // SECTOR)


def image_state(img):
    """Allocated bytes and data extents of a sparse image file."""
    fd = os.open(img, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        extents, pos, size = [], 0, os.fstat(fd).st_size
        while pos < size:
            try:
                start = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                break
            pos = os.lseek(fd, start, os.SEEK_HOLE)
            extents.append((start, pos))
        return os.fstat(fd).st_blocks * 512, extents
    finally:
        os.close(fd)


def describe(sectors, after, limit=4):
    parts = []
    for first, count in runs(sectors)[:limit]:
        zeros = all(after[i * 8:i * 8 + 8] == ZERO for i in range(first, first + count))
        parts.append("%d bytes at %#x (%s)" % (count * SECTOR, first * SECTOR, "now zeros" if zeros else "rewritten"))
    return "%d sectors changed: %s" % (len(sectors), ", ".join(parts))


# ---------------------------------------------------------------------------
# The root test

class TrimChecks:
    def __init__(self, args, seed):
        self.binary = str(Path(args.binary).resolve())
        self.seed, self.keep = seed, args.keep_artifacts
        self.failures, self.hosts, self.holds = [], {}, []
        self.tmp = Path(tempfile.mkdtemp(prefix="vc-trim-e2e-")).resolve()
        (self.tmp / "config").mkdir()
        (self.tmp / "ro").mkdir()
        # A throwaway password for this run's scratch volumes; --stdin keeps it out of
        # the process list and the logs
        self.password = secrets.token_urlsafe(24) + "\n"
        # VeraCrypt takes its language from LANG and the saved preferences: use the C
        # locale and an empty configuration directory, so the messages are English.
        # TMPDIR fixes where a macFUSE build puts its volume image (see AUX_IMAGE).
        self.env = dict(os.environ, LANG="C", LC_ALL="C", XDG_CONFIG_HOME=str(self.tmp / "config"), TMPDIR="/private/tmp")
        self.text = load_language(self.binary)
        print("Artifacts:", self.tmp)

    def expect(self, label, passed, detail=""):
        print("%s %s%s" % ("PASS" if passed else "FAIL", label, "" if passed or not detail else ": " + detail), flush=True)
        if not passed:
            self.failures.append("%s: %s" % (self.current, label))

    def vc(self, *args, check=True, stdin=None):
        return veracrypt(self.binary, args, check=check, stdin=stdin, env=self.env)

    def preflight(self, chosen):
        """Refuses to start a run that cannot finish: too little disk space, or a mounted
        volume VeraCrypt cannot verify, which makes it refuse --mount, --list and --trim."""
        need = sum({(s["host"], s["block"], s["size"]): s["size"] for s in chosen}.values()) + (256 << 20)
        free = shutil.disk_usage(str(self.tmp)).free
        if free < need:
            raise Failure("%d MiB free in %s, the chosen scenarios need about %d MiB; free some space "
                          "or point TMPDIR elsewhere" % (free >> 20, self.tmp.parent, need >> 20))
        result = self.vc("--list", check=False)
        if self.discovery_failed(result):
            raise Failure("VeraCrypt cannot verify every mounted volume, so it would refuse to mount or "
                          "trim; unmount the volume it names and retry:\n" + result.stderr.strip())

    def discovery_failed(self, result):
        return self.text["VOLUME_DISCOVERY_FAILED"].split("\n")[0] in result.stderr

    # Hosts ------------------------------------------------------------------

    def check_host(self, host):
        """Refuses to go on unless the host is still the partition (or for the whole-disk
        host, the unpartitioned whole disk) of this test's own image."""
        if host.img is None:
            st = os.lstat(host.path)
            if not stat.S_ISREG(st.st_mode) or Path(host.path).parent != self.tmp:
                raise Failure("%s is not this test's container" % host.path)
            return
        image, devices = entities(host.img)
        # The whole disk only for the whole-disk host, and only while nothing partitioned it
        whole = host.path == host.disk
        if not image or whole != host.whole or not {host.path, host.disk} <= devices \
                or (whole and devices != {host.disk}) or bool(image.get("diskimages2")) == host.legacy:
            raise Failure("%s is no longer the %s of %s" % (host.path, "disk" if host.whole else "partition", host.img))

    def check_virtual(self, host, virtual):
        """Refuses to go on unless `virtual` is the device of a VeraCrypt volume image
        attached since this test mounted the host, of the size of the host's data area."""
        matches = [i for i in plist(["hdiutil", "info", "-plist"]).get("images", [])
                   if virtual in {e.get("dev-entry") for e in i.get("system-entities", [])}]
        path = matches[0].get("image-path", "") if len(matches) == 1 else ""
        if not re.fullmatch(r"/dev/disk\d+", virtual) or not AUX_IMAGE.fullmatch(path) \
                or path in host.images_before or device_size(raw(virtual))[0] != host.size - HEADERS:
            raise Failure("%s is not the virtual device of %s" % (virtual, host.path))

    def host_for(self, s):
        if s["host"] == "container":
            path = self.tmp / "container.hc"
            if path.exists():
                path.unlink()
            return SimpleNamespace(path=str(path), size=s["size"], img=None, legacy=False, device=False, ready=True)
        key = (s["size"], s["block"], s["host"])
        if key in self.hosts and not self.hosts[key].ready:
            raise SkipScenario("its host failed to set up in an earlier scenario")
        if key not in self.hosts:
            img = self.tmp / ("host-%d-%d-%s.img" % key)
            # Registered first, so that cleanup detaches the image whatever fails below
            self.hosts[key] = host = SimpleNamespace(img=img, legacy=s["block"] != 512, device=True, path=None, ready=False,
                                                     whole=s["host"] == "whole")
            create_image(img, s["size"], allocate=True)
            try:
                self.setup_host(host, s["block"])
            except Failure as e:
                if host.legacy:
                    raise SkipScenario("no VeraCrypt volume on a host with 4096-byte blocks: %s" % str(e)[-500:])
                raise
            host.ready = True
        return self.hosts[key]

    def setup_host(self, host, block):
        img = host.img
        # Attached without mounting; the image is all zeros, so nothing can mount it
        host.disk = attach(img, block)
        if host.whole:
            host.path = host.disk
        else:
            sh(["diskutil", "partitionDisk", host.disk, "GPT", "ExFAT", "VCTRIM", "100%"])
            part = plist(["diskutil", "list", "-plist", host.disk])["AllDisksAndPartitions"][0]["Partitions"][-1]
            host.path = "/dev/" + part["DeviceIdentifier"]
            sh(["diskutil", "unmount", host.path])
        info = plist(["diskutil", "info", "-plist", host.path])
        host.size, host.block = device_size(raw(host.path))
        host.offset = 0 if host.whole else info["PartitionMapPartitionOffset"]
        if info["WholeDisk"] != host.whole or info["BusProtocol"] != "Disk Image" or info.get("MountPoint") \
                or "/dev/" + info["ParentWholeDisk"] != host.disk or info["Size"] != host.size or host.block != block:
            raise Failure("%s does not look like the host on %s: %s" % (host.path, img, info))
        self.check_host(host)
        print("host %s: %s at %d of %s, %d bytes, %d-byte blocks" % (
            host.path, "whole disk" if host.whole else "partition", host.offset, img.name, host.size, host.block))
        self.create(host)

    def create(self, host, filesystem="none", quick=True, size=None):
        if host.img:
            self.check_host(host)
        self.vc("--create", host.path, "--volume-type=normal", "--encryption=AES", "--hash=SHA-512",
                "--filesystem=" + filesystem, "--random-source=/dev/urandom", *(["--quick"] if quick else []),
                *(["--size=%d" % size] if size else []), *AUTH, stdin=self.password)

    def mount(self, host, *extra):
        self.check_host(host)
        host.images_before = {i.get("image-path") for i in plist(["hdiutil", "info", "-plist"]).get("images", [])}
        self.vc("--mount", host.path, "--protect-hidden=no", *AUTH, *extra, stdin=self.password)
        virtual, mountpoint = self.listed(host)
        if virtual is None:
            raise Failure("%s is not listed after mounting" % host.path)
        self.check_virtual(host, virtual)
        if host.device:
            record = os.path.join(RECORD_DIR, "r" + host.path[5:])
            if "--mount-options=ro" in extra:
                self.expect("no mount record for a read-only mount", not os.path.exists(record))
            else:
                fd = os.open(record, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    offset, size = struct.unpack("<QQ", os.read(fd, 16))
                finally:
                    os.close(fd)
                if (offset, size) != (DATA_OFFSET, host.size - HEADERS):
                    raise Failure("mount record has data offset %d and size %d" % (offset, size))
        return virtual, mountpoint

    def listed(self, host):
        result = self.vc("--list", host.path, check=False)
        virtual, mountpoint = list_entry(result.stdout, host.path)
        if virtual is not None:
            return virtual, mountpoint
        if self.discovery_failed(result):
            raise Failure("VeraCrypt cannot tell whether %s is mounted: %s" % (host.path, result.stderr.strip()))
        return None, None

    def settle(self, host):
        """Releases what a scenario may have left behind on its own host."""
        for fd in self.holds:
            os.close(fd)
        self.holds = []
        if os.path.ismount(str(self.tmp / "ro")):
            sh(["diskutil", "unmount", "force", self.tmp / "ro"], check=False)
        if host and host.img and host.path:
            try:
                self.check_host(host)
            except Failure:
                return      # not this test's device any more: nothing of ours to unmount
        # Not asked of --list, which may fail; unmounting a volume that is not mounted is harmless
        if host and host.path and self.vc("--unmount", host.path, check=False).returncode:
            self.vc("--unmount", "--force", host.path, check=False)

    # Scenarios -----------------------------------------------------------------

    def format(self, s, host):
        if s["fs"] == "veracrypt":
            self.create(host, "exFAT", quick=False, size=None if host.device else host.size)
            return
        virtual, _ = self.mount(host, "--filesystem=none")
        device = raw(virtual)
        # Plaintext zeros everywhere: free space then holds ciphertext, so trimmed
        # sectors read differently afterwards and are allocated in the image file
        fd = os.open(device, os.O_WRONLY)
        try:
            zeros = bytes(CHUNK)
            for pos in range(0, host.size - HEADERS, CHUNK):
                os.pwrite(fd, zeros[:min(CHUNK, host.size - HEADERS - pos)], pos)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.check_virtual(host, virtual)
        if s["fs"] == "msdos":
            sh(["newfs_msdos", device])
        else:
            # A cluster cannot be smaller than a sector of the volume (host-4k)
            sh(["newfs_exfat", "-R", "-b", max(s["cluster"], device_size(device)[1])] + s["newfs"] + [device])
            if s["after_newfs"]:
                s["after_newfs"](device)
        # In case Disk Arbitration mounted the new filesystem, before Fs.quiet() keeps
        # Spotlight and fseventsd off it
        sh(["diskutil", "unmount", virtual], check=False)
        self.unmount(host)

    def unmount(self, host):
        # macOS services may hold a just-written volume for a moment, so the unmount is
        # tried three times, 3 s apart; add tries if the last one still finds it busy
        for attempt in range(3):
            result = self.vc("--unmount", host.path, check=attempt == 2)
            if not result.returncode:
                return
            time.sleep(3)

    def run_scenario(self, s):
        self.current = s["name"]
        print("\n== %s: %s" % (s["name"], s["doc"]), flush=True)
        started = time.time()
        host = None
        try:
            host = self.host_for(s)
            self.format(s, host)

            # Populate through a normal mount, as a user would
            virtual, mountpoint = self.mount(host)
            if not mountpoint:
                raise Failure("VeraCrypt mounted no filesystem")
            fs = Fs(mountpoint, random.Random("%d:%s" % (self.seed, s["name"])))
            fs.quiet()
            s["populate"](fs)
            os.sync()
            expected = snapshot(mountpoint)

            # The oracle reads the bitmap from the virtual device with no filesystem mounted
            self.unmount(host)
            virtual, _ = self.mount(host, "--filesystem=none")
            exfat = s["fs"] != "msdos"
            before = analyze(raw(virtual)) if exfat else None
            if s["corrupt"]:
                self.check_virtual(host, virtual)
                corrupt_bitmap(before, raw(virtual))
                before = analyze(raw(virtual))
            clean, output = fsck(raw(virtual), s["fs"])
            if s["corrupt"]:
                self.expect("fsck_exfat rejects the corrupted bitmap", not clean, output[-300:])
            else:
                self.expect("fsck -n clean before TRIM", clean, output[-300:])
            kind, key = s["expect"] or ("done", None)
            if kind == "done":
                self.expect("layout supported by VeraCrypt's parser (oracle)", not before.unsupported(), str(before.unsupported()))
            if s["prop"]:
                ok, detail = s["prop"](before)
                self.expect("scenario property", ok, detail)
            self.unmount(host)

            d0 = digests(raw(host.path), host.size)
            image0 = image_state(host.img) if host.img else None

            virtual, mountpoint = self.mount(host, *s["mount"])
            if s["hold"] == "file":
                self.holds.append(os.open(os.path.join(mountpoint, sorted(p for p in expected if expected[p])[0]), os.O_RDONLY))
            elif s["hold"] == "device":
                self.holds.append(os.open(raw(virtual), os.O_RDONLY))
            trim = self.vc("--unmount", host.path, "--trim", check=False)
            print("  veracrypt --unmount --trim: exit %d\n    %s" % (
                trim.returncode, (trim.stdout + trim.stderr).strip().replace("\n", "\n    ")))
            if self.text["TRIM_MACFUSE_KERNEL_UNTESTED"] in trim.stderr:
                raise Skip("this build uses the macFUSE kernel extension, for which TRIM is refused "
                           "(TRIM_MACFUSE_KERNEL_UNTESTED); use a FUSE-T or macFUSE FSKit build")
            listed = self.listed(host)[0] is not None
            self.check_outcome(kind, key, trim, host, listed, mountpoint)
            for fd in self.holds:
                os.close(fd)
            self.holds = []
            if listed:
                self.unmount(host)

            d1 = digests(raw(host.path), host.size)
            image1 = image_state(host.img) if host.img else None

            # Remount: filesystem check, oracle, files
            virtual, _ = self.mount(host, "--filesystem=none")
            clean, output = fsck(raw(virtual), s["fs"])
            if s["corrupt"]:
                self.expect("fsck_exfat still rejects the corrupted bitmap", not clean, output[-300:])
            else:
                self.expect("fsck -n clean after TRIM", clean, output[-300:])
            after = analyze(raw(virtual)) if exfat else None
            if after and not s["corrupt"]:
                self.expect("oracle: bitmap and directory tree agree after TRIM", not after.problems, "; ".join(after.problems[:3]))
            self.check_virtual(host, virtual)
            sh(["diskutil", "mount", "readOnly", "-mountPoint", self.tmp / "ro", virtual])
            try:
                got = snapshot(str(self.tmp / "ro"))
                self.expect("files, sizes and SHA-256 unchanged", got == expected, tree_difference(expected, got))
                back = sorted(p for p in fs.deleted if p not in expected and os.path.lexists(os.path.join(self.tmp / "ro", p)))
                self.expect("deleted files and directories stay deleted", not back, ", ".join(back[:3]))
            finally:
                sh(["diskutil", "unmount", self.tmp / "ro"], check=False)
            self.unmount(host)

            self.check_host_state(kind, host, d0, d1, image0, image1, before, after, trim)
        except SkipScenario as e:
            print("SKIP %s: %s" % (s["name"], e))
        except Skip:
            raise
        except Exception as e:      # the other scenarios still run
            self.expect("scenario ran to completion", False, "%s: %s" % (type(e).__name__, str(e)[-1500:]))
        finally:
            try:
                self.settle(host)
            except Exception as e:
                self.expect("scenario cleanup", False, "%s: %s" % (type(e).__name__, e))
            print("  %.0f s" % (time.time() - started))

    def check_outcome(self, kind, key, trim, host, listed, mountpoint):
        t = self.text
        if kind in ("done", "skipped"):
            self.expect("volume unmounted", not listed)
            if host.device:
                self.expect("mount record removed", not os.path.lexists(os.path.join(RECORD_DIR, "r" + host.path[5:])))
        if kind == "done":
            return       # the amount is checked against the oracle with the host state
        reason = t[key]
        if kind == "skipped":
            want = "Warning: " + t["TRIM_SKIPPED"].replace("{0}", host.path).split("{1}")[0]
            self.expect("TRIM skipped (exit %d): %s" % (trim.returncode, key),
                        trim.returncode == 1 and want in trim.stderr and reason in trim.stderr)
        else:
            head = t["TRIM_NOT_PERFORMED" if kind == "refused" else "TRIM_UNMOUNT_FAILED"].rstrip(".")
            want = "Error: %s:\n%s" % (head, reason)
            self.expect("%s (exit %d): %s" % (kind, trim.returncode, key), trim.returncode == 1 and want in trim.stderr)
            self.expect("volume still mounted", listed)
            if mountpoint:
                mounted = os.path.ismount(mountpoint)
                self.expect("filesystem %s" % ("still mounted" if kind == "refused" else "unmounted"),
                            mounted == (kind == "refused"))

    def check_host_state(self, kind, host, d0, d1, image0, image1, before, after, trim):
        changed = changed_sectors(d0, d1)
        headers = [i for i in changed if i * SECTOR < HEADER_GROUP or i * SECTOR >= host.size - HEADER_GROUP]
        self.expect("both header groups unchanged", not headers, describe(headers, d1))
        if kind != "done":
            self.expect("host unchanged", not changed, describe(changed, d1))
            if image0:
                self.expect("image file not trimmed", image1[0] >= image0[0], "%d -> %d bytes" % (image0[0], image1[0]))
            return

        end = DATA_OFFSET + host.size - HEADERS
        to_host = lambda o: [(DATA_OFFSET + a, min(DATA_OFFSET + b, end)) for a, b in o.free_ranges()]
        self.expect("free clusters unchanged from the oracle read before TRIM to the one after",
                    before.free_ranges() == after.free_ranges(), "%d -> %d bytes" % (before.free_bytes, after.free_bytes))
        # Trimming only zeroes sectors; a sector outside the free clusters that changed lost data
        allowed = merge(to_host(before) + to_host(after))
        bad = [i for i in changed if overlap([(i * SECTOR, (i + 1) * SECTOR)], allowed) < SECTOR]
        self.expect("only free clusters changed on the host", not bad, describe(bad, d1))

        trimmed = inward(to_host(after), host.block)
        amount = sum(b - a for a, b in trimmed)
        want = self.text["TRIM_DONE"].replace("{0}", host.path).replace("{1}", size_to_string(amount, self.text))
        self.expect("exit 0, reports %s" % size_to_string(amount, self.text), trim.returncode == 0 and want in trim.stdout,
                    "expected: " + want)
        if host.legacy:
            print("SKIP zero and image checks: the legacy 4096-byte attach accepts UNMAP and ignores it")
            return
        nonzero = [(a, b) for a, b in trimmed if not zero_sectors(d1, a, b)]
        self.expect("free clusters read as zeros on the host", not nonzero,
                    "%d of %d ranges, first %s" % (len(nonzero), len(trimmed), nonzero[:2]))
        # At least the holes, at most every 4 KiB block inside the trimmed ranges
        in_image = [(host.offset + a, host.offset + b) for a, b in trimmed]
        holes, allocated = expected_holes(in_image), merge(image0[1])
        freed, least, most = image0[0] - image1[0], overlap(allocated, holes), overlap(allocated, inward(in_image, IMAGE_BLOCK))
        self.expect("image file shrank by the allocated blocks in the free clusters",
                    least - (64 << 10) <= freed <= most + (64 << 10), "freed %d bytes, expected %d to %d" % (freed, least, most))
        left = overlap(merge(image1[1]), holes)
        self.expect("no image block in the free clusters stays allocated", left == 0, "%d bytes" % left)

    def cleanup(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        for fd in self.holds:
            os.close(fd)
        if self.keep:
            print("Kept %s; afterwards unmount the volumes, detach the images (hdiutil info) and delete it" % self.tmp)
            return
        problems = []
        for host in list(self.hosts.values()) + [SimpleNamespace(path=str(self.tmp / "container.hc"), img=None)]:
            try:
                if host.path and (host.img or os.path.exists(host.path)):
                    self.settle(host)
                    if self.listed(host)[0]:
                        # Not detached: forcing the host away would leave the volume without its device
                        problems.append("VeraCrypt still lists %s; unmount it, then detach %s" % (host.path, host.img))
                        continue
            except Exception as e:      # go on with the other images
                problems.append(str(e))
            try:
                problem = host.img and detach(host.img)
                if problem:
                    problems.append(problem)
            except Exception as e:
                problems.append(str(e))
        if os.path.ismount(str(self.tmp / "ro")):
            problems.append("%s is still mounted" % (self.tmp / "ro"))
        # Only the directory this run created itself
        if self.tmp.parent != Path(tempfile.gettempdir()).resolve() or not self.tmp.name.startswith("vc-trim-e2e-"):
            problems.append("%s is not this run's own directory" % self.tmp)
        if problems:
            print("Cleanup incomplete, %s kept: %s" % (self.tmp, "; ".join(problems)))
        else:
            shutil.rmtree(self.tmp)


def load_language(binary):
    """English texts from the Language.xml of the source tree the binary was built from."""
    for path in [p / "Common" / "Language.xml" for p in Path(binary).parents] + [ROOT / "src" / "Common" / "Language.xml"]:
        if path.is_file():
            return {e.get("key"): (e.text or "").replace("\\n", "\n")
                    for e in ElementTree.parse(path).getroot().iter("entry")}
    sys.exit("Language.xml not found next to %s or in %s" % (binary, ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", help="the VeraCrypt executable to test")
    parser.add_argument("--scenario", action="append", metavar="NAME", help="run only this scenario (repeatable)")
    parser.add_argument("--list", action="store_true", help="list the scenarios and exit")
    parser.add_argument("--quick", action="store_true", help="run the quick subset")
    parser.add_argument("--random", type=int, default=0, metavar="N", help="run N seeded random scenarios")
    parser.add_argument("--seed", type=int, help="seed of the random scenarios and generators")
    parser.add_argument("--keep-artifacts", action="store_true", help="keep the images and files for debugging")
    parser.add_argument("--oracle-selftest", action="store_true",
                        help="check the oracle and generators on plain exFAT images (no root)")
    args = parser.parse_args()
    seed = args.seed if args.seed is not None else secrets.randbelow(1 << 31)
    names = {s["name"]: s for s in SCENARIOS}
    unknown = [n for n in args.scenario or [] if n not in names]
    if unknown:
        parser.error("unknown scenario %s; see --list" % ", ".join(unknown))
    if args.scenario:
        chosen = [names[n] for n in args.scenario]
    elif args.random:
        chosen = []
    else:
        chosen = [s for s in SCENARIOS if s["quick"] or not args.quick]
    chosen += [random_scenario(seed, i) for i in range(args.random)]

    if args.list:
        for s in chosen:
            print("%-22s %s %5d MiB  cluster %-8s %s" % (s["name"], "q" if s["quick"] else " ", s["size"] >> 20,
                                                          s["cluster"] or "default", s["doc"]))
        return
    if args.oracle_selftest:
        print("seed", seed)
        unit_checks()
        check = SimpleNamespace(failures=[])

        def expect(label, passed, detail=""):
            print("%s %s%s" % ("PASS" if passed else "FAIL", label, "" if passed or not detail else ": " + detail), flush=True)
            if not passed:
                check.failures.append(label)
        check.expect = expect
        tmp = Path(tempfile.mkdtemp(prefix="vc-trim-selftest-")).resolve()
        try:
            for s in chosen:
                try:
                    selftest_scenario(s, tmp, seed, check)
                except Exception as e:      # the other scenarios still run
                    expect("%s ran to completion" % s["name"], False, "%s: %s" % (type(e).__name__, str(e)[-1500:]))
        finally:
            if os.path.ismount(str(tmp / "mnt")):
                print("Kept %s: %s is still mounted" % (tmp, tmp / "mnt"))
            else:
                shutil.rmtree(tmp, ignore_errors=True)
        if check.failures:
            sys.exit("Failed: " + ", ".join(check.failures))
        print("\nAll oracle self-test checks passed.")
        return

    if not args.binary:
        parser.error("--binary is required")
    if os.geteuid() != 0:
        parser.error("needs root (sudo); only --list and --oracle-selftest run without it")
    usage = veracrypt(args.binary, ["--help"], check=False)
    if "--trim" not in usage.stdout + usage.stderr:
        sys.exit("%s has no --trim option" % args.binary)

    print("seed", seed)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit("interrupted"))
    checks = TrimChecks(args, seed)
    skipped = refused = None
    try:
        checks.preflight(chosen)
        for s in chosen:
            checks.run_scenario(s)
    except Skip as e:
        skipped = str(e)
    except Failure as e:
        refused = str(e)
    finally:
        checks.cleanup()
    if refused:
        sys.exit("Refused: " + refused)
    if skipped:
        print("SKIP: " + skipped)
        sys.exit(2)
    if checks.failures:
        sys.exit("Failed: " + ", ".join(checks.failures))
    print("\nAll TRIM checks passed.")


if __name__ == "__main__":
    main()
