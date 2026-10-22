# macOS lifecycle regression checks

Run these checks on macOS with Xcode Command Line Tools and Python 3. Apart from
`test_macos_trim.py`, they do not require administrator privileges, mounted
containers, or an installed test app.

Build the matching VeraCrypt sources first. Use a clean build after changing
headers: the current makefiles do not track every header dependency. The archive
architecture must match the compiler's default architecture.

From the repository root, set `VC_TEST_BUILD_SRC` to the `src` directory of that
build, then run:

```sh
VC_TEST_BUILD_SRC=/absolute/path/to/build/src
python3 Tests/test_macos_discovery.py --platform-archive "$VC_TEST_BUILD_SRC/Platform/Platform.a"
python3 Tests/test_fuset_cleanup.py --build-dir "$VC_TEST_BUILD_SRC"
python3 Tests/test_fuset_aux_directory.py --build-dir "$VC_TEST_BUILD_SRC"
```

The auxiliary-directory check exercises the production FUSE-T private-parent
helpers against disposable local directories, including concurrent creation,
inherited ACL removal, setup failure cleanup, per-mount parent removal, and
discovery ownership. The temporary filesystem must support ownership and ACLs.
The helper check simulates disabled ownership without mounting a filesystem.
An optional elevated run also checks caller access, parent immutability, and
actual uid isolation using a harmless fixture:

```sh
sudo python3 Tests/test_fuset_aux_directory.py --build-dir "$VC_TEST_BUILD_SRC" --owner "$(id -u)"
```

The private parent protects auxiliary filesystem paths; these checks do not
assess FUSE-T transport authentication. Existing volumes must be dismounted and
remounted with the updated build to receive this protection.

The discovery runner compiles the production plist and batch-refresh methods
with an in-memory inventory provider. It checks exact and legacy alias matches,
unresolved inventory, stale-field invalidation, one query per refresh, and fresh
discovery before destructive operations. It also runs `macos_process_test.cpp`
against the real platform archive, checking subprocess deadlines, output limits,
descriptor isolation, error reporting, and child reaping with its own helper
processes. `macos_volume_state_test.cpp` includes production headers directly to
check auxiliary mount owner/backend/basename filtering and initial, partial,
invalidated, and stale snapshot decisions.

The cleanup runner compiles production cleanup and rollback methods with mocked
mount, service, and device operations. It checks failure ordering, reporting of
unconfirmed service exits after auxiliary-mount removal, retryable busy
unmounts, per-volume hidden-protection refresh, and responsive probes during
busy startup rollback. It also runs the production multi-volume unmount loop
with scripted outcomes: every unconfirmed service exit must be reported, even
when another volume fails or a forced-unmount prompt is declined. Finally, it
runs `macos_cleanup_state_test.cpp` against the real serialization code to
check that cleanup failure details survive IPC and that local display state
leaves the legacy `/control` bytes unchanged.

`exfat_free_space_test.cpp` checks the exFAT free-space parser used by "Unmount
with TRIM": a synthetic image with a known bitmap, damaged copies that must be
refused, and on macOS images formatted with newfs_exfat compared against statfs.
Images given as arguments must be refused. It needs no root:

```sh
c++ -std=c++11 -Wall -I src -o /tmp/exfat_test Tests/exfat_free_space_test.cpp "$VC_TEST_BUILD_SRC/Platform/Platform.a" && /tmp/exfat_test
```

These tests exercise state and serialization contracts. They do not establish
real backend timing, GUI rendering, or filesystem behavior under forced unmount.

For an ordinary integration check with a FUSE-T GUI build, close other VeraCrypt
processes and dismount their volumes first. In a logged-in macOS desktop session:

```sh
python3 Tests/test_macos_gui_lifecycle.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt"
python3 Tests/test_macos_gui_inactivity.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt"
python3 Tests/test_macos_gui_teardown.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt"
```

These use isolated preferences and disposable file containers. The lifecycle
check verifies write/fsync/remount integrity, background startup with a mounted
volume, refresh after a CLI dismount, and automatic GUI exit. It checks service
exit, closed backing-file handles, and removal of the auxiliary mount and
shutdown endpoint. The inactivity check takes about two minutes: it verifies
that automatically unmounting one idle volume does not restart another volume's
idle timer. The teardown check needs an unsigned local build and clang, and
takes about three minutes. It slows a service down with `fuset_startup_faults.c`
and verifies two automatic-unmount cases: a normal quit request that arrives
meanwhile is honored, including unmount on quit; and when service exit cannot be
confirmed, a warning keeps the background application from exiting silently.
That warning stays on screen until the test ends. Failed-run artifacts are
retained for diagnosis; use `--keep-artifacts` to retain successful runs as well.

`test_macos_trim.py` is an end-to-end check of "Unmount with TRIM" on a real
VeraCrypt build. It needs administrator privileges and a FUSE-T or macFUSE FSKit
build; with the macFUSE kernel extension, VeraCrypt refuses TRIM and the test
reports SKIP. With FUSE-T, VeraCrypt mounts through a local SMB server
(`mount_smbfs` to `fuse-t._smb._tcp.local`), so a firewall that blocks it makes
mounts fail with "The operation did not finish in time". The test creates
zero-filled disk images in a private temporary directory, so that the blocks
TRIM releases can be counted, and creates VeraCrypt volumes on them, or for one
refusal in a file container. Before it writes to, formats, mounts or trims a
device, it checks with `hdiutil info` that the device belongs to one of its own
images or to the volume image that VeraCrypt has just attached for it. It
detaches and deletes its images at the end, also after a failure or Ctrl-C.

Each scenario fills an exFAT filesystem in a known way, runs `--unmount --trim`
and compares the result with an independent exFAT reader. Only free clusters may
change, and they must read as zeros. No 4 KiB block inside the trimmed ranges
may stay allocated in the image file, except the 16 KiB chunks that DiskImages2
rewrites at unaligned extent edges, and the amount released must lie between
those blocks and all blocks in the ranges, with 64 KiB of slack. Both header
groups must be unchanged, and after remounting `fsck_exfat` must be clean and
every file unchanged. A refusal must leave the host unchanged and the volume
mounted; for a busy virtual device, VeraCrypt has already unmounted the
filesystem and keeps the volume attached. The `host-4k` scenario is a partial
check: the test attaches its host with `hdiutil attach -blocksize`, through the
legacy disk image framework, which ignores UNMAP.

A full run needs about 2800 MiB (2.7 GiB) of free space in the temporary
directory (`TMPDIR`, which is `/tmp` under `sudo`) and takes about 5 minutes;
`--quick` needs 384 MiB and takes about 2 minutes, both measured on an Apple
Silicon Mac with a FUSE-T build. Do not open the test's volumes in Finder while
it runs: Finder writes to them, and the checks report a failure. See `--help`
for the other options. To run the 10 quick scenarios, then all 23:

```sh
sudo python3 Tests/test_macos_trim.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt" --quick
sudo python3 Tests/test_macos_trim.py --binary "$VC_TEST_BUILD_SRC/Main/VeraCrypt"
```

The test exits with 0 when every check passes, with 1 when a check fails or the
test refuses to start, for example because VeraCrypt cannot verify another
mounted volume, and with 2 on SKIP or on a usage error. It prints its seed at
the start; `--seed` repeats a run. `--oracle-selftest` checks the exFAT reader
and the scenario generators on plain exFAT images, without VeraCrypt or root:

```sh
python3 Tests/test_macos_trim.py --oracle-selftest
```

Use disposable containers for ordinary create/write/fsync/unmount/remount checks,
released-client compatibility, and user/root ownership combinations. Keep logs
private and verify service exit, closed backing-file handles, removed auxiliary
mounts and endpoints, and payload integrity after remounting.
