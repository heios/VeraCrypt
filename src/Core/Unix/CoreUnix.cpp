/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "CoreUnix.h"
#include "Common/Tcdefs.h"
#include "Common/Volumes.h"
#include <errno.h>
#include <string.h>
#include <iostream>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
#include <membership.h>
#include <sys/acl.h>
#include <sys/mount.h>
#endif
#ifdef TC_LINUX
#include <sys/utsname.h>
#endif
#ifdef TC_MACOSX
#include <sys/mount.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/SystemLog.h"
#include "Core/Unix/ExfatFreeSpace.h"
#include "Core/Unix/UnixUser.h"
#include "Driver/Fuse/FuseService.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
	static string CreateFuseTAuxiliaryDirectory (const string &tempDirectory, uid_t userId)
	{
		// SMB covers the mountpoint's permissions and does not preserve the
		// requesting local uid. Enforce access on an unmounted parent instead,
		// including when sudo removes TMPDIR or a user selects a shared TMPDIR.
		const bool elevated = geteuid() == 0;
		const bool userAcl = elevated && userId != 0;
		const string directoryTemplate = tempDirectory + (elevated ? "/.veracrypt_aux_root_" : "/.veracrypt_aux_")
			+ StringConverter::ToSingle (static_cast <uint64> (userId)) + "-XXXXXXXXXXXX";
		uuid_t userUuid;
		if (userAcl && mbr_uid_to_uuid (userId, userUuid) != 0)
			throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (directoryTemplate));
		vector <char> temporary (directoryTemplate.begin(), directoryTemplate.end());
		temporary.push_back ('\0');
		throw_sys_sub_if (mkdtemp (&temporary[0]) == NULL, tempDirectory);
		bool ready = false;
		finally_do_arg2 (const char *, &temporary[0], bool &, ready, { if (!finally_arg2) rmdir (finally_arg); });
		const string directory = &temporary[0];

		const int fd = open (directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		throw_sys_sub_if (fd == -1, directory);
		finally_do_arg (int, fd, { close (finally_arg); });
		struct statfs filesystem;
		throw_sys_sub_if (fstatfs (fd, &filesystem) == -1, directory);
		if (filesystem.f_flags & MNT_IGNORE_OWNERSHIP)
			throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (directory)
				+ L"\nThe temporary filesystem must enforce ownership.");
		struct stat info;
		throw_sys_sub_if (fstat (fd, &info) == -1, directory);
		if (!S_ISDIR (info.st_mode) || info.st_uid != (elevated ? 0 : userId))
			throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (directory));
		// Keep elevated parents root-owned so the caller cannot replace paths
		// used by privileged setup. Clear inherited ACLs even without a grant.
		acl_t acl = acl_init (userAcl ? 1 : 0);
		throw_sys_sub_if (acl == NULL, directory);
		finally_do_arg (acl_t *, &acl, { acl_free (*finally_arg); });
		if (userAcl)
		{
			acl_entry_t entry;
			throw_sys_sub_if (acl_create_entry (&acl, &entry) == -1, directory);
			throw_sys_sub_if (acl_set_tag_type (entry, ACL_EXTENDED_ALLOW) == -1, directory);
			throw_sys_sub_if (acl_set_qualifier (entry, userUuid) == -1, directory);
			throw_sys_sub_if (acl_set_permset_mask_np (entry,
				ACL_LIST_DIRECTORY | ACL_SEARCH | ACL_READ_ATTRIBUTES | ACL_READ_SECURITY) == -1, directory);
		}
		throw_sys_sub_if (acl_set_fd_np (fd, acl, ACL_TYPE_EXTENDED) == -1, directory);
		throw_sys_sub_if (fchmod (fd, 0700) == -1, directory);
		throw_sys_sub_if (fstat (fd, &info) == -1, directory);
		if ((info.st_mode & 0777) != 0700)
			throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (directory));

		ready = true;
		return directory;
	}

	static bool IsOtherUsersFuseTAuxiliaryMount (const MountedFilesystem &mount, uid_t userId, uid_t realUserId)
	{
		// Preserve root's existing discovery scope; only unprivileged callers
		// can be excluded by the private parent.
		if (mount.Type != "smbfs" || mount.Owner != 0 || userId == 0)
			return false;
		const string path = mount.MountPoint;
		const string parent = path.substr (0, path.find_last_of ('/'));
		const string name = parent.substr (parent.find_last_of ('/') + 1);
		const string prefix = ".veracrypt_aux_root_";
		if (name.compare (0, prefix.size(), prefix) == 0)
		{
			const string id = name.substr (prefix.size(), name.find ('-', prefix.size()) - prefix.size());
			if (!id.empty() && id.find_first_not_of ("0123456789") == string::npos)
				return id != StringConverter::ToSingle (static_cast <uint64> (userId))
					&& id != StringConverter::ToSingle (static_cast <uint64> (realUserId));
		}
		// Preserve metadata discovery for legacy paths: an ACL may grant
		// traversal despite a foreign-owned parent with mode 0700.
		return false;
	}
#endif

#ifdef TC_LINUX
	static string GetTmpUser ();
	static bool GetLinuxKernelVersion (int &kernelMajor, int &kernelMinor);
	static bool IsLinuxKernelModuleLoaded (const string &moduleName);
	static bool IsLinuxKernelVersionAtLeast (int major, int minor);
	static bool IsNtfsReadWriteKernelModuleAvailable ();
	static bool SamePath (const string& path1, const string& path2);
#endif

	// Struct to hold terminal emulator information
	struct TerminalInfo {
		const char* name;
		const char** args;
		const char** dependency_path;
	};

	// Popular terminal emulators data and arguments
	static const char* xterm_args[] = {"-T", "fsck", "-e", NULL};

	static const char* gnome_args[] = {"--title", "fsck", "--", "sh", "-c", NULL};
	static const char* gnome_deps[] = {"dbus-launch", NULL};

	static const char* konsole_args[] = {"--hold", "-p", "tabtitle=fsck", "-e", "sh", "-c", NULL};
	static const char* xfce4_args[] = {"--title=fsck", "-x", "sh", "-c", NULL};
	static const char* mate_args[] = {"--title", "fsck", "--", "sh", "-c", NULL};
	static const char* lxterminal_args[] = {"--title=fsck", "-e", "sh", "-c", NULL};
	static const char* terminator_args[] = {"-T", "fsck", "-x", "sh", "-c", NULL};
	static const char* urxvt_args[] = {"-title", "fsck", "-e", "sh", "-c", NULL};
	static const char* st_args[] = {"-t", "fsck", "-e", "sh", "-c", NULL};

	// List of popular terminal emulators
	static const TerminalInfo TERMINALS[] = {
		{"xterm", xterm_args, NULL},
		{"gnome-terminal", gnome_args, gnome_deps},
		{"konsole", konsole_args, NULL},
		{"xfce4-terminal", xfce4_args, NULL},
		{"mate-terminal", mate_args, NULL},
		{"lxterminal", lxterminal_args, NULL},
		{"terminator", terminator_args, NULL},
		{"urxvt", urxvt_args, NULL},
		{"st", st_args, NULL},
		{NULL, NULL, NULL}
	};

	CoreUnix::CoreUnix ()
	{
		// Additional read-only core instances may be created for GUI discovery.
		// Locale and signal disposition are process state, not instance state.
		static const bool initialized = [] () {
			signal (SIGPIPE, SIG_IGN);
			char *loc = setlocale (LC_ALL, "");
			if (!loc || string (loc) == "C") setlocale (LC_ALL, "en_US.UTF-8");
			return true;
		} ();
		(void) initialized;
	}

	CoreUnix::~CoreUnix ()
	{
	}

	void CoreUnix::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		if (!mountedVolume->MountPoint.IsEmpty())
			DismountFilesystem (mountedVolume->MountPoint, false);

		// Find system fsck first
		std::string errorMsg;
		std::string fsckPath = Process::FindSystemBinary("fsck", errorMsg);
		if (fsckPath.empty()) {
			throw SystemException(SRC_POS, errorMsg);
		}

		list <string> args;

		string xargs = fsckPath + " ";  // Use absolute fsck path

#ifdef TC_LINUX
		if (!repair)
			xargs += "-n ";
		else
			xargs += "-r ";
#endif

		xargs += string (mountedVolume->VirtualDevice) + "; echo '[Done]'; read W";
		// Try each terminal
		for (const TerminalInfo* term = TERMINALS; term->name != NULL; ++term) {
			errno = 0;
			std::string termPath = Process::FindSystemBinary(term->name, errorMsg);
			if (termPath.length() > 0) {
				// check dependencies
				if (term->dependency_path) {
					bool depFound = true;
					for (const char** dep = term->dependency_path; *dep != NULL; ++dep) {
						string depPath = Process::FindSystemBinary(*dep, errorMsg);
						if (depPath.empty()) {
							depFound = false;
							break;
						}
					}

					if (!depFound) {
						continue; // dependency not found, skip 
					}
				}

				// Build args
				std::list<std::string> args;
				for (const char** arg = term->args; *arg != NULL; ++arg) {
					args.push_back(*arg);
				}
				args.push_back(xargs);

				try {
					Process::Execute (termPath, args, 1000);
					return;
				}
				catch (TimeOut&) {
					return;
				}
				catch (SystemException&) {
					// Continue to next terminal
				}
			}
		}

		throw TerminalNotFound();
	}

	void CoreUnix::DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
	{
		list <string> args;

#ifdef TC_MACOSX
		if (force)
			args.push_back ("-f");
#endif
		args.push_back ("--");
		args.push_back (mountPoint);

		Process::Execute ("umount", args);
	}

#ifdef TC_LINUX
	void CoreUnix::DismountFilesystemLazy (const DirectoryPath &mountPoint) const
	{
		list <string> args;
		args.push_back ("-l");
		args.push_back ("--");
		args.push_back (mountPoint);

		Process::Execute ("umount", args);
	}
#endif

	// Mounting a device-hosted volume as root leaves a record of its data area in
	// /var/run/veracrypt/<device name>, keyed by the first sector of the host device and bound
	// to the auxiliary mount serving the volume. TRIM after unmount needs the data offset,
	// which VolumeInfo does not carry, and must be sure that the device still holds the volume
	// that was mounted. The directory is root-only writable and cleared at boot, like the
	// device naming.
	static const char VolumeRecordDirectory[] = "/var/run/veracrypt";

	string CoreUnix::GetDeviceHostedVolumeRecordName (const FilesystemPath &devicePath) const
	{
		const string device = GetTrimDevicePath (devicePath);
		return device.substr (device.rfind ('/') + 1);
	}

	string CoreUnix::GetDeviceHostedVolumeRecordPath (const FilesystemPath &devicePath) const
	{
		return string (VolumeRecordDirectory) + "/" + GetDeviceHostedVolumeRecordName (devicePath);
	}

	// Opens the record directory if it is root-owned and neither group nor world writable.
	// Records are opened relative to the returned descriptor, so the directory that was
	// checked is the one used.
	int CoreUnix::OpenDeviceHostedVolumeRecordDirectory ()
	{
		int fd = open (VolumeRecordDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
		if (fd == -1)
			return -1;

		struct stat st;
		if (fstat (fd, &st) == 0 && S_ISDIR (st.st_mode) && st.st_uid == 0 && !(st.st_mode & (S_IWGRP | S_IWOTH)))
			return fd;

		close (fd);
		return -1;
	}

	void CoreUnix::RecordDeviceHostedVolume (const Volume &volume, const DirectoryPath &auxMountPoint) const
	{
		// Only a normal volume without protection in the current format can be trimmed; a
		// legacy (V1) volume keeps its data right behind a 512-byte header
		if (geteuid() != 0 || !SupportsTrimAfterDismount()
			|| volume.GetType() != VolumeType::Normal || volume.GetProtectionType() != VolumeProtection::None
			|| volume.GetLayout()->GetDataOffset (volume.GetHostSize()) < TC_VOLUME_DATA_OFFSET)
			return;

		// A record that cannot be written only disables TRIM; the mount must not fail
		try
		{
			DeviceVolumeRecord record;
			memset (&record, 0, sizeof (record));
			record.DataOffset = volume.GetLayout()->GetDataOffset (volume.GetHostSize());
			record.DataSize = volume.GetSize();
			record.Type = (uint8) volume.GetType();
			record.Protection = (uint8) volume.GetProtectionType();

			MountedFilesystemList auxMounts = GetMountedFilesystems (DevicePath(), auxMountPoint);
			if (auxMounts.size() != 1)
			{
				SystemLog::WriteError ("Auxiliary mount " + string (auxMountPoint) + " not found; TRIM after unmount is unavailable for this volume");
				return;
			}
			memcpy (record.MountId, auxMounts.front()->MountId, sizeof (record.MountId));

			Buffer sector (volume.GetSectorSize());
			if (volume.GetFile()->ReadAt (sector, 0) != sector.Size())
				throw ParameterIncorrect (SRC_POS);
			memcpy (record.Header, sector.Ptr(), sizeof (record.Header));

			if (mkdir (VolumeRecordDirectory, 0755) != 0)
				throw_sys_sub_if (errno != EEXIST, VolumeRecordDirectory);

			int dirFd = OpenDeviceHostedVolumeRecordDirectory();
			if (dirFd == -1)
				throw ParameterIncorrect (SRC_POS);
			finally_do_arg (int, dirFd, { close (finally_arg); });
			fchmod (dirFd, 0755);	// whatever the umask, so that IsTrimSupported can stat the record

			const string name = GetDeviceHostedVolumeRecordName (volume.GetPath());
			int fd = openat (dirFd, name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
			throw_sys_sub_if (fd == -1, StringConverter::ToWide (name));
			finally_do_arg (int, fd, { close (finally_arg); });

			fchmod (fd, 0600);
			throw_sys_sub_if (write (fd, &record, sizeof (record)) != (ssize_t) sizeof (record), StringConverter::ToWide (name));
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
	}

	void CoreUnix::RemoveDeviceHostedVolumeRecord (const VolumePath &devicePath) const
	{
		if (!SupportsTrimAfterDismount())
			return;

		try
		{
			int dirFd = OpenDeviceHostedVolumeRecordDirectory();
			if (dirFd == -1)
				return;
			finally_do_arg (int, dirFd, { close (finally_arg); });
			unlinkat (dirFd, GetDeviceHostedVolumeRecordName (devicePath).c_str(), 0);
		}
		catch (exception &) { }
	}

	// Reads the record of the volume mounted from the host device and checks that it is
	// root-written, describes this volume and its auxiliary mount, and a data area of the
	// volume's size inside the device
	CoreUnix::DeviceVolumeRecord CoreUnix::ReadDeviceHostedVolumeRecord (const VolumeInfo &volume, uint64 hostSize) const
	{
		int dirFd = OpenDeviceHostedVolumeRecordDirectory();
		if (dirFd == -1)
			throw TrimFailed (SRC_POS, L"TRIM_MOUNT_RECORD_INVALID");
		finally_do_arg (int, dirFd, { close (finally_arg); });

		int fd = openat (dirFd, GetDeviceHostedVolumeRecordName (volume.Path).c_str(), O_RDONLY | O_NOFOLLOW);
		if (fd == -1)
			throw TrimFailed (SRC_POS, L"TRIM_NO_MOUNT_RECORD");
		finally_do_arg (int, fd, { close (finally_arg); });

		MountedFilesystemList auxMounts = GetMountedFilesystems (DevicePath(), volume.AuxMountPoint);
		if (auxMounts.size() != 1)
			throw TrimFailed (SRC_POS, L"TRIM_VOLUME_CHANGED");

		struct stat st;
		DeviceVolumeRecord record;
		if (fstat (fd, &st) == -1 || !S_ISREG (st.st_mode) || st.st_uid != 0 || (st.st_mode & (S_IRWXG | S_IRWXO))
			|| st.st_size != (off_t) sizeof (record) || read (fd, &record, sizeof (record)) != (ssize_t) sizeof (record)
			|| memcmp (record.MountId, auxMounts.front()->MountId, sizeof (record.MountId)) != 0
			|| record.Type != VolumeType::Normal || record.Type != volume.Type
			|| record.Protection != VolumeProtection::None || record.Protection != volume.Protection
			|| hostSize < TC_TOTAL_VOLUME_HEADERS_SIZE
			|| record.DataOffset < TC_VOLUME_DATA_OFFSET
			|| record.DataOffset > hostSize - TC_VOLUME_HEADER_GROUP_SIZE
			|| record.DataSize != volume.Size
			|| record.DataSize > hostSize - TC_VOLUME_HEADER_GROUP_SIZE - record.DataOffset)
		{
			throw TrimFailed (SRC_POS, L"TRIM_MOUNT_RECORD_INVALID");
		}

		return record;
	}

	bool CoreUnix::HostHeaderMatches (int fd, uint32 blockSize, const DeviceVolumeRecord &record)
	{
		Buffer sector (max (blockSize, (uint32) sizeof (record.Header)));
		return pread (fd, sector, sector.Size(), 0) == (ssize_t) sector.Size()
			&& memcmp (sector, record.Header, sizeof (record.Header)) == 0;
	}

	bool CoreUnix::IsTrimSupported (shared_ptr <VolumeInfo> mountedVolume, wstring &reason) const
	{
		if (!SupportsTrimAfterDismount())
		{
			reason = L"TRIM_NOT_SUPPORTED_ON_PLATFORM";
			return false;
		}

		try
		{
			uint64 freeBytes;
			// Legacy (V1) volumes are told apart as in VolumePropertiesDialog
			if (!mountedVolume || mountedVolume->Type != VolumeType::Normal || mountedVolume->SystemEncryption || mountedVolume->MinRequiredProgramVersion < 0x10b)
				reason = L"TRIM_UNSUPPORTED_VOLUME_TYPE";
			else if (mountedVolume->Protection != VolumeProtection::None)
				reason = L"TRIM_UNSUPPORTED_PROTECTION";
			else if (!mountedVolume->Path.IsDevice())
				reason = L"TRIM_UNSUPPORTED_HOST";
			else
			{
				struct stat st;
				// The record is written at mount; the elevated service checks it, this only spares
				// a request that would be refused. GetDeviceHostedVolumeRecordPath throws TrimFailed
				// for an unsupported device.
				if (stat (GetDeviceHostedVolumeRecordPath (mountedVolume->Path).c_str(), &st) != 0)
					reason = L"TRIM_NO_MOUNT_RECORD";
				else if (mountedVolume->MountPoint.IsEmpty() || mountedVolume->VirtualDevice.IsEmpty())
					reason = L"TRIM_FILESYSTEM_NO_TRIM";
				else if (!IsExfatMounted (*mountedVolume, freeBytes))
					reason = L"TRIM_UNSUPPORTED_FILESYSTEM";
				else
					return true;
			}
		}
		catch (TrimFailed &e)
		{
			reason = e.GetSubject();
		}

		return false;
	}

	// Discard requests stay modest for USB bridges: at most 1 GiB per extent and 256 extents per request
	static const uint64 MaxTrimExtentLength = 1ULL << 30;
	static const size_t MaxTrimExtentsPerRequest = 256;

	uint64 CoreUnix::DismountVolumeAndTrim (shared_ptr <VolumeInfo> mountedVolume, wstring &skipReason)
	{
		skipReason.clear();

		// Everything up to the filesystem unmount runs before anything changes; the volume
		// stays mounted when a check fails. Free space of a normal volume maps linearly onto
		// the host device. The allocation bitmap is read once the virtual device is detached,
		// when nothing can write to the filesystem any more, so the free clusters it shows
		// can be discarded on the host after the volume is dismounted.
		if (!mountedVolume)
			throw ParameterIncorrect (SRC_POS);

		shared_ptr <VolumeInfo> current = GetMountedVolume (mountedVolume->Path);
		if (!current || current->SerialInstanceNumber != mountedVolume->SerialInstanceNumber || current->AuxMountPoint != mountedVolume->AuxMountPoint)
			throw TrimFailed (SRC_POS, L"TRIM_VOLUME_CHANGED");
		mountedVolume = current;

		wstring reason;
		if (!IsTrimSupported (mountedVolume, reason))
			throw TrimFailed (SRC_POS, reason);

		// The filesystem driver's own count of free space, to cross-check the parser later
		uint64 driverFreeBytes;
		if (!IsExfatMounted (*mountedVolume, driverFreeBytes))
			throw TrimFailed (SRC_POS, L"TRIM_UNSUPPORTED_FILESYSTEM");

		const string hostDevice = GetTrimDevicePath (mountedVolume->Path);
		const string virtualDevice = GetTrimDevicePath (mountedVolume->VirtualDevice);
		const uint64 dataSize = mountedVolume->Size;
		uint64 hostSize;
		uint32 hostBlockSize;
		DeviceVolumeRecord record;
		{
			int fd = OpenTrimDevice (hostDevice, false, hostSize, hostBlockSize);
			finally_do_arg (int, fd, { close (finally_arg); });

			if (!TrimDeviceSupportsDiscard (fd, hostDevice))
				throw TrimFailed (SRC_POS, L"TRIM_HOST_DEVICE_UNSUPPORTED");

			record = ReadDeviceHostedVolumeRecord (*mountedVolume, hostSize);
			if (!HostHeaderMatches (fd, hostBlockSize, record))
				throw TrimFailed (SRC_POS, L"TRIM_HOST_DEVICE_CHANGED");
		}

		// Unmount only the filesystem; the virtual device stays attached for the check.
		// A busy filesystem fails here and nothing changes.
		try
		{
			DismountFilesystem (mountedVolume->MountPoint, false);
		}
		catch (ExecutedProcessFailed &e)
		{
			if (e.GetErrorOutput().find ("busy") != string::npos)
				throw MountedVolumeInUse (SRC_POS);
			throw;
		}
		sync();

		// From here on the volume gets dismounted in any case; TRIM runs only if every check
		// passes. The filesystem check is a hard precondition: it finds an allocation bitmap
		// that disagrees with the directory tree, which neither the parser nor the free space
		// cross-check can see. Any problem reported, a missing checker, a crash or a timeout
		// skips TRIM. Only the exit code is logged, as the output can name files.
		try
		{
			CheckExfatFilesystem (virtualDevice);
		}
		catch (ExecutedProcessFailed &e)
		{
			SystemLog::WriteError ("The exFAT check of " + virtualDevice + " failed with exit code " + StringConverter::ToSingle (e.GetExitCode()));
			skipReason = L"TRIM_FILESYSTEM_CHECK_FAILED";
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
			skipReason = L"TRIM_FILESYSTEM_CHECK_FAILED";
		}
		catch (...)
		{
			skipReason = L"TRIM_FILESYSTEM_CHECK_FAILED";
		}

		// The check can take minutes, during which the virtual device may have been mounted
		// again and written to; the dismount below would unmount that silently
		if (skipReason.empty() && !GetMountedFilesystems (mountedVolume->VirtualDevice).empty())
			skipReason = L"TRIM_VOLUME_REMOUNTED";

		// Reads the free ranges from the volume image, which the mount service still serves
		// after the virtual device is detached. Any failure only skips TRIM.
		vector <ExfatRange> freeRanges;
		bool freeRangesRead = false;
		DetachedVolumeHandler readFreeRanges = [&] (const VolumeInfo &volume)
		{
			if (!skipReason.empty())
				return;
			freeRangesRead = true;

			try
			{
				const string image = string (volume.AuxMountPoint) + FuseService::GetVolumeImagePath();
				int fd = open (image.c_str(), O_RDONLY | O_NOFOLLOW);
				throw_sys_sub_if (fd == -1, StringConverter::ToWide (image));
				finally_do_arg (int, fd, { close (finally_arg); });

				struct stat st;
				throw_sys_sub_if (fstat (fd, &st) == -1, StringConverter::ToWide (image));
				if (!S_ISREG (st.st_mode) || (uint64) st.st_size != dataSize)
					throw TrimFailed (SRC_POS, L"TRIM_VOLUME_SIZE_MISMATCH");
#ifdef TC_MACOSX
				// The image must be served by the auxiliary mount the record was written for,
				// not by a mount put in its place after the record was checked
				struct statfs fs;
				if (fstatfs (fd, &fs) == -1 || fs.f_fsid.val[0] != record.MountId[0] || fs.f_fsid.val[1] != record.MountId[1])
					throw TrimFailed (SRC_POS, L"TRIM_IMAGE_MOUNT_CHANGED");
#endif

				freeRanges = GetExfatFreeRanges ([fd] (uint64 offset, const BufferPtr &buffer)
				{
					if (pread (fd, buffer, buffer.Size(), offset) != (ssize_t) buffer.Size())
						throw TrimFailed (SRC_POS, L"TRIM_IMAGE_UNREADABLE");
				}, dataSize);

				uint64 freeBytes = 0;
				for (const ExfatRange &range : freeRanges)
					freeBytes += range.Length;

				// Guards against the parser over-reporting free space only. The driver takes
				// its count from the same bitmap, so a bitmap inconsistent with the directory
				// tree passes here; that is what the filesystem check above is for.
				if (freeBytes > driverFreeBytes)
					throw TrimFailed (SRC_POS, L"TRIM_FREE_SPACE_MISMATCH");
			}
			catch (TrimFailed &e)
			{
				skipReason = e.GetSubject();
			}
			catch (exception &e)
			{
				skipReason = StringConverter::ToExceptionString (e);
			}
			catch (...)
			{
				skipReason = L"TRIM_IMAGE_UNREADABLE";
			}

			if (!skipReason.empty())
				freeRanges.clear();
		};

		// A failure from here on leaves the filesystem unmounted but the volume attached,
		// except an unconfirmed service exit, which is reported as in a plain unmount
		try
		{
			mountedVolume = DetachVolume (mountedVolume, false, false, readFreeRanges);
		}
		catch (MountedVolumeInUse &)
		{
			throw TrimDismountFailed (SRC_POS, L"TRIM_VOLUME_IN_USE");
		}
		catch (DismountServiceCleanupFailed &) { throw; }
		catch (exception &e)
		{
			throw TrimDismountFailed (SRC_POS, StringConverter::ToExceptionString (e));
		}
		CompleteDismount (mountedVolume);

		if (skipReason.empty() && !freeRangesRead)
			skipReason = L"TRIM_IMAGE_UNREADABLE";
		if (!skipReason.empty())
			return 0;

		// The volume is already dismounted; a failure from here on only ends TRIM, and the
		// free space discarded until then is reported
		uint64 trimmedBytes = 0;
		try
		{
			uint64 size;
			uint32 blockSize;
			int fd = OpenTrimDevice (hostDevice, true, size, blockSize);
			finally_do_arg (int, fd, { close (finally_arg); });

			// The device is checked again on the descriptor that the discards go to
			if (size != hostSize || blockSize != hostBlockSize || !HostHeaderMatches (fd, blockSize, record))
			{
				skipReason = L"TRIM_HOST_DEVICE_CHANGED";
				return 0;
			}

			FlushTrimDevice (fd);

			vector <ExfatRange> extents;

			auto discard = [&] ()
			{
				if (extents.empty())
					return;

				DiscardTrimExtents (fd, hostDevice, extents);
				for (const ExfatRange &extent : extents)
					trimmedBytes += extent.Length;
				extents.clear();
			};

			try
			{
				for (const ExfatRange &range : freeRanges)
				{
					// Host offset = data area offset + filesystem offset, kept inside the data area
					// (which excludes both header groups) and rounded inwards to whole host blocks
					uint64 start = record.DataOffset + range.Offset;
					uint64 end = min (start + range.Length, record.DataOffset + dataSize);
					start = (start + blockSize - 1) / blockSize * blockSize;
					end = end / blockSize * blockSize;

					while (start < end)
					{
						ExfatRange extent = { start, min (end - start, MaxTrimExtentLength) };
						extents.push_back (extent);
						start += extent.Length;

						if (extents.size() == MaxTrimExtentsPerRequest)
							discard();
					}
				}

				discard();
			}
			catch (SystemException &e)
			{
				// Report how much was discarded before the failure
				SystemLog::WriteException (e);
				skipReason = L"TRIM_UNMAP_FAILED";
			}

			FlushTrimDevice (fd);
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
			if (skipReason.empty())
				skipReason = StringConverter::ToExceptionString (e);
		}

		return trimmedBytes;
	}

	shared_ptr <VolumeInfo> CoreUnix::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		mountedVolume = DetachVolume (mountedVolume, ignoreOpenFiles, syncVolumeInfo, DetachedVolumeHandler());
		CompleteDismount (mountedVolume);
		return mountedVolume;
	}

	void CoreUnix::CompleteDismount (shared_ptr <VolumeInfo> mountedVolume)
	{
		if (mountedVolume->Path.IsDevice())
			RemoveDeviceHostedVolumeRecord (mountedVolume->Path);

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeDismountedEvent.Raise (eventArgs);
	}

	shared_ptr <VolumeInfo> CoreUnix::DetachVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo, const DetachedVolumeHandler &onDetached)
	{
		if (!mountedVolume->MountPoint.IsEmpty())
		{
#ifdef TC_LINUX
			try
			{
				DismountFilesystem (mountedVolume->MountPoint, ignoreOpenFiles);
			}
			catch (ExecutedProcessFailed &e)
			{
				throw FilesystemDismountFailed (e);
			}
#else
			DismountFilesystem (mountedVolume->MountPoint, ignoreOpenFiles);
#endif

			// Delete mount directory if a default path has been used
			if (string (mountedVolume->MountPoint).find (GetDefaultMountPointPrefix()) == 0)
				mountedVolume->MountPoint.Delete();
		}

		try
		{
			DismountNativeVolume (mountedVolume);
		}
#ifdef TC_LINUX
		catch (ExecutedProcessFailed &e)
		{
			throw FilesystemDismountFailed (e);
		}
#endif
		catch (NotApplicable &) { }

		// On Linux, DismountNativeVolume detaches the loop device once it is verified to belong to the volume
#ifndef TC_LINUX
		if (!mountedVolume->LoopDevice.IsEmpty())
		{
			try
			{
				DetachLoopDevice (mountedVolume->LoopDevice);
			}
			catch (ExecutedProcessFailed&) { }
		}
#endif

		if (syncVolumeInfo || mountedVolume->Protection == VolumeProtection::HiddenVolumeReadOnly)
		{
			sync();
			VolumeInfoList ml = GetMountedVolumes (mountedVolume->Path);

			if (ml.size() > 0)
				mountedVolume = ml.front();
		}

		if (onDetached)
			onDetached (*mountedVolume);

		list <string> args;
		args.push_back ("--");
		args.push_back (mountedVolume->AuxMountPoint);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("umount", args);
				break;
			}
			catch (ExecutedProcessFailed &e)
			{
				if (t > 10)
#ifdef TC_LINUX
					throw FilesystemDismountFailed (e);
#else
					throw;
#endif
				Thread::Sleep (200);
			}
		}

		try
		{
			mountedVolume->AuxMountPoint.Delete();
		}
		catch (...)	{ }

		return mountedVolume;
	}

#ifdef TC_LINUX
	shared_ptr <VolumeInfo> CoreUnix::EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume)
	{
		unique_ptr <Exception> firstException;

		if (!mountedVolume->MountPoint.IsEmpty())
		{
			bool mountPointMounted = true;
			bool mountPointDetached = false;

			try
			{
				mountPointMounted = !GetMountedFilesystems (DevicePath(), mountedVolume->MountPoint).empty();
			}
			catch (...) { }

			if (mountPointMounted)
			{
				try
				{
					DismountFilesystemLazy (mountedVolume->MountPoint);
					mountPointDetached = true;
				}
				catch (Exception &e)
				{
					if (!firstException.get())
						firstException.reset (e.CloneNew());
				}
			}

			if ((!mountPointMounted || mountPointDetached) && string (mountedVolume->MountPoint).find (GetDefaultMountPointPrefix()) == 0)
			{
				try
				{
					mountedVolume->MountPoint.Delete();
				}
				catch (...) { }
			}
		}

		try
		{
			DismountNativeVolumeDeferred (mountedVolume);
		}
		catch (NotApplicable&) { }
		catch (Exception &e)
		{
			if (!firstException.get())
				firstException.reset (e.CloneNew());
		}

		if (!mountedVolume->AuxMountPoint.IsEmpty())
		{
			bool auxMountPointMounted = true;
			bool auxMountPointDetached = false;

			try
			{
				auxMountPointMounted = !GetMountedFilesystems (DevicePath(), mountedVolume->AuxMountPoint).empty();
			}
			catch (...) { }

			if (auxMountPointMounted)
			{
				list <string> args;
				args.push_back ("--");
				args.push_back (mountedVolume->AuxMountPoint);

				try
				{
					for (int t = 0; true; t++)
					{
						try
						{
							Process::Execute ("umount", args);
							auxMountPointDetached = true;
							break;
						}
						catch (ExecutedProcessFailed&)
						{
							if (t > 10)
								throw;
							Thread::Sleep (200);
						}
					}
				}
				catch (ExecutedProcessFailed&)
				{
					try
					{
						DismountFilesystemLazy (mountedVolume->AuxMountPoint);
						auxMountPointDetached = true;
					}
					catch (Exception &e)
					{
						if (!firstException.get())
							firstException.reset (e.CloneNew());
					}
				}
				catch (Exception &e)
				{
					if (!firstException.get())
						firstException.reset (e.CloneNew());
				}
			}

			if (!auxMountPointMounted || auxMountPointDetached)
			{
				try
				{
					mountedVolume->AuxMountPoint.Delete();
				}
				catch (...) { }
			}
		}

		if (firstException.get())
			firstException->Throw();

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeDismountedEvent.Raise (eventArgs);

		return mountedVolume;
	}
#endif

	bool CoreUnix::FilesystemSupportsLargeFiles (const FilePath &filePath) const
	{
		string path = filePath;
		size_t pos;

		while ((pos = path.find_last_of ('/')) != string::npos)
		{
			path = path.substr (0, pos);

			if (path.empty())
				break;

			try
			{
				MountedFilesystemList filesystems = GetMountedFilesystems (DevicePath(), path);
				if (!filesystems.empty())
				{
					const MountedFilesystem &fs = *filesystems.front();

					if (fs.Type == "fat"
						|| fs.Type == "fat32"
						|| fs.Type == "vfat"
						|| fs.Type == "fatfs"
						|| fs.Type == "msdos"
						|| fs.Type == "msdosfs"
						|| fs.Type == "umsdos"
						|| fs.Type == "dos"
						|| fs.Type == "dosfs"
						|| fs.Type == "pcfs"
						)
					{
						return false;
					}

					return true;
				}
			}
			catch (...) { }
		}

		return true;	// Prevent errors if the filesystem cannot be identified
	}

	bool CoreUnix::FilesystemSupportsUnixPermissions (const DevicePath &devicePath) const
	{
		File device;
		device.Open (devicePath);

		Buffer bootSector (device.GetDeviceSectorSize());
		device.SeekAt (0);
		device.ReadCompleteBuffer (bootSector);

		uint8 *b = bootSector.Ptr();

		return memcmp (b + 3,  "NTFS", 4) != 0
			&& memcmp (b + 54, "FAT", 3) != 0
			&& memcmp (b + 82, "FAT32", 5) != 0
			&& memcmp (b + 3,  "EXFAT", 5) != 0;
	}

	string CoreUnix::GetDefaultMountPointPrefix () const
	{
		const char *envPrefix = getenv ("VERACRYPT_MOUNT_PREFIX");
		if (envPrefix && !string (envPrefix).empty())
			return envPrefix;

		if (FilesystemPath ("/media").IsDirectory())
			return "/media/veracrypt";
#ifdef TC_LINUX
		if (FilesystemPath ("/run/media").IsDirectory())
			return "/run/media/veracrypt";
#endif
		if (FilesystemPath ("/mnt").IsDirectory())
			return "/mnt/veracrypt";

		return GetTempDirectory() + "/veracrypt_mnt";
	}

	uint32 CoreUnix::GetDeviceSectorSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.GetDeviceSectorSize();
	}

	uint64 CoreUnix::GetDeviceSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.Length();
	}

	DirectoryPath CoreUnix::GetDeviceMountPoint (const DevicePath &devicePath) const
	{
		DevicePath devPath = devicePath;
#ifdef TC_MACOSX
		if (string (devPath).find ("/dev/rdisk") != string::npos)
			devPath = string ("/dev/") + string (devicePath).substr (6);
#endif
		MountedFilesystemList mountedFilesystems = GetMountedFilesystems (devPath);

		if (mountedFilesystems.size() < 1)
			return DirectoryPath();

		return mountedFilesystems.front()->MountPoint;
	}

	shared_ptr <VolumeInfo> CoreUnix::ReadAuxiliaryVolumeInfo (const DirectoryPath &auxMountPoint)
	{
		File control;
		control.Open (string (auxMountPoint) + FuseService::GetControlPath());
		Buffer buffer (8192);
		string data;
		for (uint64 count; (count = control.Read (buffer)) != 0; )
		{
			if (data.size() + count > 1024 * 1024) throw ParameterTooLarge (SRC_POS);
			data.append (reinterpret_cast <const char *> (buffer.Ptr()), count);
		}
		shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr (reinterpret_cast <const uint8 *> (data.data()), data.size())));
		shared_ptr <VolumeInfo> volume = Serializable::DeserializeNew <VolumeInfo> (stream);
		volume->AuxMountPoint = auxMountPoint;
		return volume;
	}

	VolumeInfoList CoreUnix::GetMountedVolumes (const VolumePath &volumePath) const
	{
		VolumeDiscoveryResult result = GetMountedVolumesWithStatus (volumePath);
		if (!result.IsComplete()) throw VolumeDiscoveryFailed (SRC_POS, wstring (result.UnresolvedMounts.front()));
		return result.Volumes;
	}

	VolumeDiscoveryResult CoreUnix::GetMountedVolumesWithStatus (const VolumePath &volumePath) const
	{
		VolumeDiscoveryResult result;
		VolumeInfoList &volumes = result.Volumes;

		foreach_ref (const MountedFilesystem &mf, GetMountedFilesystems ())
		{
#ifdef TC_MACOSX
			if (!mf.IsAuxiliaryMountCandidate (GetFuseMountDirPrefix(), getuid(), GetRealUserId()))
#else
			if (string (mf.MountPoint).find (GetFuseMountDirPrefix()) == string::npos)
#endif
				continue;

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			// Elevated SMB mounts have a root mount-table owner. Their private
			// parent identifies the user; an inaccessible foreign mount is not
			// an unresolved mount of the current user.
			if (IsOtherUsersFuseTAuxiliaryMount (mf, getuid(), GetRealUserId()))
				continue;
#endif

			shared_ptr <VolumeInfo> mountedVol;
			// Introduce a retry mechanism with a timeout for control file access.
			// The list is already filtered to VeraCrypt auxiliary mounts; in
			// FUSE-T builds, the mount table device name varies by backend.
#ifdef VC_MACOSX_FUSET
			int controlFileRetries = volumePath.IsEmpty() ? 1 : 10; // Up to 10 attempts with 500ms sleeps for specific volume lookups
			string controlFileError;
			while (!mountedVol && (controlFileRetries-- > 0))
#endif
			{
				try 
				{
					mountedVol = ReadAuxiliaryVolumeInfo (mf.MountPoint);
				}
				catch (const std::exception& e)
				{
#ifdef VC_MACOSX_FUSET
					controlFileError = StringConverter::ToSingle (StringConverter::ToExceptionString (e));
					if (controlFileRetries > 0)
					{
						// FUSE-T's SMB backend can briefly expose the auxiliary mount
						// before the control file is readable and deserializable.
						Thread::Sleep (500);
					}
#else
					(void) e;
#endif
				}
#ifdef VC_MACOSX_FUSET
				catch (...)
				{
					controlFileError = "unknown exception";
					if (controlFileRetries > 0)
					{
						// FUSE-T's SMB backend can briefly expose the auxiliary mount
						// before the control file is readable and deserializable.
						Thread::Sleep (500);
					}
				}
#endif
			}

			if (!mountedVol)
			{
#ifdef VC_MACOSX_FUSET
				if (!volumePath.IsEmpty())
				{
					stringstream logMessage;
					logMessage << "Failed to read VeraCrypt auxiliary mount control file after retries: "
						<< string (mf.MountPoint) << FuseService::GetControlPath();
					if (!controlFileError.empty())
						logMessage << ": " << controlFileError;
					SystemLog::WriteError (logMessage.str());
				}
#endif
#ifdef TC_MACOSX
				result.UnresolvedMounts.push_back (mf.MountPoint);
#endif
				continue;
			}

			if (!volumePath.IsEmpty() && wstring (mountedVol->Path).compare (volumePath) != 0)
				continue;

			mountedVol->AuxMountPoint = mf.MountPoint;

#ifndef TC_MACOSX
			// Recorded devices may have been released and reused since
			UpdateMountedVolumeInfo (mountedVol);

			if (mountedVol->MountPoint.IsEmpty() && !mountedVol->VirtualDevice.IsEmpty())
			{
				MountedFilesystemList mpl = GetMountedFilesystems (mountedVol->VirtualDevice);

				if (mpl.size() > 0)
					mountedVol->MountPoint = mpl.front()->MountPoint;
			}
#endif

			volumes.push_back (mountedVol);

			if (!volumePath.IsEmpty())
				break;
		}

#ifdef TC_MACOSX
		UpdateMountedVolumesInfo (volumes);
#endif
		return result;
	}

#ifdef TC_MACOSX
	void CoreUnix::UpdateMountedVolumesInfo (VolumeInfoList &volumes) const
	{
		foreach (shared_ptr <VolumeInfo> volume, volumes)
			UpdateMountedVolumeInfo (volume);
	}
#endif

	gid_t CoreUnix::GetRealGroupId () const
	{
		const char *env = getenv ("SUDO_GID");
		if (env)
		{
			try
			{
				string s (env);
				return static_cast <gid_t> (StringConverter::ToUInt64 (s));
			}
			catch (...) { }
		}

		gid_t doasGid;
		if (GetDoasUserIds (nullptr, &doasGid))
			return doasGid;

		return getgid();
	}

	uid_t CoreUnix::GetRealUserId () const
	{
		const char *env = getenv ("SUDO_UID");
		if (env)
		{
			try
			{
				string s (env);
				return static_cast <uid_t> (StringConverter::ToUInt64 (s));
			}
			catch (...) { }
		}

		uid_t doasUid;
		if (GetDoasUserIds (&doasUid, nullptr))
			return doasUid;

		return getuid();
	}

	string CoreUnix::GetTempDirectory () const
	{
		const char *tmpdir = getenv ("TMPDIR");
		string envDir = tmpdir ? tmpdir : "/tmp";

#ifdef TC_LINUX
		/*
		 * If pam_tmpdir.so is in use, a different temporary directory is
		 * allocated for each user ID. We need to mount to the directory used
		 * by the non-root user.
		 */
		if (getuid () == 0 && envDir.size () >= 2
			&& envDir.substr (envDir.size () - 2) == "/0") {
			string tmpuser = GetTmpUser ();
			if (SamePath (envDir, tmpuser + "/0")) {
				/* Substitute the sudo'ing user for 0 */
				char uid[40];
				FILE *fp = fopen ("/proc/self/loginuid", "r");
				if (fp != NULL) {
					if (fgets (uid, sizeof (uid), fp) != nullptr) {
						envDir = tmpuser + "/" + uid;
					}
					fclose (fp);
				}
			}
		}
#endif

		return envDir;
	}

#ifdef TC_LINUX
	static string GetTmpUser ()
	{
		string tmpuser = "/tmp/user";
		FILE *fp = fopen ("/etc/security/tmpdir.conf", "r");
		if (fp == NULL) {
			return tmpuser;
		}
		while (true) {
			/* Parses the same way as pam_tmpdir */
			char line[1024];
			if (fgets (line, sizeof (line), fp) == nullptr) {
				break;
			}
			if (line[0] == '#') {
				continue;
			}
			size_t len = strlen (line);
			if (len > 0 && line[len-1] == '\n') {
				line[len-1] = '\0';
			}
			char *eq = strchr (line, '=');
			if (eq == nullptr) {
				continue;
			}
			*eq = '\0';
			const char *key = line;
			const char *value = eq + 1;
			if (strcmp (key, "tmpdir") == 0) {
				tmpuser = value;
				break;
			}
		}
		fclose (fp);
		return tmpuser;
	}

	static bool SamePath (const string& path1, const string& path2)
	{
		size_t i1 = 0;
		size_t i2 = 0;
		while (i1 < path1.size () && i2 < path2.size ()) {
			if (path1[i1] != path2[i2]) {
				return false;
			}
			/* Any two substrings consisting entirely of slashes compare equal */
			if (path1[i1] == '/') {
				while (i1 < path1.size () && path1[i1] == '/') {
					++i1;
				}
				while (i2 < path2.size () && path2[i2] == '/') {
					++i2;
				}
			}
			else
			{
				++i1;
				++i2;
			}
		}
		return (i1 == path1.size () && i2 == path2.size ());
	}
#endif

	bool CoreUnix::IsMountPointAvailable (const DirectoryPath &mountPoint) const
	{
		return GetMountedFilesystems (DevicePath(), mountPoint).size() == 0;
	}

#ifdef TC_LINUX
	static bool GetLinuxKernelVersion (int &kernelMajor, int &kernelMinor)
	{
		struct utsname kernelInfo;
		if (uname (&kernelInfo) != 0)
			return false;

		kernelMajor = 0;
		kernelMinor = 0;
		int versionFields = sscanf (kernelInfo.release, "%d.%d", &kernelMajor, &kernelMinor);

		if (versionFields < 1)
			return false;

		return true;
	}

	static bool IsLinuxKernelVersionAtLeast (int major, int minor)
	{
		int kernelMajor = 0;
		int kernelMinor = 0;
		if (!GetLinuxKernelVersion (kernelMajor, kernelMinor))
			return false;

		return kernelMajor > major || (kernelMajor == major && kernelMinor >= minor);
	}

	static bool IsLinuxKernelModuleLoaded (const string &moduleName)
	{
		string modulePath = "/sys/module/" + moduleName;
		struct stat moduleStat;
		return stat (modulePath.c_str(), &moduleStat) == 0 && S_ISDIR (moduleStat.st_mode);
	}

	static bool IsNtfsReadWriteKernelModuleAvailable ()
	{
		list <string> args;
		args.push_back ("-F");
		args.push_back ("description");
		args.push_back ("ntfs");

		try
		{
			string description = StringConverter::ToLower (StringConverter::Trim (Process::Execute ("modinfo", args, 2000)));
			// The upstream fs/ntfs module reports "NTFS read-write filesystem driver".
			// ntfs3 compatibility aliases report different wording, such as read/write.
			return description.find ("ntfs") != string::npos
				&& description.find ("read-write") != string::npos
				&& description.find ("filesystem driver") != string::npos;
		}
		catch (...) { }

		return false;
	}

	bool CoreUnix::IsNtfsReadWriteKernelFilesystemTypeAvailable () const
	{
		if (!IsNtfsReadWriteKernelModuleAvailable ())
			return false;

		if (!IsLinuxKernelModuleLoaded ("ntfs"))
		{
			list <string> args;
			args.push_back ("-q");
			args.push_back ("-b");
			args.push_back ("ntfs");

			try
			{
				Process::Execute ("modprobe", args, 5000);
			}
			catch (...) { }
		}

		return IsLinuxKernelModuleLoaded ("ntfs") && IsFilesystemTypeRegistered ("ntfs");
	}

	string CoreUnix::DetectFilesystemType (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-p");
		args.push_back ("-o");
		args.push_back ("value");
		args.push_back ("-s");
		args.push_back ("TYPE");
		args.push_back ("--");
		args.push_back (devicePath);

		try
		{
			return StringConverter::ToLower (StringConverter::Trim (Process::Execute ("blkid", args, 2000)));
		}
		catch (...)
		{
			return string();
		}
	}

	bool CoreUnix::IsFilesystemTypeRegistered (const string &filesystemType) const
	{
		FILE *procFilesystems = fopen ("/proc/filesystems", "r");
		if (!procFilesystems)
			return false;

		bool registered = false;
		char line[256];
		finally_do_arg (FILE *, procFilesystems, fclose (finally_arg););

		while (fgets (line, sizeof (line), procFilesystems))
		{
			string entry = StringConverter::Trim (line);
			size_t separator = entry.find_last_of (" \t");

			if (separator != string::npos)
				entry = entry.substr (separator + 1);

			if (entry == filesystemType)
			{
				registered = true;
				break;
			}
		}

		return registered;
	}

	bool CoreUnix::IsKernelFilesystemTypeAvailable (const string &filesystemType) const
	{
		if (IsFilesystemTypeRegistered (filesystemType))
			return true;

		// This is only used from mount-time paths that run with root-equivalent privileges.
		// If a future unprivileged caller uses it, modprobe is expected to fail silently here.
		list <string> moduleNames;
		moduleNames.push_back (filesystemType);
		moduleNames.push_back ("fs-" + filesystemType);

		foreach (const string &moduleName, moduleNames)
		{
			list <string> args;
			args.push_back ("-q");
			args.push_back ("-b");
			args.push_back (moduleName);

			try
			{
				Process::Execute ("modprobe", args, 5000);
			}
			catch (...) { }

			if (IsFilesystemTypeRegistered (filesystemType))
				return true;
		}

		return false;
	}

	string CoreUnix::SelectNtfsKernelFilesystemType () const
	{
		bool kernelHasStandaloneNtfs = IsLinuxKernelVersionAtLeast (7, 1);

		// Linux 6.9-7.0 may expose an "ntfs" compatibility alias from ntfs3,
		// but that legacy mount path is forced read-only. Only use "ntfs" where
		// the standalone read/write in-kernel driver is expected upstream, or when
		// module metadata and /sys/module positively identify a loaded backport as
		// the modern driver. Do not trust a pre-existing "ntfs" registration on
		// pre-7.1 kernels; it may belong to ntfs3's read-only compatibility path.
		if (!kernelHasStandaloneNtfs && IsNtfsReadWriteKernelFilesystemTypeAvailable ())
			return "ntfs";

		if (kernelHasStandaloneNtfs && IsKernelFilesystemTypeAvailable ("ntfs"))
			return "ntfs";

		if (IsKernelFilesystemTypeAvailable ("ntfs3"))
			return "ntfs3";

		throw KernelNtfsDriverUnavailable (SRC_POS);
	}

	void CoreUnix::ResolveNtfsKernelMountOptions (const DevicePath &devicePath, bool mountNtfsWithKernelDriver,
		wstring &filesystemType, bool &internalMountOnly) const
	{
		string requestedFilesystemType = StringConverter::ToLower (StringConverter::ToSingle (filesystemType));
		bool explicitKernelNtfsRequest = requestedFilesystemType == "kernel-ntfs" || requestedFilesystemType == "ntfs-kernel";

		if (requestedFilesystemType == "ntfs3")
		{
			// mount.ntfs3 helpers are not required; -i keeps mount(8) on the kernel path.
			internalMountOnly = true;
			return;
		}

		if (!explicitKernelNtfsRequest
			&& !(mountNtfsWithKernelDriver
				&& filesystemType.empty()
				&& DetectFilesystemType (devicePath) == "ntfs"))
			return;

		filesystemType = StringConverter::ToWide (SelectNtfsKernelFilesystemType());
		internalMountOnly = true;
	}

	string CoreUnix::DetectLinuxMountFallbackFilesystemType (const DevicePath &devicePath) const
	{
		string detectedFilesystemType = DetectFilesystemType (devicePath);

		if (detectedFilesystemType == "vfat" || detectedFilesystemType == "exfat" || detectedFilesystemType == "msdos")
			return detectedFilesystemType;

		if (detectedFilesystemType == "fat")
			return "vfat";

		return string();
	}

	void CoreUnix::MountFilesystemWithFallback (const DevicePath &devicePath, const DirectoryPath &mountPoint,
		const string &filesystemType, bool allowFilesystemTypeFallback, bool readOnly,
		const string &systemMountOptions, bool internalMountOnly) const
	{
		try
		{
			MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions, internalMountOnly);
		}
		catch (ExecutedProcessFailed&)
		{
			if (!allowFilesystemTypeFallback || !filesystemType.empty() || internalMountOnly)
				throw;

			string fallbackFilesystemType = DetectLinuxMountFallbackFilesystemType (devicePath);
			if (fallbackFilesystemType.empty())
				throw;

			MountFilesystem (devicePath, mountPoint, fallbackFilesystemType, readOnly, systemMountOptions, false);
		}
	}
#endif

	void CoreUnix::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions, bool internalMountOnly) const
	{
		if (GetMountedFilesystems (DevicePath(), mountPoint).size() > 0)
			throw MountPointUnavailable (SRC_POS);

		list <string> args;
		string options;

		if (internalMountOnly)
			args.push_back ("-i");

		if (!filesystemType.empty())
		{
#ifdef TC_SOLARIS
			args.push_back ("-F");
#else
			args.push_back ("-t");
#endif
			args.push_back (filesystemType);
		}

		if (readOnly)
			options = "-oro";

		if (!systemMountOptions.empty())
		{
			if (options.empty())
				options = "-o";
			else
				options += ",";

			options += systemMountOptions;
		}

		if (!options.empty())
			args.push_back (options);

		args.push_back ("--");
		args.push_back (devicePath);
		args.push_back (mountPoint);

		Process::Execute ("mount", args);
	}

	VolumeSlotNumber CoreUnix::MountPointToSlotNumber (const DirectoryPath &mountPoint) const
	{
		string mountPointStr (mountPoint);
		if (mountPointStr.find (GetDefaultMountPointPrefix()) == 0)
		{
			try
			{
				return StringConverter::ToUInt32 (StringConverter::GetTrailingNumber (mountPointStr));
			}
			catch (...) { }
		}
		return GetFirstFreeSlotNumber();
	}

	shared_ptr <VolumeInfo> CoreUnix::MountVolume (MountOptions &options)
	{
		CoalesceSlotNumberAndMountPoint (options);

		if (IsVolumeMounted (*options.Path))
			throw VolumeAlreadyMounted (SRC_POS);

		if (options.MountPoint && !options.MountPoint->IsEmpty())
		{
			// Reject if the mount point is a system directory
			if (IsProtectedSystemDirectory(*options.MountPoint))
				throw MountPointBlocked (SRC_POS);

			// Reject if the mount point is in the user's PATH and the user has not explicitly allowed insecure mount points
			if (!GetAllowInsecureMount() && IsDirectoryOnUserPath(*options.MountPoint))
				throw MountPointNotAllowed (SRC_POS);
		}

		Cipher::EnableHwSupport (!options.NoHardwareCrypto);

		shared_ptr <Volume> volume;

		while (true)
		{
			try
			{
				volume = OpenVolume (
					options.Path,
					options.PreserveTimestamps,
					options.Password,
					options.Pim,
					options.Kdf,
					options.Keyfiles,
					options.EMVSupportEnabled,
					options.Protection,
					options.ProtectionPassword,
					options.ProtectionPim,
					options.ProtectionKdf,
					options.ProtectionKeyfiles,
					options.SharedAccessAllowed,
					VolumeType::Unknown,
					options.UseBackupHeaders,
					options.PartitionInSystemEncryptionScope
					);

				options.Password.reset();
			}
			catch (SystemException &e)
			{
				if (options.Protection != VolumeProtection::ReadOnly
					&& (e.GetErrorCode() == EROFS || e.GetErrorCode() == EACCES || e.GetErrorCode() == EPERM))
				{
					// Read-only filesystem
					options.Protection = VolumeProtection::ReadOnly;
					continue;
				}

				options.Password.reset();
				throw;
			}

			break;
		}

		// Opening a partially encrypted system volume can force read-only
		// protection. Carry that effective mode into either mount backend.
		if (volume->GetProtectionType() == VolumeProtection::ReadOnly)
			options.Protection = VolumeProtection::ReadOnly;

		if (options.Path->IsDevice())
		{
			const uint32 devSectorSize = volume->GetFile()->GetDeviceSectorSize();
			const size_t volSectorSize = volume->GetSectorSize();
			if (devSectorSize != volSectorSize)
				throw DeviceSectorSizeMismatch (SRC_POS, StringConverter::ToWide(devSectorSize) + L" != " + StringConverter::ToWide((uint32) volSectorSize));
		}

		string fuseMountPoint;
#ifdef VC_MACOSX_FUSET
		// An older service may still be shutting down after its SMB mount has
		// disappeared. FUSE-T also uses the pathname during backend teardown,
		// so a replacement volume must have a different auxiliary path.
		// An elevated parent also needs trusted ancestors. Match the shutdown
		// socket's location instead of honoring a caller-controlled TMPDIR.
		const string auxiliaryParent = CreateFuseTAuxiliaryDirectory (geteuid() == 0 ? "/private/tmp" : GetTempDirectory(), GetRealUserId());
		// Cover failures before the service takes over, including child creation.
		// A live mount keeps this parent nonempty; its service removes it later.
		finally_do_arg (string, auxiliaryParent, { rmdir (finally_arg.c_str()); });
		string mountTemplate = auxiliaryParent + "/" + GetFuseMountDirPrefix() + "-XXXXXXXXXXXX";
		vector <char> mountDirectory (mountTemplate.begin(), mountTemplate.end());
		mountDirectory.push_back ('\0');
		throw_sys_if (mkdtemp (&mountDirectory[0]) == NULL);
		fuseMountPoint = &mountDirectory[0];
#else
		// Find a free mount point for FUSE service
		MountedFilesystemList mountedFilesystems = GetMountedFilesystems ();
		for (int i = 1; true; i++)
		{
			stringstream path;
			path << GetTempDirectory() << "/" << GetFuseMountDirPrefix() << i;
			FilesystemPath fsPath (path.str());

			bool inUse = false;

			foreach_ref (const MountedFilesystem &mf, mountedFilesystems)
			{
				if (mf.MountPoint == path.str())
				{
					inUse = true;
					break;
				}
			}

			if (!inUse)
			{
				try
				{
					if (fsPath.IsDirectory())
						fsPath.Delete();

					throw_sys_sub_if (mkdir (path.str().c_str(), S_IRUSR | S_IXUSR) == -1, path.str());

					fuseMountPoint = fsPath;
					break;
				}
				catch (...)
				{
					if (i > 255)
						throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (path.str()));
				}
			}
		}
#endif

#ifdef VC_MACOSX_FUSET
		uint64 fuseServiceSerialInstanceNumber;
#endif

		try
		{
#ifdef VC_MACOSX_FUSET
			throw_sys_if (chmod (fuseMountPoint.c_str(), S_IRUSR | S_IXUSR) == -1);
#endif
#ifdef TC_MACOSX
			// FUSE canonicalizes its mount path. Give hdiutil the same path so
			// its inventory identifies the image even when TMPDIR is a symlink.
			char *canonicalPath = realpath (fuseMountPoint.c_str(), NULL);
			throw_sys_if (canonicalPath == NULL);
			finally_do_arg (char *, canonicalPath, { free (finally_arg); });
			fuseMountPoint = canonicalPath;
#endif
#ifdef VC_MACOSX_FUSET
			fuseServiceSerialInstanceNumber = FuseService::Mount (volume, options.SlotNumber, fuseMountPoint);
#else
			FuseService::Mount (volume, options.SlotNumber, fuseMountPoint);
#endif
		}
		catch (...)
		{
			try
			{
				DirectoryPath (fuseMountPoint).Delete();
			}
			catch (...) { }
			throw;
		}

		if (options.Path->IsDevice())
			RecordDeviceHostedVolume (*volume, fuseMountPoint);

		DevicePath mountedVirtualDevice;

		try
		{
			// Create a mount directory if a default path has been specified
			bool mountDirCreated = false;
			string mountPoint;
			if (!options.NoFilesystem && options.MountPoint)
			{
				mountPoint = *options.MountPoint;

#ifndef TC_MACOSX
				if (mountPoint.find (GetDefaultMountPointPrefix()) == 0 && !options.MountPoint->IsDirectory())
				{
					Directory::Create (*options.MountPoint);
					try
					{
						throw_sys_sub_if (chown (mountPoint.c_str(), GetRealUserId(), GetRealGroupId()) == -1, mountPoint);
					} catch (ParameterIncorrect&) { }

					mountDirCreated = true;
				}
#endif
			}

			try
			{
				try
				{
					MountVolumeNative (volume, options, fuseMountPoint);
				}
				catch (NotApplicable&)
				{
					mountedVirtualDevice = MountAuxVolumeImage (fuseMountPoint, options);
				}
			}
			catch (...)
			{
				if (mountDirCreated)
					remove (mountPoint.c_str());
				throw;
			}

#ifndef TC_MACOSX
			// set again correct ownership of the mount point to avoid any issues
			if (!options.NoFilesystem && options.MountPoint)
			{
				mountPoint = *options.MountPoint;

				if (mountPoint.find (GetDefaultMountPointPrefix()) == 0)
				{
					try
					{
						throw_sys_sub_if (chown (mountPoint.c_str(), GetRealUserId(), GetRealGroupId()) == -1, mountPoint);
					} catch (...) { }
				}
			}
#endif

#ifdef VC_MACOSX_FUSET
			shared_ptr <VolumeInfo> mountedVolume = GetMountedVolume (*options.Path);
			if (mountedVolume)
			{
				if (mountedVolume->SerialInstanceNumber != fuseServiceSerialInstanceNumber)
					throw ParameterIncorrect (SRC_POS);
				if (!mountedVirtualDevice.IsEmpty())
				{
					if (mountedVolume->VirtualDevice.IsEmpty())
						mountedVolume->VirtualDevice = mountedVirtualDevice;

					if (!options.NoFilesystem && mountedVolume->MountPoint.IsEmpty())
					{
						for (int mountPointRetries = 20; mountPointRetries > 0; --mountPointRetries)
						{
							try
							{
								mountedVolume->MountPoint = GetDeviceMountPoint (mountedVirtualDevice);
								if (!mountedVolume->MountPoint.IsEmpty())
									break;
							}
							catch (...) { }

							Thread::Sleep (500);
						}
					}
				}
			}
			else if (!mountedVirtualDevice.IsEmpty())
			{
				mountedVolume.reset (new VolumeInfo);
				mountedVolume->Set (*volume);
				mountedVolume->ProgramVersion = VERSION_NUM;
				mountedVolume->SlotNumber = options.SlotNumber;
				mountedVolume->AuxMountPoint = fuseMountPoint;
				mountedVolume->VirtualDevice = mountedVirtualDevice;

				mountedVolume->SerialInstanceNumber = fuseServiceSerialInstanceNumber;

				if (!options.NoFilesystem)
				{
					for (int mountPointRetries = 20; mountPointRetries > 0; --mountPointRetries)
					{
						try
						{
							mountedVolume->MountPoint = GetDeviceMountPoint (mountedVirtualDevice);
							if (!mountedVolume->MountPoint.IsEmpty())
								break;
						}
						catch (...) { }

						Thread::Sleep (500);
					}
				}
			}
#else
			shared_ptr <VolumeInfo> mountedVolume = GetMountedVolume (*options.Path);
#endif
			if (!mountedVolume)
				throw ParameterIncorrect (SRC_POS);

#ifdef TC_LINUX
			mountedVolume->RequesterBacked = volume->GetFile()->IsRequesterBacked();
#endif

			VolumeEventArgs eventArgs (mountedVolume);
			VolumeMountedEvent.Raise (eventArgs);

			return mountedVolume;
		}
		catch (...)
		{
#ifdef VC_MACOSX_FUSET
			// Enumeration may itself have failed. Cleanup belongs to the instance
			// we just started, not a later volume discovered by path or slot.
			try { throw; }
			catch (exception &e) { SystemLog::WriteException (e); }
			catch (...) { }
			try
			{
				shared_ptr <VolumeInfo> cleanupVolume (new VolumeInfo);
				cleanupVolume->Set (*volume);
				cleanupVolume->ProgramVersion = VERSION_NUM;
				cleanupVolume->SlotNumber = options.SlotNumber;
				cleanupVolume->SerialInstanceNumber = fuseServiceSerialInstanceNumber;
				cleanupVolume->AuxMountPoint = fuseMountPoint;
				DismountVolume (cleanupVolume);
			}
			catch (DismountServiceCleanupFailed &) { throw; }
			catch (exception &e)
			{
				SystemLog::WriteException (e);
				throw MountServiceCleanupFailed (SRC_POS, StringConverter::ToWide (fuseMountPoint) + L"\n" + StringConverter::ToExceptionString (e));
			}
			catch (...)
			{
				throw MountServiceCleanupFailed (SRC_POS, StringConverter::ToWide (fuseMountPoint));
			}
#else
			try
			{
				shared_ptr <VolumeInfo> mountedVolume = GetMountedVolume (*options.Path);
				if (mountedVolume)
					DismountVolume (mountedVolume);
			}
			catch (...) { }
			// The volume may be gone before it is found, with its record left behind
			if (options.Path->IsDevice())
				RemoveDeviceHostedVolumeRecord (*options.Path);
#endif
			throw;
		}
	}

	DevicePath CoreUnix::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
		DevicePath loopDev = AttachFileToLoopDevice (string (auxMountPoint) + FuseService::GetVolumeImagePath(), options.Protection == VolumeProtection::ReadOnly);

		try
		{
			FuseService::SendAuxDeviceInfo (auxMountPoint, loopDev, loopDev);
		}
		catch (...)
		{
			try
			{
				DetachLoopDevice (loopDev);
			}
			catch (...) { }
			throw;
		}

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			wstring filesystemType = options.FilesystemType;
			bool internalMountOnly = false;

#ifdef TC_LINUX
			bool allowFilesystemTypeFallback = filesystemType.empty();

			ResolveNtfsKernelMountOptions (loopDev, options.MountNtfsWithKernelDriver, filesystemType, internalMountOnly);
			allowFilesystemTypeFallback = allowFilesystemTypeFallback && filesystemType.empty() && !internalMountOnly;

			MountFilesystemWithFallback (loopDev, *options.MountPoint,
				StringConverter::ToSingle (filesystemType),
				allowFilesystemTypeFallback,
				options.Protection == VolumeProtection::ReadOnly,
				StringConverter::ToSingle (options.FilesystemOptions),
				internalMountOnly);
#else
			MountFilesystem (loopDev, *options.MountPoint,
				StringConverter::ToSingle (filesystemType),
				options.Protection == VolumeProtection::ReadOnly,
				StringConverter::ToSingle (options.FilesystemOptions),
				internalMountOnly);
#endif
		}

		return loopDev;
	}

	void CoreUnix::SetFileOwner (const FilesystemPath &path, const UserId &owner) const
	{
		throw_sys_if (chown (string (path).c_str(), owner.SystemId, (gid_t) -1) == -1);
	}

	DirectoryPath CoreUnix::SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const
	{
		if (slotNumber < GetFirstSlotNumber() || slotNumber > GetLastSlotNumber())
			throw ParameterIncorrect (SRC_POS);

		stringstream s;
		s << GetDefaultMountPointPrefix() << slotNumber;
		return s.str();
	}

	bool CoreUnix::IsProtectedSystemDirectory (const DirectoryPath &directory) const
	{
		static const char* systemDirs[] = {
			"/usr",
			"/bin",
			"/sbin",
			"/lib",
#ifdef TC_LINUX
			"/lib32",
			"/lib64",
			"/libx32",
#endif
			"/etc",
			"/boot",
			"/root",
			"/proc",
			"/sys",
			"/dev",
			NULL
		};

		// Resolve any symlinks in the path
		string path(directory);
		char* resolvedPathCStr = realpath(path.c_str(), NULL);
		if (resolvedPathCStr)
		{
			path = resolvedPathCStr;
			free(resolvedPathCStr); // Free the allocated memory
		}

		// reject of the path is the root directory "/"
		if (path == "/")
			return true;

		// Check if resolved path matches any system directory
		for (int i = 0; systemDirs[i] != NULL; ++i)
		{
			if (path == systemDirs[i] || path.find(string(systemDirs[i]) + "/") == 0)
				return true;
		}

		return false;
	}

	bool CoreUnix::IsDirectoryOnUserPath(const DirectoryPath &directory) const
	{
		// Obtain the PATH environment variable
		const char* pathEnv = UserEnvPATH.c_str();
		if (!pathEnv[0])
			return false;

		// Resolve the given directory
		string dirPath(directory);
		char* resolvedDir = realpath(dirPath.c_str(), NULL);
		if (resolvedDir)
		{
			dirPath = resolvedDir;
			free(resolvedDir);
		}

		// Split PATH and compare each entry
		stringstream ss(pathEnv);
		string token;
		while (getline(ss, token, ':'))
		{
			// remove any trailing slashes from the token
			while (!token.empty() && token[token.length() - 1] == '/')
				token.erase(token.length() - 1);

			if (token.empty())
				continue;

			// check if the directory is the same as the entry or a subdirectory
			if (dirPath == token || dirPath.find(token + "/") == 0)
				return true;

			// handle the case where the PATH entry is a symlink
			char* resolvedEntry = realpath(token.c_str(), NULL);
			if (!resolvedEntry)
				continue; // skip to the next entry since the path does not exist

			string entryPath(resolvedEntry);
			free(resolvedEntry);

			// remove any trailing slashes from the token
			while (!entryPath.empty() && entryPath[entryPath.length() - 1] == '/')
				entryPath.erase(entryPath.length() - 1);

			// perform check again if the resolved path is different from the original (symlink)
			if (dirPath == entryPath || dirPath.find(entryPath + "/") == 0)
				return true;
		}

		return false;
	}
}
