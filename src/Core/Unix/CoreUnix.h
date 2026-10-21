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

#ifndef TC_HEADER_Core_CoreUnix
#define TC_HEADER_Core_CoreUnix

#include "System.h"
#include "Platform/Unix/Process.h"
#include "Core/CoreBase.h"
#include "Core/Unix/MountedFilesystem.h"
#include <functional>

namespace VeraCrypt
{
	struct ExfatRange;

	class CoreUnix : public CoreBase
	{
	public:
		CoreUnix ();
		virtual ~CoreUnix ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const;
		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const;
		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false);
		virtual uint64 DismountVolumeAndTrim (shared_ptr <VolumeInfo> mountedVolume, wstring &skipReason);
#ifdef TC_LINUX
		virtual shared_ptr <VolumeInfo> EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume);
#endif
		virtual bool FilesystemSupportsLargeFiles (const FilePath &filePath) const;
		virtual DirectoryPath GetDeviceMountPoint (const DevicePath &devicePath) const;
		virtual uint32 GetDeviceSectorSize (const DevicePath &devicePath) const;
		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const;
		virtual int GetOSMajorVersion () const { throw NotApplicable (SRC_POS); }
		virtual int GetOSMinorVersion () const { throw NotApplicable (SRC_POS); }
		virtual VolumeInfoList GetMountedVolumes (const VolumePath &volumePath = VolumePath()) const;
		virtual VolumeDiscoveryResult GetMountedVolumesWithStatus (const VolumePath &volumePath = VolumePath()) const;
		virtual bool IsDevicePresent (const DevicePath &device) const { throw NotApplicable (SRC_POS); }
		virtual bool IsInPortableMode () const { return false; }
		virtual bool IsMountPointAvailable (const DirectoryPath &mountPoint) const;
		virtual bool IsOSVersion (int major, int minor) const { throw NotApplicable (SRC_POS); }
		virtual bool IsOSVersionLower (int major, int minor) const { throw NotApplicable (SRC_POS); }
		virtual bool IsPasswordCacheEmpty () const { throw NotApplicable (SRC_POS); }
		virtual bool IsTrimSupported (shared_ptr <VolumeInfo> mountedVolume, wstring &reason) const;
		virtual bool HasAdminPrivileges () const { return getuid() == 0 || geteuid() == 0; }
		virtual VolumeSlotNumber MountPointToSlotNumber (const DirectoryPath &mountPoint) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options);
		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const;
		virtual DirectoryPath SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const;
		virtual void WipePasswordCache () const { throw NotApplicable (SRC_POS); }
		virtual bool IsProtectedSystemDirectory (const DirectoryPath &directory) const;
		virtual bool IsDirectoryOnUserPath(const DirectoryPath &directory) const;

	protected:
		static shared_ptr <VolumeInfo> ReadAuxiliaryVolumeInfo (const DirectoryPath &auxMountPoint);
		virtual DevicePath AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const { throw NotApplicable (SRC_POS); }
		virtual void DetachLoopDevice (const DevicePath &devicePath) const { throw NotApplicable (SRC_POS); }
		virtual void DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const { throw NotApplicable (SRC_POS); }
#ifdef TC_LINUX
		virtual void DismountFilesystemLazy (const DirectoryPath &mountPoint) const;
		virtual void DismountNativeVolumeDeferred (shared_ptr <VolumeInfo> mountedVolume) const { DismountNativeVolume (mountedVolume); }
#endif
		virtual bool FilesystemSupportsUnixPermissions (const DevicePath &devicePath) const;
		virtual string GetDefaultMountPointPrefix () const;
		virtual string GetFuseMountDirPrefix () const { return ".veracrypt_aux_mnt"; }
		virtual MountedFilesystemList GetMountedFilesystems (const DevicePath &devicePath = DevicePath(), const DirectoryPath &mountPoint = DirectoryPath()) const = 0;
		virtual uid_t GetRealUserId () const;
		virtual gid_t GetRealGroupId () const;
		virtual string GetTempDirectory () const;
		// internalMountOnly maps to mount(8) -i and suppresses /sbin/mount.<type> helpers.
		virtual void MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions, bool internalMountOnly = false) const;
		virtual DevicePath MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const;
		virtual void MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const { throw NotApplicable (SRC_POS); }
		virtual void UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> mountedVolume) const { (void) mountedVolume; }

		// Dismounts the volume without removing its mount record or raising VolumeDismountedEvent.
		// onDetached, if set, runs once the virtual device is detached (nothing can write to the
		// filesystem then) and before the auxiliary mount, which still serves the volume image, goes away.
		typedef function <void (const VolumeInfo &)> DetachedVolumeHandler;
		virtual shared_ptr <VolumeInfo> DetachVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo, const DetachedVolumeHandler &onDetached);

		// TRIM after unmount for volumes served without kernel crypto: the exFAT filesystem is
		// unmounted and checked on the virtual device, the volume is dismounted while its
		// allocation bitmap is read from the volume image, and the free clusters are discarded
		// on the host device. CoreUnix keeps the mount record and runs the sequence; a platform
		// supporting it overrides the hooks below.
		struct DeviceVolumeRecord
		{
			uint64 DataOffset;
			uint64 DataSize;
			int32 MountId[2];	// identity of the auxiliary mount the record was written for
			uint8 Type;			// VolumeType::Enum
			uint8 Protection;	// VolumeProtection::Enum
			uint8 Header[512];
		};

		void RecordDeviceHostedVolume (const Volume &volume, const DirectoryPath &auxMountPoint) const;
		void RemoveDeviceHostedVolumeRecord (const VolumePath &devicePath) const;

		static const int TrimFsckTimeout = 10 * 60 * 1000;
		static const size_t TrimFsckOutputLimit = 1 << 20;

		virtual bool SupportsTrimAfterDismount () const { return false; }
		// Path to open for TRIM, unbuffered where the platform has one; throws TrimFailed for unsupported devices
		virtual string GetTrimDevicePath (const FilesystemPath &devicePath) const { throw NotApplicable (SRC_POS); }
		// Opens the device and returns its descriptor, size and block size
		virtual int OpenTrimDevice (const string &devicePath, bool readWrite, uint64 &size, uint32 &blockSize) const { throw NotApplicable (SRC_POS); }
		virtual bool TrimDeviceSupportsDiscard (int fd, const string &devicePath) const { throw NotApplicable (SRC_POS); }
		// Whether the filesystem mounted from the volume's virtual device is exFAT; freeBytes receives the driver's free space
		virtual bool IsExfatMounted (const VolumeInfo &volume, uint64 &freeBytes) const { throw NotApplicable (SRC_POS); }
		// Runs the platform's read-only exFAT check on the device; throws unless the filesystem is clean
		virtual void CheckExfatFilesystem (const string &devicePath) const { throw NotApplicable (SRC_POS); }
		virtual void FlushTrimDevice (int fd) const { throw NotApplicable (SRC_POS); }
		// Discards the device byte ranges (block aligned) of one request; throws SystemException on failure
		virtual void DiscardTrimExtents (int fd, const string &devicePath, const vector <ExfatRange> &extents) const { throw NotApplicable (SRC_POS); }
#ifdef TC_MACOSX
		virtual void UpdateMountedVolumesInfo (VolumeInfoList &volumes) const;
#endif
#ifdef TC_LINUX
		string DetectFilesystemType (const DevicePath &devicePath) const;
		bool IsFilesystemTypeRegistered (const string &filesystemType) const;
		bool IsKernelFilesystemTypeAvailable (const string &filesystemType) const;
		bool IsNtfsReadWriteKernelFilesystemTypeAvailable () const;
		string DetectLinuxMountFallbackFilesystemType (const DevicePath &devicePath) const;
		void MountFilesystemWithFallback (const DevicePath &devicePath, const DirectoryPath &mountPoint,
			const string &filesystemType, bool allowFilesystemTypeFallback, bool readOnly,
			const string &systemMountOptions, bool internalMountOnly) const;
		void ResolveNtfsKernelMountOptions (const DevicePath &devicePath, bool mountNtfsWithKernelDriver,
			wstring &filesystemType, bool &internalMountOnly) const;
		string SelectNtfsKernelFilesystemType () const;
#endif

	private:
		CoreUnix (const CoreUnix &);
		CoreUnix &operator= (const CoreUnix &);
		void CompleteDismount (shared_ptr <VolumeInfo> mountedVolume);
		string GetDeviceHostedVolumeRecordName (const FilesystemPath &devicePath) const;
		string GetDeviceHostedVolumeRecordPath (const FilesystemPath &devicePath) const;
		static bool HostHeaderMatches (int fd, uint32 blockSize, const DeviceVolumeRecord &record);
		static int OpenDeviceHostedVolumeRecordDirectory ();
		DeviceVolumeRecord ReadDeviceHostedVolumeRecord (const VolumeInfo &volume, uint64 hostSize) const;
	};
}

#endif // TC_HEADER_Core_CoreUnix
