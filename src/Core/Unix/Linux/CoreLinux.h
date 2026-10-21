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

#ifndef TC_HEADER_Core_CoreLinux
#define TC_HEADER_Core_CoreLinux

#include "System.h"
#include "Core/Unix/CoreUnix.h"

namespace VeraCrypt
{
	class CoreLinux : public CoreUnix
	{
	public:
		CoreLinux ();
		virtual ~CoreLinux ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const;
		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false);
		virtual uint64 DismountVolumeAndTrim (shared_ptr <VolumeInfo> mountedVolume, wstring &skipReason);
		virtual shared_ptr <VolumeInfo> EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume);
		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const;
		virtual bool IsTrimSupported (shared_ptr <VolumeInfo> mountedVolume, wstring &reason) const;

	protected:
		virtual DevicePath AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const;
		virtual void DetachLoopDevice (const DevicePath &devicePath) const;
		virtual void DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const;
		virtual void DismountNativeVolumeDeferred (shared_ptr <VolumeInfo> mountedVolume) const;
		virtual MountedFilesystemList GetMountedFilesystems (const DevicePath &devicePath = DevicePath(), const DirectoryPath &mountPoint = DirectoryPath()) const;
		virtual void MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions, bool internalMountOnly = false) const;
		virtual void MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const;
		virtual void UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> mountedVolume) const;

		virtual bool SupportsTrimAfterDismount () const { return true; }
		virtual string GetTrimDevicePath (const FilesystemPath &devicePath) const;
		virtual int OpenTrimDevice (const string &devicePath, bool readWrite, uint64 &size, uint32 &blockSize) const;
		virtual bool TrimDeviceSupportsDiscard (int fd, const string &devicePath) const;
		virtual bool IsExfatMounted (const VolumeInfo &volume, uint64 &freeBytes) const;
		virtual void CheckExfatFilesystem (const string &devicePath) const;
		virtual void FlushTrimDevice (int fd) const;
		virtual void DiscardTrimExtents (int fd, const string &devicePath, const vector <ExfatRange> &extents) const;

	private:
		void DismountNativeVolumeInternal (shared_ptr <VolumeInfo> mountedVolume, bool deferred) const;
		DevicePath GetOwnedVirtualDevice (const VolumeInfo &volume) const;
		shared_ptr <VolumeInfo> ResolveMountedVolume (shared_ptr <VolumeInfo> mountedVolume) const;

		CoreLinux (const CoreLinux &);
		CoreLinux &operator= (const CoreLinux &);
	};
}

#endif // TC_HEADER_Core_CoreLinux
