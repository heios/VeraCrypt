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

#ifndef TC_HEADER_Core_CoreMacOSX
#define TC_HEADER_Core_CoreMacOSX

#include "System.h"
#include "Core/Unix/FreeBSD/CoreFreeBSD.h"

namespace VeraCrypt
{
	class CoreMacOSX : public CoreFreeBSD
	{
	public:
		CoreMacOSX ();
		virtual ~CoreMacOSX ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const;
		virtual string GetDefaultMountPointPrefix () const { return "/Volumes/veracrypt"; }

	protected:
		virtual shared_ptr <VolumeInfo> DetachVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo, const DetachedVolumeHandler &onDetached);
		virtual DevicePath MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const;
		virtual void UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> mountedVolume) const;
		virtual void UpdateMountedVolumesInfo (VolumeInfoList &volumes) const;

		// TRIM after unmount (see CoreUnix)
		virtual bool SupportsTrimAfterDismount () const { return true; }
		virtual string GetTrimDevicePath (const FilesystemPath &devicePath) const;
		virtual int OpenTrimDevice (const string &devicePath, bool readWrite, uint64 &size, uint32 &blockSize) const;
		virtual bool TrimDeviceSupportsDiscard (int fd, const string &devicePath) const;
		virtual bool IsExfatMounted (const VolumeInfo &volume, uint64 &freeBytes) const;
		virtual void CheckExfatFilesystem (const string &devicePath) const;
		virtual void FlushTrimDevice (int fd) const;
		virtual void DiscardTrimExtents (int fd, const string &devicePath, const vector <ExfatRange> &extents) const;

	private:
		CoreMacOSX (const CoreMacOSX &);
		CoreMacOSX &operator= (const CoreMacOSX &);
		void UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> volume, const string &inventory) const;
		shared_ptr <VolumeInfo> ValidateMountedVolume (shared_ptr <VolumeInfo> volume) const;
	};
}

#endif // TC_HEADER_Core_CoreMacOSX
