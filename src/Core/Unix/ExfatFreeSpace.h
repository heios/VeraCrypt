/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0, the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source distributions.
*/

#ifndef TC_HEADER_Core_Unix_ExfatFreeSpace
#define TC_HEADER_Core_Unix_ExfatFreeSpace

// Apart from the C++ standard library, this header depends on the Platform library
// only, so that the parser can be compiled, tested and fuzzed outside the VeraCrypt
// build (see Tests/exfat_free_space_test.cpp).

#include <functional>
#include "Platform/Platform.h"
#include "Core/CoreException.h"

namespace VeraCrypt
{
	// A byte range relative to the start of the filesystem.
	struct ExfatRange
	{
		uint64 Offset;
		uint64 Length;
	};

	// Fills `buffer` with the bytes at `offset` of the filesystem, or throws.
	typedef function <void (uint64 offset, const BufferPtr &buffer)> ExfatReader;

	// Limits from the exFAT specification: the root directory may not exceed 256 MiB
	// (section 6.2) and the up-case table holds at most 2^16 two-byte entries (section 7.2.5).
	static const uint64 ExfatMaxRootDirectoryBytes = 256ULL << 20;
	static const uint64 ExfatMaxUpcaseTableBytes = 2 * 65536;

	// Returns the unallocated clusters of an unmounted exFAT filesystem as sorted,
	// merged byte ranges, taken from its allocation bitmap (exFAT specification,
	// sections 3.1, 7.1 and 7.2). Throws TrimFailed when the filesystem is not exFAT
	// or looks damaged in any way, since the result decides what may be discarded;
	// its subject is TRIM_EXFAT_UNSUPPORTED, ": " and the untranslated reason. The
	// bitmap is trusted beyond the checks made here: a bitmap that disagrees with the
	// directory tree is only found by a full filesystem check. The metadata read,
	// file names included, is plaintext and is kept in SecureBuffer only.
	inline vector <ExfatRange> GetExfatFreeRanges (const ExfatReader &read, uint64 deviceSize)
	{
		struct Fail
		{
			static void If (bool condition, const char *reason)
			{
				if (condition)
					throw TrimFailed (SRC_POS, StringConverter::ToWide (string ("TRIM_EXFAT_UNSUPPORTED: ") + reason));
			}
		};

		auto u32 = [] (const uint8 *p) { return (uint32) p[0] | (uint32) p[1] << 8 | (uint32) p[2] << 16 | (uint32) p[3] << 24; };
		auto u64 = [&] (const uint8 *p) { return (uint64) u32 (p) | (uint64) u32 (p + 4) << 32; };

		// Main boot region: boot sector, 8 extended boot sectors, OEM and reserved sectors, checksum sector
		SecureBuffer boot (512);
		read (0, boot);
		Fail::If (memcmp (&boot[3], "EXFAT   ", 8) != 0 || boot[510] != 0x55 || boot[511] != 0xaa, "no exFAT filesystem found");

		const unsigned sectorShift = boot[108];
		const unsigned clusterShift = sectorShift + boot[109];
		Fail::If (sectorShift < 9 || sectorShift > 12 || clusterShift > 25, "invalid exFAT sector or cluster size");

		const uint64 sectorSize = 1ULL << sectorShift;
		const uint64 clusterSize = 1ULL << clusterShift;
		boot.Allocate ((size_t) (12 * sectorSize));
		read (0, boot);

		uint32 checksum = 0;
		for (size_t i = 0; i < 11 * sectorSize; ++i)
		{
			if (i != 106 && i != 107 && i != 112)
				checksum = ((checksum & 1) ? 0x80000000 : 0) + (checksum >> 1) + boot[i];
		}

		for (size_t i = 11 * sectorSize; i < 12 * sectorSize; i += 4)
			Fail::If (u32 (&boot[i]) != checksum, "exFAT boot sector checksum mismatch");

		const uint64 volumeSectors = u64 (&boot[72]);
		const uint64 fatOffset = (uint64) u32 (&boot[80]) << sectorShift;
		const uint64 fatLength = (uint64) u32 (&boot[84]) << sectorShift;
		const uint64 heapOffset = (uint64) u32 (&boot[88]) << sectorShift;
		const uint64 clusterCount = u32 (&boot[92]);
		const uint32 rootCluster = u32 (&boot[96]);
		const unsigned volumeFlags = boot[106] | boot[107] << 8;

		Fail::If (boot[110] != 1 || (volumeFlags & 1), "exFAT with two FATs (TexFAT) is not supported");
		Fail::If (volumeFlags & 2, "the exFAT filesystem is marked dirty; check and repair it first");
		Fail::If (volumeFlags & 4, "the exFAT filesystem reports a media failure");
		Fail::If (clusterCount == 0 || clusterCount > 0xfffffff5
			|| volumeSectors > (deviceSize >> sectorShift)
			|| fatOffset < 24 * sectorSize
			|| fatOffset + fatLength > heapOffset
			|| fatLength < (clusterCount + 2) * 4
			|| heapOffset + (clusterCount << clusterShift) > (volumeSectors << sectorShift),
			"inconsistent exFAT geometry");

		auto clusterOffset = [&] (uint32 cluster) { return heapOffset + ((uint64) (cluster - 2) << clusterShift); };

		// A cluster may belong to one metadata chain only. Claiming each cluster before
		// it is read rejects cycles (at the first repeated cluster), cross-linked chains
		// and cluster numbers outside the heap, and bounds the work by the heap size.
		vector <bool> claimed (clusterCount, false);
		vector <uint32> metadataClusters;
		auto claim = [&] (uint32 cluster)
		{
			Fail::If (cluster < 2 || cluster - 2 >= clusterCount, "exFAT cluster chain leaves the cluster heap");
			Fail::If (claimed[cluster - 2], "exFAT cluster chains are cyclic or cross-linked");
			claimed[cluster - 2] = true;
			metadataClusters.push_back (cluster);
		};

		SecureBuffer fatSector ((size_t) sectorSize);
		uint64 fatSectorOffset = (uint64) -1;
		auto nextCluster = [&] (uint32 cluster)
		{
			const uint64 pos = fatOffset + (uint64) cluster * 4;
			const uint64 sector = pos & ~(sectorSize - 1);

			if (sector != fatSectorOffset)
			{
				read (sector, fatSector);
				fatSectorOffset = sector;
			}

			return u32 (&fatSector[pos - sector]);
		};

		// Follows a FAT cluster chain that must consist of exactly `count` clusters
		// and reads its first clusters into `data`, a whole number of clusters long
		auto readChain = [&] (uint32 first, uint64 count, const BufferPtr &data)
		{
			uint32 cluster = first;

			for (uint64 i = 0; i < count; ++i)
			{
				Fail::If (cluster == 0xffffffff, "exFAT cluster chain is shorter than the data length");
				claim (cluster);

				if ((i << clusterShift) < data.Size())
					read (clusterOffset (cluster), data.GetRange ((size_t) (i << clusterShift), (size_t) clusterSize));

				cluster = nextCluster (cluster);
			}

			Fail::If (cluster != 0xffffffff, "exFAT cluster chain is longer than the data length");
		};

		// The root directory has no recorded length; its chain is followed to the end,
		// then read. Up to here, only the clusters of the root directory are claimed.
		uint64 rootBytes = 0;
		for (uint32 cluster = rootCluster; cluster != 0xffffffff; cluster = nextCluster (cluster))
		{
			Fail::If (rootBytes >= ExfatMaxRootDirectoryBytes, "exFAT root directory is too large");
			claim (cluster);
			rootBytes += clusterSize;
		}

		SecureBuffer root;
		if (rootBytes != 0)
			root.Allocate ((size_t) rootBytes);

		for (size_t i = 0; i < metadataClusters.size(); ++i)
			read (clusterOffset (metadataClusters[i]), root.GetRange (i << clusterShift, (size_t) clusterSize));

		// Directory entries: 0x81 allocation bitmap, 0x82 up-case table, 0x00 end of directory
		uint32 bitmapCluster = 0, upcaseCluster = 0;
		uint64 bitmapLength = 0, upcaseLength = 0;

		for (size_t i = 0; i + 32 <= root.Size() && root[i] != 0; i += 32)
		{
			if (root[i] == 0x81)
			{
				// With a single FAT there is exactly one bitmap, the first one
				Fail::If (bitmapCluster != 0 || (root[i + 1] & 1), "exFAT root directory has an unexpected allocation bitmap entry");
				bitmapCluster = u32 (&root[i + 20]);
				bitmapLength = u64 (&root[i + 24]);
			}
			else if (root[i] == 0x82)
			{
				Fail::If (upcaseCluster != 0, "exFAT root directory has more than one up-case table entry");
				upcaseCluster = u32 (&root[i + 20]);
				upcaseLength = u64 (&root[i + 24]);
			}
		}

		const uint64 bitmapBytes = (clusterCount + 7) / 8;
		Fail::If (bitmapCluster == 0, "exFAT allocation bitmap not found");
		// The bitmap holds one bit per cluster; its length may only pad to the end of its last cluster
		Fail::If (bitmapLength < bitmapBytes || bitmapLength > bitmapBytes + clusterSize - 1, "exFAT allocation bitmap has an invalid size");
		Fail::If (upcaseCluster == 0, "exFAT up-case table not found");
		Fail::If (upcaseLength < 16 || upcaseLength > ExfatMaxUpcaseTableBytes, "exFAT up-case table has an invalid size");

		// The bitmap and up-case table have no NoFatChain flag; their chains are always in the FAT
		// Only the clusters that hold the bitmapBytes in use are read
		SecureBuffer bitmap ((size_t) (((bitmapBytes + clusterSize - 1) >> clusterShift) << clusterShift));
		readChain (bitmapCluster, (bitmapLength + clusterSize - 1) >> clusterShift, bitmap);
		readChain (upcaseCluster, (upcaseLength + clusterSize - 1) >> clusterShift, BufferPtr());

		// Bit n stands for cluster n + 2; 1 means allocated
		auto isAllocated = [&] (uint64 n) { return (bitmap[n >> 3] >> (n & 7)) & 1; };

		// Sanity check that the bitmap was located correctly: the clusters of the root
		// directory, of the bitmap itself and of the up-case table are allocated
		for (uint32 cluster : metadataClusters)
			Fail::If (!isAllocated (cluster - 2), "exFAT allocation bitmap is inconsistent");

		vector <ExfatRange> ranges;
		for (uint64 n = 0; n < clusterCount; )
		{
			if (isAllocated (n))
			{
				++n;
				continue;
			}

			const uint64 start = n;
			while (n < clusterCount && !isAllocated (n))
				++n;

			ExfatRange range = { heapOffset + (start << clusterShift), (n - start) << clusterShift };
			ranges.push_back (range);
		}

		return ranges;
	}
}

#endif // TC_HEADER_Core_Unix_ExfatFreeSpace
