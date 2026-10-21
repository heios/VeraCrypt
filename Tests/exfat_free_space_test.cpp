/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0, the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source distributions.
*/

// Checks src/Core/Unix/ExfatFreeSpace.h. Builds a small exFAT image in memory with
// a known allocation bitmap, checks the free ranges the parser returns, then damages
// copies of the image and checks that each one is refused. On macOS it also formats
// a disk image with newfs_exfat, writes marked files, deletes half of them, and
// compares the parsed free space with statfs and with where the markers ended up.
// No root. Build VeraCrypt first, which builds src/Platform/Platform.a, then run from
// the repository root:
//
//   c++ -std=c++11 -Wall -I src -o /tmp/exfat_test Tests/exfat_free_space_test.cpp src/Platform/Platform.a && /tmp/exfat_test [image ...]
//
// Every image given on the command line must be refused by the parser. Each refusal is
// printed with its reason.

#include "Core/Unix/ExfatFreeSpace.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/mount.h>
#endif

using namespace VeraCrypt;

static string AttachedDevice;
static string TempDir;
static const string TempDirPrefix = "/tmp/exfattest.";

// Deletes the directory mkdtemp created, and nothing else. Uses system(), not Run(),
// since Run() calls Check(), which calls this.
static void RemoveTempDir ()
{
	if (TempDir.size() > TempDirPrefix.size() && TempDir.compare (0, TempDirPrefix.size(), TempDirPrefix) == 0)
		system (("rm -rf -- " + TempDir).c_str());
	TempDir.clear();
}

static void Check (bool ok, const string &what)
{
	if (ok)
		return;

	fprintf (stderr, "FAIL: %s\n", what.c_str());
	if (!AttachedDevice.empty())
		system (("hdiutil detach -force " + AttachedDevice + " >/dev/null").c_str());
	RemoveTempDir();
	exit (1);
}

// Returns whether the parser refuses the image, and prints the reason if it does
static bool Throws (const vector <uint8_t> &image, const string &name)
{
	try
	{
		GetExfatFreeRanges ([&] (uint64_t offset, const BufferPtr &buffer)
		{
			// Like the reader in CoreUnix.cpp
			if (offset + buffer.Size() > image.size())
				throw TrimFailed (SRC_POS, L"TRIM_IMAGE_UNREADABLE");
			memcpy (buffer, &image[offset], buffer.Size());
		}, image.size());
		return false;
	}
	catch (TrimFailed &e)
	{
		printf ("%s refused: %s\n", name.c_str(), StringConverter::ToSingle (e.GetSubject()).c_str());
		return true;
	}
	catch (exception &e)
	{
		Check (false, name + ": " + StringConverter::ToSingle (StringConverter::ToExceptionString (e)));
	}
	catch (...)
	{
		Check (false, name + ": unknown exception");
	}

	return true;	// not reached, Check (false) exits
}

static vector <ExfatRange> Parse (const vector <uint8_t> &img)
{
	return GetExfatFreeRanges ([&] (uint64_t offset, const BufferPtr &buffer)
	{
		Check (offset + buffer.Size() <= img.size(), "read beyond the image");
		memcpy (buffer, &img[offset], buffer.Size());
	}, img.size());
}

static uint32_t U32 (const uint8_t *p)
{
	return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

static void PutU32 (uint8_t *p, uint32_t v)
{
	for (int i = 0; i < 4; ++i)
		p[i] = (uint8_t) (v >> (8 * i));
}

// Rewrites the main boot region checksum after a boot sector field was changed
static void FixChecksum (vector <uint8_t> &img)
{
	const size_t sectorSize = (size_t) 1 << img[108];
	uint32_t checksum = 0;
	for (size_t i = 0; i < 11 * sectorSize; ++i)
	{
		if (i != 106 && i != 107 && i != 112)
			checksum = ((checksum & 1) ? 0x80000000 : 0) + (checksum >> 1) + img[i];
	}

	for (size_t i = 11 * sectorSize; i < 12 * sectorSize; i += 4)
		PutU32 (&img[i], checksum);
}

// Damages copies of a valid image in ways the parser must refuse
static void TestDamagedImages (const vector <uint8_t> &img)
{
	const unsigned sectorShift = img[108], clusterShift = sectorShift + img[109];
	const uint64_t fatOffset = (uint64_t) U32 (&img[80]) << sectorShift;
	const uint64_t heapOffset = (uint64_t) U32 (&img[88]) << sectorShift;
	const uint32_t clusterCount = U32 (&img[92]);
	const uint32_t rootCluster = U32 (&img[96]);

	auto fat = [&] (vector <uint8_t> &image, uint32_t cluster) { return &image[fatOffset + (uint64_t) cluster * 4]; };
	auto clusterOffset = [&] (uint32_t cluster) { return heapOffset + ((uint64_t) (cluster - 2) << clusterShift); };

	// Root directory entries of the bitmap and the up-case table (first root cluster)
	size_t bitmapEntry = 0, upcaseEntry = 0;
	for (size_t i = clusterOffset (rootCluster); img[i] != 0; i += 32)
	{
		if (img[i] == 0x81)
			bitmapEntry = i;
		else if (img[i] == 0x82)
			upcaseEntry = i;
	}
	Check (bitmapEntry != 0 && upcaseEntry != 0, "bitmap and up-case entries found");

	const uint32_t bitmapCluster = U32 (&img[bitmapEntry + 20]);
	const uint32_t upcaseCluster = U32 (&img[upcaseEntry + 20]);
	const uint64_t bitmapLength = U32 (&img[bitmapEntry + 24]);
	const uint64_t bitmapBytes = (clusterCount + 7) / 8;
	const uint64_t clusterSize = 1ULL << clusterShift;

	struct Case
	{
		const char *Name;
		std::function <void (vector <uint8_t> &)> Damage;
	};

	vector <Case> cases =
	{
		{ "dirty volume", [&] (vector <uint8_t> &b) { b[106] |= 2; } },
		{ "checksum mismatch", [&] (vector <uint8_t> &b) { b[100] ^= 1; } },
		{ "non-exFAT", [&] (vector <uint8_t> &b) { b[3] = 'N'; FixChecksum (b); } },
		{ "two FATs", [&] (vector <uint8_t> &b) { b[110] = 2; FixChecksum (b); } },
		{ "sector shift 8", [&] (vector <uint8_t> &b) { b[108] = 8; FixChecksum (b); } },
		{ "sector shift 13", [&] (vector <uint8_t> &b) { b[108] = 13; FixChecksum (b); } },
		{ "cluster shift 26", [&] (vector <uint8_t> &b) { b[109] = (uint8_t) (26 - sectorShift); FixChecksum (b); } },
		{ "zero clusters", [&] (vector <uint8_t> &b) { PutU32 (&b[92], 0); FixChecksum (b); } },
		{ "heap beyond volume", [&] (vector <uint8_t> &b) { PutU32 (&b[92], 0xfffffff5); FixChecksum (b); } },
		{ "FAT overlaps heap", [&] (vector <uint8_t> &b) { PutU32 (&b[84], U32 (&b[88])); FixChecksum (b); } },
		{ "root cluster out of range", [&] (vector <uint8_t> &b) { PutU32 (&b[96], clusterCount + 2); FixChecksum (b); } },
		{ "root cluster 1", [&] (vector <uint8_t> &b) { PutU32 (&b[96], 1); FixChecksum (b); } },
		{ "root chain cycle", [&] (vector <uint8_t> &b) { PutU32 (fat (b, rootCluster), rootCluster); } },
		{ "root chain out of range", [&] (vector <uint8_t> &b) { PutU32 (fat (b, rootCluster), clusterCount + 5); } },
		{ "root chain to free cluster", [&] (vector <uint8_t> &b) { PutU32 (fat (b, rootCluster), clusterCount + 1); } },
		{ "bitmap chain cycle", [&] (vector <uint8_t> &b) { PutU32 (fat (b, bitmapCluster), bitmapCluster); } },
		{ "bitmap cross-linked with root", [&] (vector <uint8_t> &b) { PutU32 (&b[bitmapEntry + 20], rootCluster); } },
		{ "up-case cross-linked with bitmap", [&] (vector <uint8_t> &b) { PutU32 (&b[upcaseEntry + 20], bitmapCluster); } },
		{ "bitmap entry missing", [&] (vector <uint8_t> &b) { b[bitmapEntry] = 0x01; } },
		{ "second bitmap entry", [&] (vector <uint8_t> &b) { b[upcaseEntry] = 0x81; } },
		{ "up-case entry missing", [&] (vector <uint8_t> &b) { b[upcaseEntry] = 0x02; } },
		{ "bitmap chain too long", [&] (vector <uint8_t> &b) { PutU32 (fat (b, bitmapCluster), upcaseCluster); } },
		{ "bitmap too small", [&] (vector <uint8_t> &b) { PutU32 (&b[bitmapEntry + 24], (uint32_t) bitmapBytes - 1); } },
		{ "bitmap too large", [&] (vector <uint8_t> &b) { PutU32 (&b[bitmapEntry + 24], (uint32_t) (bitmapBytes + clusterSize)); } },
		{ "up-case too large", [&] (vector <uint8_t> &b) { PutU32 (&b[upcaseEntry + 24], 2 * 65536 + 1); } },
		{ "root cluster not allocated", [&] (vector <uint8_t> &b) { b[clusterOffset (bitmapCluster) + (rootCluster - 2) / 8] &= ~(1 << ((rootCluster - 2) % 8)); } },
		{ "bitmap cluster not allocated", [&] (vector <uint8_t> &b) { b[clusterOffset (bitmapCluster) + (bitmapCluster - 2) / 8] &= ~(1 << ((bitmapCluster - 2) % 8)); } },
		{ "up-case cluster not allocated", [&] (vector <uint8_t> &b) { b[clusterOffset (bitmapCluster) + (upcaseCluster - 2) / 8] &= ~(1 << ((upcaseCluster - 2) % 8)); } },
	};

	// Ending the chain early only makes a difference for a bitmap of several clusters
	if (bitmapLength > clusterSize)
		cases.push_back ({ "bitmap chain truncated", [&] (vector <uint8_t> &b) { PutU32 (fat (b, bitmapCluster), 0xffffffff); } });

	for (const Case &c : cases)
	{
		vector <uint8_t> bad = img;
		c.Damage (bad);
		Check (Throws (bad, c.Name), string (c.Name) + " refused");
	}

	// The damage must be what makes the difference: the untouched image parses
	Check (!Throws (img, "valid image"), "valid image accepted");
}

// A minimal exFAT image: 512-byte sectors and clusters, 8192 clusters, so that the
// bitmap (1024 bytes) and the root directory each span two clusters. Clusters 2-6
// hold the metadata; clusters 10-20 are marked allocated to split the free space.
static const unsigned SyntheticClusterCount = 8192;
static const unsigned SyntheticHeapSector = 96;

static vector <uint8_t> BuildSyntheticImage ()
{
	const unsigned sectorSize = 512, fatSector = 24;
	const unsigned volumeSectors = SyntheticHeapSector + SyntheticClusterCount;
	vector <uint8_t> img (volumeSectors * sectorSize, 0);

	// Boot sector
	img[0] = 0xeb; img[1] = 0x76; img[2] = 0x90;
	memcpy (&img[3], "EXFAT   ", 8);
	PutU32 (&img[72], volumeSectors);
	PutU32 (&img[80], fatSector);
	PutU32 (&img[84], (SyntheticClusterCount + 2) * 4 / sectorSize + 1);
	PutU32 (&img[88], SyntheticHeapSector);
	PutU32 (&img[92], SyntheticClusterCount);
	PutU32 (&img[96], 5);
	PutU32 (&img[100], 0x12345678);
	img[105] = 1;	// filesystem revision 1.0
	img[108] = 9;	// sector shift
	img[109] = 0;	// sectors per cluster shift
	img[110] = 1;	// one FAT
	img[111] = 0x80;
	img[510] = 0x55; img[511] = 0xaa;

	// Extended boot sectors carry a signature of their own
	for (unsigned s = 1; s <= 8; ++s)
		PutU32 (&img[s * sectorSize + 508], 0xaa550000);

	FixChecksum (img);

	// FAT: media entry, then the chains of the bitmap (2-3), up-case table (4) and root (5-6)
	uint8_t *fat = &img[fatSector * sectorSize];
	PutU32 (fat, 0xfffffff8);
	PutU32 (fat + 4, 0xffffffff);
	PutU32 (fat + 2 * 4, 3);
	PutU32 (fat + 3 * 4, 0xffffffff);
	PutU32 (fat + 4 * 4, 0xffffffff);
	PutU32 (fat + 5 * 4, 6);
	PutU32 (fat + 6 * 4, 0xffffffff);

	// Allocation bitmap: bit n is cluster n + 2
	uint8_t *heap = &img[SyntheticHeapSector * sectorSize];
	uint8_t *bitmap = heap;
	bitmap[0] = 0x1f;	// clusters 2-6
	bitmap[1] = 0xff;	// clusters 10-17
	bitmap[2] = 0x07;	// clusters 18-20

	// Root directory: allocation bitmap and up-case table entries
	uint8_t *root = heap + 3 * sectorSize;
	root[0] = 0x81;
	PutU32 (&root[20], 2);
	PutU32 (&root[24], (SyntheticClusterCount + 7) / 8);
	root[32] = 0x82;
	PutU32 (&root[32 + 20], 4);
	PutU32 (&root[32 + 24], 128);

	return img;
}

static void TestSyntheticImage ()
{
	const vector <uint8_t> img = BuildSyntheticImage();
	const vector <ExfatRange> ranges = Parse (img);
	const uint64_t heap = SyntheticHeapSector * 512;

	Check (ranges.size() == 2, "synthetic image has two free ranges");
	Check (ranges[0].Offset == heap + 5 * 512 && ranges[0].Length == 3 * 512, "clusters 7-9 are free");
	Check (ranges[1].Offset == heap + 19 * 512 && ranges[1].Length == (SyntheticClusterCount - 19) * 512, "clusters 21 onwards are free");

	TestDamagedImages (img);
	puts ("synthetic image ok");
}

#ifdef __APPLE__

static string Run (const string &command)
{
	FILE *p = popen ((command + " 2>&1").c_str(), "r");
	string out;
	char buf[4096];
	for (size_t n; (n = fread (buf, 1, sizeof (buf), p)) > 0; )
		out.append (buf, n);
	Check (pclose (p) == 0, command + ":\n" + out);
	return out;
}

static void TestClusterSize (const string &clusterSize)
{
	const int files = 60, block = 4096;   // 60 files need a second root directory cluster at 4 KiB
	string dir = TempDirPrefix + "XXXXXX";
	Check (mkdtemp (&dir[0]) != nullptr, "mkdtemp");
	TempDir = dir;
	const string image = TempDir + "/v.img", mnt = TempDir + "/mnt";
	mkdir (mnt.c_str(), 0700);

	int fd = open (image.c_str(), O_CREAT | O_RDWR, 0600);
	Check (fd != -1 && ftruncate (fd, 300 << 20) == 0, "create image");
	close (fd);

	string attached = Run ("hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount " + image);
	attached.erase (0, attached.find ("/dev/disk"));
	AttachedDevice = attached.substr (0, attached.find_first_of (" \t\n"));
	Run ("newfs_exfat -R -b " + clusterSize + " /dev/r" + AttachedDevice.substr (5));
	Run ("diskutil mount -mountPoint " + mnt + " " + AttachedDevice);

	// Every 4 KiB block of every file starts with: token, file index, block index
	uint8_t token[16];
	arc4random_buf (token, sizeof (token));
	for (int i = 0; i < files; ++i)
	{
		const string path = mnt + "/f" + std::to_string (i);
		FILE *f = fopen (path.c_str(), "wb");
		for (int b = 0; b < (i + 1) * 16; ++b)
		{
			vector <uint8_t> data (block);
			arc4random_buf (data.data(), data.size());
			memcpy (&data[0], token, 16);
			memcpy (&data[16], &i, 4);
			memcpy (&data[20], &b, 4);
			fwrite (data.data(), 1, data.size(), f);
		}
		fflush (f);
		fcntl (fileno (f), F_FULLFSYNC);
		fclose (f);
	}

	for (int i = 1; i < files; i += 2)
		unlink ((mnt + "/f" + std::to_string (i)).c_str());
	sync();

	// Unmounting writes metadata (.fseventsd), so take statfs from a read-only remount
	Run ("diskutil unmount " + AttachedDevice);
	Run ("diskutil mount readOnly -mountPoint " + mnt + " " + AttachedDevice);

	struct statfs st;
	Check (statfs (mnt.c_str(), &st) == 0, "statfs");
	const uint64_t statfsFree = (uint64_t) st.f_bfree * st.f_bsize;

	Run ("hdiutil detach " + AttachedDevice);
	AttachedDevice.clear();

	vector <uint8_t> img (300 << 20);
	fd = open (image.c_str(), O_RDONLY);
	Check (pread (fd, img.data(), img.size(), 0) == (ssize_t) img.size(), "read image");
	close (fd);

	vector <ExfatRange> ranges = Parse (img);

	uint64_t parsedFree = 0;
	for (size_t i = 0; i < ranges.size(); ++i)
	{
		parsedFree += ranges[i].Length;
		Check (i == 0 || ranges[i].Offset > ranges[i - 1].Offset + ranges[i - 1].Length, "ranges sorted and merged");
	}

	printf ("cluster %s: %zu free ranges, parsed %llu bytes free, statfs %llu\n", clusterSize.c_str(), ranges.size(),
		(unsigned long long) parsedFree, (unsigned long long) statfsFree);
	Check (parsedFree == statfsFree, "parsed free space equals statfs");

	// Blocks of kept files must be outside the free ranges. Blocks of deleted files should be
	// inside, except where unmount metadata reused a freed cluster and left its tail stale.
	auto isFree = [&] (uint64_t offset)
	{
		for (const ExfatRange &r : ranges)
			if (offset >= r.Offset && offset < r.Offset + r.Length)
				return true;
		return false;
	};

	int kept = 0, deleted = 0, deletedButAllocated = 0;
	for (uint64_t offset = 0; offset + block <= img.size(); offset += 512)
	{
		if (memcmp (&img[offset], token, 16) != 0)
			continue;

		int i;
		memcpy (&i, &img[offset + 16], 4);
		if (i % 2 == 0)
		{
			Check (!isFree (offset), "file " + std::to_string (i) + " block at " + std::to_string (offset) + " is in a free range");
			kept++;
		}
		else
		{
			deleted++;
			deletedButAllocated += !isFree (offset);
		}
	}

	int expectedKept = 0;
	for (int i = 0; i < files; i += 2)
		expectedKept += (i + 1) * 16;
	Check (kept == expectedKept && deleted > 0, "all markers found");
	Check (deletedButAllocated * 20 < deleted, "deleted files are free");

	TestDamagedImages (img);

	RemoveTempDir();
}

#endif // __APPLE__

int main (int argc, char **argv)
{
	try
	{
		TestSyntheticImage();

#ifdef __APPLE__
		TestClusterSize ("4096");   // multi-cluster bitmap and FAT chain
		TestClusterSize ("131072");
#endif

		for (int i = 1; i < argc; ++i)
		{
			vector <uint8_t> img;
			FILE *f = fopen (argv[i], "rb");
			Check (f != nullptr, string ("open ") + argv[i]);
			char buf[65536];
			for (size_t n; (n = fread (buf, 1, sizeof (buf), f)) > 0; )
				img.insert (img.end(), buf, buf + n);
			fclose (f);
			Check (Throws (img, argv[i]), string (argv[i]) + " refused");
		}

		puts ("ok");
		return 0;
	}
	catch (exception &e)
	{
		Check (false, StringConverter::ToSingle (StringConverter::ToExceptionString (e)));
	}
	catch (...)
	{
		Check (false, "unknown exception");
	}

	return 1;	// not reached, Check (false) exits
}
