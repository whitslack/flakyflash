#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

#include "common/buffer.h"
#include "common/compiler.h"
#include "common/endian.h"
#include "common/enumflags.h"
#include "common/fd.h"
#include "common/io.h"


// https://docs.microsoft.com/en-us/windows/win32/fileio/exfat-specification

namespace exfat {


enum class VolumeFlags : uint16_t { // §3.1.13
	ACTIVE_FAT = 1 << 0, // §3.1.13.1: ActiveFat
	VOLUME_DIRTY = 1 << 1, // §3.1.13.2: VolumeDirty
	MEDIA_FAILURE = 1 << 2, // §3.1.13.3: MediaFailure
	CLEAR_TO_ZERO = 1 << 3, // §3.1.13.4: ClearToZero
};
DEFINE_ENUM_FLAG_OPS(VolumeFlags)

struct BootSector { // §3.1
	std::byte jump_instruction[3]; // §3.1.1: JumpBoot
	char file_system_name[8]; // §3.1.2: FileSystemName: "EXFAT   "
	std::byte must_be_zero[53]; // §3.1.3: MustBeZero
	le<uint64_t> hidden_sectors; // §3.1.4: PartitionOffset
	le<uint64_t> total_logical_sectors; // §3.1.5: VolumeLength
	le<uint32_t> reserved_logical_sectors; // §3.1.6: FatOffset
	le<uint32_t> logical_sectors_per_fat; // §3.1.7: FatLength
	le<uint32_t> data_start_lsn; // §3.1.8: ClusterHeapOffset
	le<uint32_t> total_data_clusters; // §3.1.9: ClusterCount
	le<uint32_t> root_dir_start_cluster; // §3.1.10: FirstClusterOfRootDirectory
	le<uint32_t> volume_id; // §3.1.11: VolumeSerialNumber
	le<uint16_t> version; // §3.1.12: FileSystemRevision
	le<VolumeFlags> volume_flags; // §3.1.13: VolumeFlags
	uint8_t bytes_per_logical_sector_shift; // §3.1.14: BytesPerSectorShift
	uint8_t logical_sectors_per_cluster_shift; // §3.1.15: SectorsPerClusterShift
	uint8_t fats; // §3.1.16: NumberOfFats
	uint8_t physical_drive_number; // §3.1.17: DriveSelect
	uint8_t percent_in_use; // §3.1.18: PercentInUse
	std::byte reserved[7]; // Reserved
	std::byte opaque[0x1FE - 0x078]; // §3.1.19: BootCode
	std::byte boot_sector_signature[2]; // §3.1.20: BootSignature: 0x55 0xAA
};
static_assert(sizeof(struct BootSector) == 512);

enum TypeImportance : uint8_t { // §6.2.1.2
	CRITICAL = 0 << 5,
	BENIGN = 1 << 5
};

enum TypeCategory : uint8_t { // §6.2.1.3
	PRIMARY = 0 << 6,
	SECONDARY = 1 << 6
};

enum InUse : uint8_t { // §6.2.1.4
	IN_USE = 1 << 7
};

enum EntryType : uint8_t { // §6.2.1
	// InUse | TypeImportance | TypeCategory | TypeCode
	ALLOC_BITMAP = +IN_USE | +CRITICAL | +PRIMARY | 1,
	UPCASE_TABLE = +IN_USE | +CRITICAL | +PRIMARY | 2,
	VOLUME_LABEL = +IN_USE | +CRITICAL | +PRIMARY | 3,
	FILE = +IN_USE | +CRITICAL | +PRIMARY | 5,
	STREAM_EXTENSION = +IN_USE | +CRITICAL | +SECONDARY | 0,
	FILE_NAME = +IN_USE | +CRITICAL | +SECONDARY | 1,
	VOLUME_GUID = +IN_USE | +BENIGN | +PRIMARY | 0,
	VENDOR_EXTENSION = +IN_USE | +BENIGN | +SECONDARY | 0,
	VENDOR_ALLOC = +IN_USE | +BENIGN | +SECONDARY | 1,
};

struct GenericDirectoryEntry { // §6.2
	EntryType entry_type; // §6.2.1: EntryType
	std::byte opaque[19]; // CustomDefined
	le<uint32_t> first_cluster; // §6.2.2: FirstCluster
	le<uint64_t> data_length; // §6.2.3: DataLength
};
static_assert(sizeof(struct GenericDirectoryEntry) == 32);

enum class GeneralPrimaryFlags : uint16_t { // §6.3.4
	ALLOC_POSSIBLE = 1 << 0, // §6.3.4.1: AllocationPossible
	NO_FAT_CHAIN = 1 << 1, // §6.3.4.2: NoFatChain
};
DEFINE_ENUM_FLAG_OPS(GeneralPrimaryFlags)

struct GenericPrimaryDirectoryEntry { // §6.3
	EntryType entry_type; // §6.3.1: EntryType
	uint8_t secondary_count; // §6.3.2: SecondaryCount
	le<uint16_t> set_checksum; // §6.3.3: SetChecksum
	le<GeneralPrimaryFlags> flags; // §6.3.4: GeneralPrimaryFlags
	std::byte opaque[14]; // CustomDefined
	le<uint32_t> first_cluster; // §6.3.5: FirstCluster
	le<uint64_t> data_length; // §6.3.6: DataLength
};
static_assert(sizeof(struct GenericPrimaryDirectoryEntry) == 32);

enum class GeneralSecondaryFlags : uint8_t { // §6.4.2
	ALLOC_POSSIBLE = 1 << 0, // §6.4.2.1: AllocationPossible
	NO_FAT_CHAIN = 1 << 1, // §6.4.2.2: NoFatChain
};
DEFINE_ENUM_FLAG_OPS(GeneralSecondaryFlags)

struct GenericSecondaryDirectoryEntry { // §6.4
	EntryType entry_type; // §6.4.1: EntryType
	GeneralSecondaryFlags flags; // §6.4.2: GeneralSecondaryFlags
	std::byte opaque[18]; // CustomDefined
	le<uint32_t> first_cluster; // §6.4.3: FirstCluster
	le<uint64_t> data_length; // §6.4.4: DataLength
};
static_assert(sizeof(struct GenericSecondaryDirectoryEntry) == 32);

enum class BitmapFlags : uint8_t { // §7.1.2
	BITMAP_ID = 1 << 0, // §7.1.2.1: BitmapIdentifier
};
DEFINE_ENUM_FLAG_OPS(BitmapFlags)

struct AllocationBitmapDirectoryEntry { // §7.1
	EntryType entry_type; // §7.1.1: EntryType: ALLOC_BITMAP
	BitmapFlags flags; // §7.1.2: BitmapFlags
	std::byte reserved[18]; // Reserved
	le<uint32_t> first_cluster; // §7.1.3: FirstCluster
	le<uint64_t> data_length; // §7.1.4: DataLength
};
static_assert(sizeof(struct AllocationBitmapDirectoryEntry) == 32);

struct UpcaseTableDirectoryEntry { // §7.2
	EntryType entry_type; // §7.2.1: EntryType: UPCASE_TABLE
	std::byte reserved1[3]; // Reserved1
	le<uint32_t> table_checksum; // §7.2.2: TableChecksum
	std::byte reserved2[12]; // Reserved2
	le<uint32_t> first_cluster; // §7.2.3: FirstCluster
	le<uint64_t> data_length; // §7.2.4: DataLength
};
static_assert(sizeof(struct UpcaseTableDirectoryEntry) == 32);

struct VolumeLabelDirectoryEntry { // §7.3
	EntryType entry_type; // §7.3.1: EntryType: VOLUME_LABEL
	uint8_t char_count; // §7.3.2: CharacterCount
	le<char16_t> volume_label[11]; // §7.3.3: VolumeLabel
	std::byte reserved[8]; // Reserved
};
static_assert(sizeof(struct VolumeLabelDirectoryEntry) == 32);

enum class FileAttributes : uint16_t { // §7.4.4
	READ_ONLY = 1 << 0,
	HIDDEN = 1 << 1,
	SYSTEM = 1 << 2,
	DIRECTORY = 1 << 4,
	ARCHIVE = 1 << 5,
};
DEFINE_ENUM_FLAG_OPS(FileAttributes)

enum Timestamp : uint32_t { // §7.4.8
	DOUBLE_SECONDS_SHIFT = 0, // §7.4.8.1: DoubleSeconds
	DOUBLE_SECONDS_WIDTH = 5,
	MINUTE_SHIFT = 5, // §7.4.8.2: Minute
	MINUTE_WIDTH = 6,
	HOUR_SHIFT = 11, // §7.4.8.3: Hour
	HOUR_WIDTH = 5,
	DAY_SHIFT = 16, // §7.4.8.4: Day
	DAY_WIDTH = 5,
	MONTH_SHIFT = 21, // §7.4.8.5: Month
	MONTH_WIDTH = 4,
	YEAR_SHIFT = 25, // §7.4.8.6: Year
	YEAR_WIDTH = 7
};

void timestamp_to_tm(struct tm &tm, Timestamp timestamp) noexcept;
Timestamp _pure timestamp_from_tm(const struct tm &tm) noexcept;

struct FileDirectoryEntry { // §7.4
	EntryType entry_type; // §7.4.1: EntryType: FILE
	uint8_t secondary_count; // §7.4.2: SecondaryCount
	le<uint16_t> set_checksum; // §7.4.3: SetChecksum
	le<FileAttributes> attributes; // §7.4.4: FileAttributes
	std::byte reserved1[2]; // Reserved1
	le<Timestamp> create_time; // §7.4.5: CreateTimestamp
	le<Timestamp> modify_time; // §7.4.6: LastModifiedTimestamp
	le<Timestamp> access_time; // §7.4.7: LastAccessedTimestamp
	uint8_t create_time_10ms; // §7.4.5: Create10msIncrement
	uint8_t modify_time_10ms; // §7.4.6: LastModified10msIncrement
	uint8_t create_utc_offset; // §7.4.5: CreateUtcOffset
	uint8_t modify_utc_offset; // §7.4.6: LastModifiedUtcOffset
	uint8_t access_utc_offset; // §7.4.7: LastAccessedUtcOffset
	std::byte reserved2[7]; // Reserved2
};
static_assert(sizeof(struct FileDirectoryEntry) == 32);

struct VolumeGUIDDirectoryEntry { // §7.5
	EntryType entry_type; // §7.5.1: EntryType: VOLUME_GUID
	uint8_t secondary_count; // §7.5.2: SecondaryCount
	le<uint16_t> set_checksum; // §7.5.3: SetChecksum
	le<GeneralPrimaryFlags> flags; // §7.5.4: GeneralPrimaryFlags
	std::array<std::byte, 16> volume_guid; // §7.5.5: VolumeGuid
	std::byte reserved[10]; // Reserved
};
static_assert(sizeof(struct VolumeGUIDDirectoryEntry) == 32);

struct StreamExtensionDirectoryEntry { // §7.6
	EntryType entry_type; // §7.6.1: EntryType: STREAM_EXTENSION
	GeneralSecondaryFlags flags; // §7.6.2: GeneralSecondaryFlags
	std::byte reserved1; // Reserved1
	uint8_t name_length; // §7.6.3: NameLength
	le<uint16_t> name_hash; // §7.6.4: NameHash
	std::byte reserved2[2]; // Reserved2
	le<uint64_t> valid_data_length; // §7.6.5: ValidDataLength
	std::byte reserved3[4]; // Reserved3
	le<uint32_t> first_cluster; // §7.6.6: FirstCluster
	le<uint64_t> data_length; // §7.6.7: DataLength
};
static_assert(sizeof(struct StreamExtensionDirectoryEntry) == 32);

struct FileNameDirectoryEntry { // §7.7
	EntryType entry_type; // §7.7.1: EntryType: FILE_NAME
	GeneralSecondaryFlags flags; // §7.7.2: GeneralSecondaryFlags
	le<char16_t> file_name[15]; // §7.7.3: FileName
};
static_assert(sizeof(struct FileNameDirectoryEntry) == 32);

struct VendorExtensionDirectoryEntry { // §7.8
	EntryType entry_type; // §7.8.1: EntryType: VENDOR_EXTENSION
	GeneralSecondaryFlags flags; // §7.8.2: GeneralSecondaryFlags
	std::array<std::byte, 16> vendor_guid; // §7.8.3: VendorGuid
	std::byte opaque[14]; // VendorDefined
};
static_assert(sizeof(struct VendorExtensionDirectoryEntry) == 32);

struct VendorAllocationDirectoryEntry { // §7.9
	EntryType entry_type; // §7.9.1: EntryType: VENDOR_ALLOC
	GeneralSecondaryFlags flags; // §7.9.2: GeneralSecondaryFlags
	std::array<std::byte, 16> vendor_guid; // §7.9.3: VendorGuid
	std::byte opaque[2]; // VendorDefined
	le<uint32_t> first_cluster; // §7.9.4: FirstCluster
	le<uint64_t> data_length; // §7.9.5: DataLength
};
static_assert(sizeof(struct VendorAllocationDirectoryEntry) == 32);

union DirectoryEntry {
	struct GenericDirectoryEntry generic;
	struct GenericPrimaryDirectoryEntry generic_primary;
	struct GenericSecondaryDirectoryEntry generic_secondary;
	struct AllocationBitmapDirectoryEntry alloc_bitmap;
	struct UpcaseTableDirectoryEntry upcase_table;
	struct VolumeLabelDirectoryEntry volume_label;
	struct FileDirectoryEntry file;
	struct VolumeGUIDDirectoryEntry volume_guid;
	struct StreamExtensionDirectoryEntry stream_extension;
	struct FileNameDirectoryEntry file_name;
	struct VendorExtensionDirectoryEntry vendor_extension;
	struct VendorAllocationDirectoryEntry vendor_alloc;
};
static_assert(sizeof(union DirectoryEntry) == 32);


template <typename T, typename Itr>
[[nodiscard]] static inline auto _pure checksum(T checksum, Itr begin, Itr end) noexcept(noexcept(static_cast<T>(*begin++)))
	-> std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, decltype(static_cast<T>(*begin++))>
{
	while (begin != end) {
		checksum = static_cast<T>(std::rotr(checksum, 1) + static_cast<T>(*begin++));
	}
	return checksum;
}


class ClusterChainIO : public Readable<ClusterChainIO>, public Writable<ClusterChainIO> {
public:
	FileDescriptor &dev_fd;
	const struct BootSector &bs;
	const le<uint32_t> * const fat;
private:
	uint32_t cluster;
	uint32_t cluster_position;
public:
	explicit ClusterChainIO(FileDescriptor &dev_fd, const struct BootSector &bs, const le<uint32_t> *fat, uint32_t starting_cluster, uint64_t starting_position = 0);
public:
	_nodiscard ssize_t read(void *buf, size_t n);
	using Readable::read;
	_nodiscard size_t write(const void *buf, size_t n);
	using Writable::write;
};


class Directory {
public:
	Source &source;
private:
	DynamicBuffer buffer;
public:
	explicit Directory(Source &source) = delete;
	template <typename... Args> explicit Directory(Source &source, Args &&...args) :
		source(source), buffer(std::forward<Args>(args)...) { }
public:
	_nodiscard const union DirectoryEntry * next_entry();
};


} // namespace exfat


extern template class Readable<exfat::ClusterChainIO>;
extern template class Writable<exfat::ClusterChainIO>;
