#include <bit>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>

#include <sysexits.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <sys/random.h>
#include <sys/sysinfo.h>

#include "common/cli.h"
#include "common/compiler.h"
#include "common/endian.h"
#include "common/fd.h"
#include "common/format.h"
#include "common/narrow.h"
#include "common/uuid.h"

#include "exfat.h"


#if __cpp_lib_constexpr_functional < 201907L
namespace std {
	struct __is_transparent;
	struct identity {
		using is_transparent = __is_transparent;
		template <typename T> constexpr T && operator()(T &&t) const noexcept { return std::forward<T>(t); }
	};
}
#endif


struct BootSector {

#pragma pack(push, 1)
	struct BPB {
		le<uint16_t> bytes_per_logical_sector; // BPB_BytsPerSec
		uint8_t logical_sectors_per_cluster; // BPB_SecPerClus
		le<uint16_t> reserved_logical_sectors; // BPB_RsvdSecCnt
		uint8_t fats; // BPB_NumFATs
		le<uint16_t> root_dir_entries; // BPB_RootEntCnt
		le<uint16_t> old_total_logical_sectors; // BPB_TotSec16
		std::byte media_descriptor; // BPB_Media
		le<uint16_t> logical_sectors_per_fat; // BPB_FATSz16
		le<uint16_t> physical_sectors_per_track; // BPB_SecPerTrk
		le<uint16_t> heads; // BPB_NumHeads
		le<uint32_t> hidden_sectors; // BPB_HiddSec
		le<uint32_t> total_logical_sectors; // BPB_TotSec32
	};
	static_assert(sizeof(struct BPB) == 25);

	struct EBPB {
		uint8_t physical_drive_number; // BS_DrvNum
		std::byte reserved; // BS_Reserved1
		std::byte extended_boot_signature; // BS_BootSig
		le<uint32_t> volume_id; // BS_VolID
		char volume_label[11]; // BS_VolLab
		char file_system_type[8]; // BS_FilSysType
	};
	static_assert(sizeof(struct EBPB) == 26);
#pragma pack(pop)

	struct FATParams {
		struct EBPB ebpb;
		std::byte opaque[0x1FC - 0x03E];
	};
	static_assert(sizeof(struct FATParams) == 512 - (3 + 8 + 25) - (1 + 1 + 2));

	struct FAT32Params {
		le<uint32_t> logical_sectors_per_fat; // BPB_FATSz32
		le<uint16_t> mirroring_flags; // BPB_ExtFlags
		le<uint16_t> version; // BPB_FSVer
		le<uint32_t> root_dir_start_cluster; // BPB_RootClus
		le<uint16_t> fs_info_lsn; // BPB_FSInfo
		le<uint16_t> boot_sector_backup_lsn; // BPB_BkBootSec
		std::byte reserved[12]; // BPB_Reserved
		struct EBPB ebpb;
		std::byte opaque[0x1FC - 0x05A];
	};
	static_assert(sizeof(struct FAT32Params) == 512 - (3 + 8 + 25) - (1 + 1 + 2));

	std::byte jump_instruction[3]; // BS_jmpBoot
	char oem_name[8]; // BS_OEMName
	struct BPB bpb;
	union {
		struct FATParams fat;
		struct FAT32Params fat32;
	};
	std::byte padding;
	uint8_t old_physical_drive_number;
	std::byte boot_sector_signature[2]; // 0x55, 0xAA
};
static_assert(sizeof(struct BootSector) == 512);


struct FSInfoSector {
	std::byte fs_info_sector_signature1[4]; // FSI_LeadSig: "RRaA"
	std::byte reserved1[480]; // FSI_Reserved1
	std::byte fs_info_sector_signature2[4]; // FSI_StrucSig: "rrAa"
	le<uint32_t> last_known_free_data_clusters; // FSI_Free_Count
	le<uint32_t> most_recently_allocated_data_cluster; // FSI_Nxt_Free
	std::byte reserved2[12]; // FSI_Reserved2
	std::byte fs_info_sector_signature3[4]; // FSI_TrailSig: 0x00, 0x00, 0x55, 0xAA
};
static_assert(sizeof(struct FSInfoSector) == 512);


static std::ostream & operator<<(std::ostream &os, std::byte b) {
	return os << std::hex << static_cast<unsigned>(b) << std::dec;
}

template <size_t N>
static std::ostream & operator<<(std::ostream &os, const std::byte (&b)[N]) {
	if constexpr (N > 0) {
		os << std::hex << static_cast<unsigned>(b[0]);
		for (size_t i = 1; i < N; ++i) {
			os.put(' ') << static_cast<unsigned>(b[i]);
		}
		os << std::dec;
	}
	return os;
}

static std::string _pure to_string(std::u16string_view sv) {
	std::string ret;
	auto &codecvt = std::use_facet<std::codecvt<char16_t, char, std::mbstate_t>>(std::locale());
	std::mbstate_t state { };
	const char16_t *from_next;
	char *to_next;
	ret.resize(sv.size() * codecvt.max_length());
	codecvt.out(state, sv.data(), sv.data() + sv.size(), from_next, ret.data(), ret.data() + ret.size(), to_next);
	ret.resize(to_next - ret.data());
	return ret;
}

struct fat_version {
	const uint16_t version;
	constexpr explicit fat_version(uint16_t version) noexcept : version(version) { }
	friend std::ostream & operator<<(std::ostream &os, const struct fat_version &v) {
		auto fill = os.fill('0');
		auto flags = os.flags(std::ios_base::dec | std::ios_base::right);
		os << (v.version >> 8) << '.' << std::setw(2) << (v.version & 0xFF);
		os.flags(flags);
		os.fill(fill);
		return os;
	}
};

struct exfat_volume_flags {
	exfat::VolumeFlags flags;
	constexpr explicit exfat_volume_flags(exfat::VolumeFlags flags) noexcept : flags(flags) { }
	friend std::ostream & operator<<(std::ostream &os, const struct exfat_volume_flags &f) {
		using Flags = exfat::VolumeFlags;
		auto flags = f.flags;
		if (+(flags & (Flags::ACTIVE_FAT | Flags::VOLUME_DIRTY | Flags::MEDIA_FAILURE | Flags::CLEAR_TO_ZERO))) {
			if (+(flags & Flags::ACTIVE_FAT)) {
				os << "ActiveFat";
				if (+(flags &= ~Flags::ACTIVE_FAT)) {
					os << " | ";
				}
			}
			if (+(flags & Flags::VOLUME_DIRTY)) {
				os << "VolumeDirty";
				if (+(flags &= ~Flags::VOLUME_DIRTY)) {
					os << " | ";
				}
			}
			if (+(flags & Flags::MEDIA_FAILURE)) {
				os << "MediaFailure";
				if (+(flags &= ~Flags::MEDIA_FAILURE)) {
					os << " | ";
				}
			}
			if (+(flags & Flags::CLEAR_TO_ZERO)) {
				os << "ClearToZero";
				if (+(flags &= ~Flags::CLEAR_TO_ZERO)) {
					os << " | ";
				}
			}
			if (!flags) {
				return os;
			}
		}
		return os << flags;
	}
};

static void getrandom_fully(void *buf, size_t buflen, unsigned flags = 0) {
	for (ssize_t r; (r = ::getrandom(buf, buflen, flags)) >= 0;) {
		if ((buflen -= r) == 0) {
			return;
		}
		buf = static_cast<std::byte *>(buf) + r;
	}
	throw std::system_error(errno, std::system_category(), "getrandom");
}

static bool f3_fill(void *buf, size_t size, uint64_t x) noexcept {
	bool changed = false;
	auto vec = static_cast<le<uint64_t> *>(buf);
	size_t n = size / sizeof *vec;
	assert(n * sizeof *vec == size);
	for (size_t i = 0; i < n; ++i) {
		changed |= std::exchange(vec[i], x) != x;
		x = x * UINT64_C(0x10000000F) + 17;
	}
	return changed;
}

static size_t _pure count_flipped_bits(const void *buf1, const void *buf2, size_t size) noexcept {
	auto words1 = static_cast<const unsigned long *>(buf1), words2 = static_cast<const unsigned long *>(buf2);
	size_t n = size / sizeof(unsigned long);
	assert(n * sizeof(unsigned long) == size);
	return std::inner_product(words1, words1 + n, words2, size_t { }, std::plus { },
			[](unsigned long x, unsigned long y) noexcept {
				return std::popcount(x ^ y);
			});
}

static DynamicBuffer make_aligned_buffer(size_t alignment, size_t size) {
	assert(size % alignment == 0);
	DynamicBuffer buf;
	if (!(buf.bptr = static_cast<std::byte *>(std::aligned_alloc(alignment, size)))) {
		throw std::bad_alloc();
	}
	buf.eptr = (buf.pptr = buf.gptr = buf.bptr) + size;
	return buf;
}

enum class Action {
	READ, REREAD, ZEROOUT, READZEROS, F3WRITE, F3READ, SECDISCARD, DISCARD, TRASH, BAD, FREE, LIST
};

static Action _pure parse_action(std::string_view sv) {
	if (sv == "read") {
		return Action::READ;
	}
	if (sv == "reread") {
		return Action::REREAD;
	}
	if (sv == "zeroout") {
		return Action::ZEROOUT;
	}
	if (sv == "readzeros") {
		return Action::READZEROS;
	}
	if (sv == "f3write") {
		return Action::F3WRITE;
	}
	if (sv == "f3read") {
		return Action::F3READ;
	}
	if (sv == "secdiscard") {
		return Action::SECDISCARD;
	}
	if (sv == "discard") {
		return Action::DISCARD;
	}
	if (sv == "trash") {
		return Action::TRASH;
	}
	if (sv == "bad") {
		return Action::BAD;
	}
	if (sv == "free") {
		return Action::FREE;
	}
	if (sv == "list") {
		return Action::LIST;
	}
	throw std::invalid_argument(std::string { sv });
}

struct Actions : std::vector<Action> {
	using std::vector<Action>::vector;
	Actions & operator=(std::string_view sv) {
		this->clear();
		for (std::string_view::size_type pos;
			(pos = sv.find(',')) != std::string_view::npos;
			sv.remove_prefix(pos + 1))
		{
			if (pos > 0) {
				this->emplace_back(parse_action(sv.substr(0, pos)));
			}
		}
		if (!sv.empty()) {
			this->emplace_back(parse_action(sv));
		}
		return *this;
	}
	void drop_destructive_actions(const char option[]) {
		std::erase_if(*this, [option](Action action) {
			switch (action) {
				case Action::READ:
				case Action::REREAD:
					return false;
				case Action::ZEROOUT:
					log_dropped_action(option, "zeroout");
					return true;
				case Action::READZEROS:
					return false;
				case Action::F3WRITE:
					log_dropped_action(option, "f3write");
					return true;
				case Action::F3READ:
					return false;
				case Action::SECDISCARD:
					log_dropped_action(option, "secdiscard");
					return true;
				case Action::DISCARD:
					log_dropped_action(option, "discard");
					return true;
				case Action::TRASH:
					log_dropped_action(option, "trash");
					return true;
				case Action::BAD:
					log_dropped_action(option, "bad");
					return true;
				case Action::FREE:
					log_dropped_action(option, "free");
					return true;
				case Action::LIST:
					return false;
			}
			return false;
		});
		std::clog.flush();
	}
private:
	static void log_dropped_action(const char option[], const char action[]) {
		std::clog << "--" << option << ": " << action << " action ignored due to --dry-run\n";
	}
};

int main(int argc, char *argv[]) {
	std::ios_base::sync_with_stdio(false);
	std::locale::global(std::locale(""));
	std::clog << std::showbase << std::internal;
	cli::Option<Actions>
			bad_clusters_option { "bad-clusters", 'b' },
			free_clusters_option { "free-clusters", 'f' };
	cli::Option<>
			dry_run_option { "dry-run", 'n' },
			verbose_option { "verbose", 'v' },
			help_option { "help" };
	bad_clusters_option.args.emplace_back();
	free_clusters_option.args.emplace_back(Actions { Action::READ, Action::REREAD });
	if ((argc = cli::parse(argc, argv, {
			&bad_clusters_option,
			&free_clusters_option,
			&dry_run_option,
			&verbose_option,
			&help_option
		})) != 2 || help_option)
	{
		std::clog << "usage: " << argv[0] << " [options] <block-device>\n"
				"\n"
				"options:\n"
				"\t-b,--bad-clusters=[<action>,...]\n"
				"\t-f,--free-clusters=[<action>,...]\n"
				"\t-n,--dry-run\n"
				"\t-v,--verbose\n"
				"\n"
				"actions:\n"
				"\tread: read cluster; mark bad if device errors\n"
				"\treread: re-read cluster; mark bad if different\n"
				"\tzeroout: issue BLKZEROOUT ioctl on cluster\n"
				"\t         (elided if a previous \"read\" found cluster already zeroed)\n"
				"\treadzeros: read cluster; mark bad if not zeroed\n"
				"\tf3write: fill cluster with reproducible data\n"
				"\t         (elided if a previous \"read\" found cluster already correct)\n"
				"\tf3read: read cluster; mark bad if subtly changed\n"
				"\tsecdiscard: issue BLKSECDISCARD ioctl on cluster\n"
				"\tdiscard: issue BLKDISCARD ioctl on cluster\n"
				"\ttrash: fill cluster with pseudorandom garbage\n"
				"\tbad: mark cluster as bad unconditionally\n"
				"\tfree: mark cluster as free unconditionally\n"
				"\tlist: write cluster number to stdout\n"
				"\n"
				"defaults:\n"
				"\t--bad-clusters=\n"
				"\t--free-clusters=read,reread\n";
		return EX_USAGE;
	}
	if (dry_run_option) {
		bad_clusters_option.args.back().drop_destructive_actions(bad_clusters_option.long_form);
		free_clusters_option.args.back().drop_destructive_actions(free_clusters_option.long_form);
	}

	auto const page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size < 0) {
		throw std::system_error(errno, std::system_category(), "sysconf(_SC_PAGE_SIZE)");
	}

	FileDescriptor fd(argv[1], (dry_run_option ? O_RDONLY : O_RDWR) | O_EXCL | O_DIRECT | O_CLOEXEC);

	auto const bs = new(std::align_val_t(page_size)) struct BootSector;
	fd.pread_fully(bs, sizeof *bs, 0);
	uint64_t total_logical_sectors;
	uint32_t reserved_logical_sectors, logical_sectors_per_fat;
	unsigned bytes_per_logical_sector_shift, bytes_per_logical_sector, logical_sectors_per_cluster_shift, fats;
	const struct BootSector::BPB *bpb = nullptr;
	const struct BootSector::FAT32Params *fat32 = nullptr;
	struct exfat::BootSector *exfat = nullptr;
	if (bs->boot_sector_signature[0] != static_cast<std::byte>(0x55) ||
		bs->boot_sector_signature[1] != static_cast<std::byte>(0xAA) ||
		std::memcmp(bs->oem_name, "NTFS    ", 8) == 0 ||
		(std::memcmp(bs->oem_name, "EXFAT   ", 8) == 0 ?
			(exfat = reinterpret_cast<struct exfat::BootSector *>(bs),
			std::any_of(std::begin(exfat->must_be_zero), std::end(exfat->must_be_zero), std::identity { }) ||
			(bytes_per_logical_sector_shift = exfat->bytes_per_logical_sector_shift) < 9 ||
			bytes_per_logical_sector_shift > 12 ||
			(logical_sectors_per_cluster_shift = exfat->logical_sectors_per_cluster_shift) > 25 - bytes_per_logical_sector_shift ||
			(fats = exfat->fats) < 1 || fats > 2 ||
			(total_logical_sectors = exfat->total_logical_sectors) < UINT64_C(1) << 20 - bytes_per_logical_sector_shift ||
			(reserved_logical_sectors = exfat->reserved_logical_sectors) < 24 ||
			(logical_sectors_per_fat = exfat->logical_sectors_per_fat) < (uint64_t { exfat->total_data_clusters } + 2) * sizeof(uint32_t) + (bytes_per_logical_sector = 1u << bytes_per_logical_sector_shift) - 1 >> bytes_per_logical_sector_shift ||
			exfat->data_start_lsn < reserved_logical_sectors + uint64_t { logical_sectors_per_fat } * fats ||
			letoh(exfat->total_data_clusters) != std::min(total_logical_sectors - exfat->data_start_lsn >> logical_sectors_per_cluster_shift, (UINT64_C(1) << 32) - 11) ||
			exfat->root_dir_start_cluster < 2 ||
			exfat->root_dir_start_cluster > exfat->total_data_clusters + 1 ||
			exfat->version < 0x0100 ||
			exfat->version >> 8 > 99 ||
			(exfat->version & 0xFF) > 99 ||
			exfat->percent_in_use > 100 && exfat->percent_in_use != 0xFF)
		:	(bpb = &bs->bpb,
			(bytes_per_logical_sector = bpb->bytes_per_logical_sector) == 0 ||
			bytes_per_logical_sector != 1u << (bytes_per_logical_sector_shift = std::bit_width(bytes_per_logical_sector) - 1) ||
			bpb->logical_sectors_per_cluster == 0 ||
			bpb->logical_sectors_per_cluster != 1u << (logical_sectors_per_cluster_shift = std::bit_width(bpb->logical_sectors_per_cluster) - 1) ||
			(reserved_logical_sectors = bpb->reserved_logical_sectors) == 0 ||
			(fats = bpb->fats) == 0 ||
			static_cast<uint8_t>(bpb->media_descriptor) < 0xF8 &&
				bpb->media_descriptor != static_cast<std::byte>(0xF0) ||
			(total_logical_sectors = bpb->old_total_logical_sectors) == 0 &&
				(total_logical_sectors = bpb->total_logical_sectors) == 0 ||
			(logical_sectors_per_fat = bpb->logical_sectors_per_fat) == 0 &&
				(logical_sectors_per_fat = (fat32 = &bs->fat32)->logical_sectors_per_fat) == 0)))
	{
		std::clog << argv[1] << ": device does not contain a FAT or exFAT file system" << std::endl;
		return EX_DATAERR;
	}
	uint32_t data_start_lsn, total_data_clusters;
	const unsigned cluster_shift = logical_sectors_per_cluster_shift + bytes_per_logical_sector_shift;
	const uint32_t cluster_size = UINT32_C(1) << cluster_shift;
	unsigned active_fat = 0;
	const struct BootSector::EBPB *ebpb = nullptr;
	if (exfat) {
		if (exfat->version >> 8 != 1) {
			std::clog << argv[1] << ": device contains unsupported exFAT revision " << fat_version(exfat->version) << std::endl;
			return EX_DATAERR;
		}
		{
			size_t boot_region_size = size_t(12) << bytes_per_logical_sector_shift;
			const std::unique_ptr<std::byte[]> boot_region { new(std::align_val_t(page_size)) std::byte[boot_region_size] };
			fd.pread_fully(boot_region.get(), boot_region_size, 0);
			uint32_t checksum = exfat::checksum(uint32_t { }, boot_region.get(), boot_region.get() + offsetof(struct exfat::BootSector, volume_flags));
			checksum = exfat::checksum(checksum, boot_region.get() + offsetof(struct exfat::BootSector, bytes_per_logical_sector_shift), boot_region.get() + offsetof(struct exfat::BootSector, percent_in_use));
			checksum = exfat::checksum(checksum, boot_region.get() + offsetof(struct exfat::BootSector, reserved), boot_region.get() + boot_region_size - bytes_per_logical_sector);
			if (std::any_of(reinterpret_cast<le<uint32_t> *>(boot_region.get() + boot_region_size - bytes_per_logical_sector), reinterpret_cast<le<uint32_t> *>(boot_region.get() + boot_region_size), [checksum_le = htole(checksum)](le<uint32_t> word) noexcept {
				return word != checksum_le;
			})) {
				std::clog << argv[1] << ": exFAT main boot region checksum is incorrect" << std::endl;
				return EX_DATAERR;
			}
		}
		active_fat = +(exfat->volume_flags & exfat::VolumeFlags::ACTIVE_FAT) ? 1 : 0;
		data_start_lsn = exfat->data_start_lsn;
		total_data_clusters = exfat->total_data_clusters;
	}
	else {
		if (fat32) {
			if (fat32->version != uint16_t(0)) {
				std::clog << argv[1] << ": device contains unsupported FAT32 version " << fat_version(fat32->version) << std::endl;
				return EX_DATAERR;
			}
			if (fat32->mirroring_flags & 0x80) {
				active_fat = fat32->mirroring_flags & 0xF;
			}
			ebpb = &fat32->ebpb;
		}
		else {
			ebpb = &bs->fat.ebpb;
		}
		if (ebpb->extended_boot_signature != static_cast<std::byte>(0x29) &&
			ebpb->extended_boot_signature != static_cast<std::byte>(0x28))
		{
			ebpb = nullptr;
		}
		data_start_lsn = reserved_logical_sectors + fats * logical_sectors_per_fat + (bpb->root_dir_entries * 32 + bytes_per_logical_sector - 1 >> bytes_per_logical_sector_shift);
		total_data_clusters = static_cast<uint32_t>(total_logical_sectors - data_start_lsn >> logical_sectors_per_cluster_shift);
	}
	if (active_fat >= fats) {
		std::clog << argv[1] << ": active FAT #" << active_fat << " does not exist on a volume with " << fats << " FAT" << (fats == 1 ? "" : "s") << std::endl;
		return EX_DATAERR;
	}
	if (verbose_option) {
		if (exfat) {
			std::clog <<
					"exfat.jump_instruction = " << exfat->jump_instruction << "\n"
					"exfat.file_system_name = " << std::quoted(std::string_view { exfat->file_system_name, sizeof exfat->file_system_name }) << "\n"
					"exfat.hidden_sectors = " << +exfat->hidden_sectors << "\n"
					"exfat.total_logical_sectors = " << +exfat->total_logical_sectors <<
						" (" << byte_count(uintmax_t { exfat->total_logical_sectors } << bytes_per_logical_sector_shift) << ")\n"
					"exfat.reserved_logical_sectors = " << +exfat->reserved_logical_sectors <<
						" (" << byte_count(uintmax_t { exfat->reserved_logical_sectors } << bytes_per_logical_sector_shift) << ")\n"
					"exfat.logical_sectors_per_fat = " << +exfat->logical_sectors_per_fat <<
						" (" << byte_count(uintmax_t { exfat->logical_sectors_per_fat } << bytes_per_logical_sector_shift) << ")\n"
					"exfat.data_start_lsn = " << +exfat->data_start_lsn <<
						" (" << byte_count(uintmax_t { exfat->data_start_lsn } << bytes_per_logical_sector_shift) << ")\n"
					"exfat.total_data_clusters = " << +exfat->total_data_clusters <<
						" (" << byte_count(uintmax_t { exfat->total_data_clusters } << cluster_shift) << ")\n"
					"exfat.root_dir_start_cluster = " << +exfat->root_dir_start_cluster << "\n"
					"exfat.volume_id = " << std::hex << +exfat->volume_id << std::dec << "\n"
					"exfat.version = " << fat_version(exfat->version) << "\n"
					"exfat.volume_flags = " << exfat_volume_flags(exfat->volume_flags) << "\n"
					"exfat.bytes_per_logical_sector_shift = " << bytes_per_logical_sector_shift <<
						" (" << byte_count(bytes_per_logical_sector) << ")\n"
					"exfat.logical_sectors_per_cluster_shift = " << logical_sectors_per_cluster_shift <<
						" (" << byte_count(cluster_size) << ")\n"
					"exfat.fats = " << +exfat->fats << "\n"
					"exfat.physical_drive_number = " << +exfat->physical_drive_number << "\n"
					"exfat.percent_in_use = " << (exfat->percent_in_use == 0xFF ? std::hex : std::dec) << +exfat->percent_in_use << std::dec << "\n"
					"exfat.boot_sector_signature = " << exfat->boot_sector_signature << '\n';
		}
		else {
			std::clog <<
					"bs.jump_instruction = " << bs->jump_instruction << "\n"
					"bs.oem_name = " << std::quoted(std::string_view { bs->oem_name, sizeof bs->oem_name }) << "\n"
					"bpb.bytes_per_logical_sector = " << +bpb->bytes_per_logical_sector << "\n"
					"bpb.logical_sectors_per_cluster = " << +bpb->logical_sectors_per_cluster <<
						" (" << byte_count(bpb->logical_sectors_per_cluster << bytes_per_logical_sector_shift) << ")\n"
					"bpb.reserved_logical_sectors = " << +bpb->reserved_logical_sectors <<
						" (" << byte_count(bpb->reserved_logical_sectors << bytes_per_logical_sector_shift) << ")\n"
					"bpb.fats = " << +bpb->fats << "\n"
					"bpb.root_dir_entries = " << +bpb->root_dir_entries << "\n"
					"bpb.old_total_logical_sectors = " << +bpb->old_total_logical_sectors <<
						" (" << byte_count(bpb->old_total_logical_sectors << bytes_per_logical_sector_shift) << ")\n"
					"bpb.media_descriptor = " << bpb->media_descriptor << "\n"
					"bpb.logical_sectors_per_fat = " << +bpb->logical_sectors_per_fat <<
						" (" << byte_count(bpb->logical_sectors_per_fat << bytes_per_logical_sector_shift) << ")\n"
					"bpb.physical_sectors_per_track = " << +bpb->physical_sectors_per_track << "\n"
					"bpb.heads = " << +bpb->heads << '\n';
			if (bpb->old_total_logical_sectors == uint16_t(0)) {
				std::clog <<
						"bpb.hidden_sectors = " << +bpb->hidden_sectors << "\n"
						"bpb.total_logical_sectors = " << +bpb->total_logical_sectors <<
							" (" << byte_count(uintmax_t { bpb->total_logical_sectors } << bytes_per_logical_sector_shift) << ")\n";
			}
			if (fat32) {
				std::clog <<
						"fat32.logical_sectors_per_fat = " << +fat32->logical_sectors_per_fat <<
							" (" << byte_count(uintmax_t { fat32->logical_sectors_per_fat } << bytes_per_logical_sector_shift) << ")\n"
						"fat32.mirroring_flags = " << std::hex << +fat32->mirroring_flags << std::dec << "\n"
						"fat32.version = " << fat_version(fat32->version) << "\n"
						"fat32.root_dir_start_cluster = " << +fat32->root_dir_start_cluster << "\n"
						"fat32.fs_info_lsn = " << +fat32->fs_info_lsn << "\n"
						"fat32.boot_sector_backup_lsn = " << +fat32->boot_sector_backup_lsn << "\n"
						"fat32.reserved = " << fat32->reserved << '\n';
			}
			if (ebpb) {
				std::clog <<
						"ebpb.physical_drive_number = " << +ebpb->physical_drive_number << "\n"
						"ebpb.reserved = " << ebpb->reserved << "\n"
						"ebpb.extended_boot_signature = " << ebpb->extended_boot_signature << "\n"
						"ebpb.volume_id = " << std::hex << +ebpb->volume_id << std::dec << '\n';
				if (ebpb->extended_boot_signature == static_cast<std::byte>(0x29)) {
					std::clog <<
							"ebpb.volume_label = " << std::quoted(std::string_view { ebpb->volume_label, sizeof ebpb->volume_label }) << "\n"
							"ebpb.file_system_type = " << std::quoted(std::string_view { ebpb->file_system_type, sizeof ebpb->file_system_type }) << '\n';
				}
			}
			std::clog <<
					"bs.old_physical_drive_number = " << +bs->old_physical_drive_number << "\n"
					"bs.boot_sector_signature = " << bs->boot_sector_signature << "\n"
					"data_start_lsn = " << data_start_lsn << "\n"
					"total_data_clusters = " << total_data_clusters <<
						" (" << byte_count(uintmax_t { total_data_clusters } << cluster_shift) << ')';
		}
	}

	std::function<uint32_t (const void *fat, uint32_t cluster)> get_fat_entry;
	std::function<void (void *fat, uint32_t cluster, uint32_t next)> put_fat_entry;
	uint32_t expected_fat_id, bad_cluster, bitmap_first_cluster = 0;
	std::unique_ptr<std::byte[]> bitmap;
	size_t bitmap_size = 0;
	if (exfat) {
		get_fat_entry = [&bitmap](const void *fat, uint32_t cluster) noexcept -> uint32_t {
			if (cluster >= 2) {
				auto idx = cluster - 2;
				if ((bitmap[idx / 8] & std::byte { 1 } << idx % 8) == std::byte { }) {
					return 0; // cluster is free, irrespective of stale entry in FAT
				}
			}
			return static_cast<const le<uint32_t> *>(fat)[cluster];
		};
		put_fat_entry = [&bitmap](void *fat, uint32_t cluster, uint32_t next) {
			if (cluster >= 2) {
				auto idx = cluster - 2;
				if (next) {
					bitmap[idx / 8] |= std::byte { 1 } << idx % 8;
				}
				else {
					bitmap[idx / 8] &= ~(std::byte { 1 } << idx % 8);
				}
			}
			static_cast<le<uint32_t> *>(fat)[cluster] = next;
		};
		expected_fat_id = 0xFFFFFFF8;
		bad_cluster = 0xFFFFFFF7;
	}
	else {
		uint32_t min_fat_size;
		unsigned fat_entry_width;
		if (total_data_clusters < 4085) {
			get_fat_entry = [](const void *fat, uint32_t cluster) noexcept -> uint32_t {
				auto row = static_cast<const uint8_t *>(fat) + cluster / 2 * 3;
				if (cluster & 1) {
					return row[1] >> 4 | row[2] << 4;
				}
				else {
					return row[0] | (row[1] & 0xF) << 8;
				}
			};
			put_fat_entry = [](void *fat, uint32_t cluster, uint32_t next) {
				if (next > 0xFFF) {
					throw std::out_of_range("illegal cluster number");
				}
				auto row = static_cast<uint8_t *>(fat) + cluster / 2 * 3;
				if (cluster & 1) {
					row[1] = static_cast<uint8_t>(row[1] & 0xF | next << 4);
					row[2] = static_cast<uint8_t>(next >> 4);
				}
				else {
					row[0] = static_cast<uint8_t>(next);
					row[1] = static_cast<uint8_t>(row[1] & 0xF0 | next >> 8);
				}
			};
			expected_fat_id = 0xF00 | static_cast<uint8_t>(bpb->media_descriptor);
			bad_cluster = 0xFF7;
			min_fat_size = ((total_data_clusters + 2) * 3 + 1) / 2;
			fat_entry_width = 12;
		}
		else if (total_data_clusters < 65525) {
			get_fat_entry = [](const void *fat, uint32_t cluster) noexcept -> uint32_t {
				return static_cast<const le<uint16_t> *>(fat)[cluster];
			};
			put_fat_entry = [](void *fat, uint32_t cluster, uint32_t next) {
				if (next > 0xFFFF) {
					throw std::out_of_range("illegal cluster number");
				}
				static_cast<le<uint16_t> *>(fat)[cluster] = static_cast<uint16_t>(next);
			};
			expected_fat_id = 0xFF00 | static_cast<uint8_t>(bpb->media_descriptor);
			bad_cluster = 0xFFF7;
			min_fat_size = (total_data_clusters + 2) * sizeof(uint16_t);
			fat_entry_width = 16;
		}
		else {
			get_fat_entry = [](const void *fat, uint32_t cluster) noexcept -> uint32_t {
				return static_cast<const le<uint32_t> *>(fat)[cluster] & 0x0FFFFFFF;
			};
			put_fat_entry = [](void *fat, uint32_t cluster, uint32_t next) {
				if (next > 0x0FFFFFFF) {
					throw std::out_of_range("illegal cluster number");
				}
				auto &entry = static_cast<le<uint32_t> *>(fat)[cluster];
				entry = entry & ~0x0FFFFFFF | next;
			};
			expected_fat_id = 0x0FFFFF00 | static_cast<uint8_t>(bpb->media_descriptor);
			bad_cluster = 0x0FFFFFF7;
			min_fat_size = (total_data_clusters + 2) * sizeof(uint32_t);
			fat_entry_width = 32;
		}
		if (verbose_option) {
			std::clog << " [FAT" << fat_entry_width << "]\n";
		}
		if (logical_sectors_per_fat < min_fat_size + bytes_per_logical_sector - 1 >> bytes_per_logical_sector_shift) {
			std::clog << argv[1] << ": logical_sectors_per_fat=" << logical_sectors_per_fat << " is too small for total_data_clusters=" << total_data_clusters << std::endl;
			return EX_DATAERR;
		}
	}
	std::clog.flush();

	struct FSInfoSector *fs_info = nullptr;
	if (fat32 && fat32->fs_info_lsn != uint16_t(0) && fat32->fs_info_lsn != uint16_t(0xFFFF)) {
		fs_info = new(std::align_val_t(page_size)) struct FSInfoSector;
		fd.pread_fully(fs_info, sizeof *fs_info, fat32->fs_info_lsn << bytes_per_logical_sector_shift);
		if (std::memcmp(fs_info->fs_info_sector_signature1, "RRaA", 4) != 0 ||
			std::memcmp(fs_info->fs_info_sector_signature2, "rrAa", 4) != 0 ||
			std::memcmp(fs_info->fs_info_sector_signature3, "\0\0\x55\xAA", 4) != 0)
		{
			delete fs_info, fs_info = nullptr;
			std::clog << argv[1] << ": FS Information Sector is invalid\n";
		}
		else if (verbose_option) {
			std::clog << "fs_info.last_known_free_data_clusters = ";
			if (fs_info->last_known_free_data_clusters == 0xFFFFFFFF) {
				std::clog << std::hex << +fs_info->last_known_free_data_clusters << std::dec;
			}
			else {
				std::clog << +fs_info->last_known_free_data_clusters <<
						" (" << byte_count(uintmax_t { fs_info->last_known_free_data_clusters } << cluster_shift) << ')';
			}
			std::clog << "\n"
					"fs_info.most_recently_allocated_data_cluster = " << (fs_info->most_recently_allocated_data_cluster == 0xFFFFFFFF ? std::hex : std::dec) << +fs_info->most_recently_allocated_data_cluster << std::dec << '\n';
		}
	}
	std::clog.flush();

	const size_t fat_size = logical_sectors_per_fat << bytes_per_logical_sector_shift;
	auto const fat = new(std::align_val_t(page_size)) std::byte[fat_size];
	fd.pread_fully(fat, fat_size, (reserved_logical_sectors << bytes_per_logical_sector_shift) + active_fat * fat_size);
	if (auto entry = get_fat_entry(fat, 0); entry != expected_fat_id) {
		std::clog << argv[1] << ": FAT ID is " << std::hex << entry << " but should be " << expected_fat_id << std::dec << '\n';
	}
	if (exfat) {
		const size_t buffer_size = std::max<size_t>(page_size, cluster_size);
		exfat::ClusterChainIO input(fd, *exfat, reinterpret_cast<const le<uint32_t> *>(fat), exfat->root_dir_start_cluster);
		InputSource source(input);
		exfat::Directory root(source, make_aligned_buffer(page_size, buffer_size));
		while (auto entry = root.next_entry()) {
			switch (entry->generic.entry_type) {
				case exfat::ALLOC_BITMAP: {
					auto &ab = entry->alloc_bitmap;
					unsigned bitmap_id = +(ab.flags & exfat::BitmapFlags::BITMAP_ID) ? 1 : 0;
					if (verbose_option) {
						std::clog <<
								"alloc_bitmap[" << bitmap_id << "].first_cluster = " << +ab.first_cluster << "\n"
								"alloc_bitmap[" << bitmap_id << "].data_length = " << +ab.data_length <<
									" (" << byte_count(+ab.data_length) << ")\n";
					}
					auto const expected_size = (exfat->total_data_clusters + 7) / 8;
					if (+ab.data_length != expected_size) {
						std::clog << argv[1] << ": exFAT allocation bitmap has size " << +ab.data_length << " (" << byte_count(ab.data_length) << ") but should have size " << expected_size << " (" << byte_count(expected_size) << ") for total_data_clusters=" << +exfat->total_data_clusters << std::endl;
						return EX_DATAERR;
					}
					if (bitmap_id == active_fat) {
						bitmap_size = narrow_check<size_t>(expected_size + cluster_size - 1) & ~(cluster_size - 1);
						bitmap.reset(new(std::align_val_t(page_size)) std::byte[bitmap_size]);
						exfat::ClusterChainIO(fd, *exfat, reinterpret_cast<const le<uint32_t> *>(fat), bitmap_first_cluster = ab.first_cluster).read_fully(bitmap.get(), bitmap_size);
					}
					break;
				}
				case exfat::UPCASE_TABLE: {
					auto &ut = entry->upcase_table;
					if (verbose_option) {
						std::clog <<
								"upcase_table.table_checksum = " << std::hex << +ut.table_checksum << std::dec << "\n"
								"upcase_table.first_cluster = " << +ut.first_cluster << "\n"
								"upcase_table.data_length = " << +ut.data_length <<
									" (" << byte_count(+ut.data_length) << ")\n";
					}
					break;
				}
				case exfat::VOLUME_LABEL: {
					auto &vl = entry->volume_label;
					if (verbose_option) {
						std::clog <<
								"volume_label = " << std::quoted(to_string(std::u16string { vl.volume_label, vl.volume_label + vl.char_count })) << '\n';
					}
					break;
				}
				case exfat::VOLUME_GUID: {
					auto &vg = entry->volume_guid;
					if (verbose_option) {
						std::clog << "volume_guid = " << UUID { vg.volume_guid } << '\n';
					}
					break;
				}
				default:
					break;
			}
		}
		if (!bitmap) {
			std::clog << argv[1] << ": missing exFAT allocation bitmap" << std::endl;
			return EX_DATAERR;
		}
	}
	const uint32_t max_cluster = total_data_clusters + 1;
	uint32_t free_clusters = 0, bad_clusters = 0, used_clusters = 0;
	for (uint32_t cluster = 2; cluster <= max_cluster; ++cluster) {
		auto entry = get_fat_entry(fat, cluster);
		if (entry == 0) {
			++free_clusters;
		}
		else if (entry == bad_cluster) {
			++bad_clusters;
		}
		else {
			++used_clusters;
		}
	}
	if (verbose_option) {
		std::clog << "FAT contains:\n" <<
				std::setw(10) << used_clusters << " used cluster" << (used_clusters == 1 ? ' ' : 's') <<
					" (" << std::setw(8) << byte_count(uintmax_t { used_clusters } << cluster_shift) << ")\n" <<
				std::setw(10) << free_clusters << " free cluster" << (free_clusters == 1 ? ' ' : 's') <<
					" (" << std::setw(8) << byte_count(uintmax_t { free_clusters } << cluster_shift) << ")\n" <<
				std::setw(10) << bad_clusters << "  bad cluster" << (bad_clusters == 1 ? ' ' : 's') <<
					" (" << std::setw(8) << byte_count(uintmax_t { bad_clusters } << cluster_shift) << ")\n";
	}
	if (fs_info && fs_info->last_known_free_data_clusters != free_clusters && fs_info->last_known_free_data_clusters != 0xFFFFFFFF) {
		std::clog << argv[1] << ": FS Information Sector free cluster count is incorrect\n";
	}
	std::clog.flush();

	if (bad_clusters_option.value().empty() && free_clusters_option.value().empty()) {
		return EX_OK;
	}

	unsigned buf_size_shift = 26u; // 64 MiB
	{
		struct sysinfo info { };
		if (sysinfo(&info) == 0) {
			buf_size_shift = std::min(std::max(static_cast<unsigned>(std::bit_width(info.freeram - 1)) - 1, 23u /* 8 MiB */), buf_size_shift);
		}
	}
	uint32_t alignment_offset_clusters = 0;
	try {
		struct hd_geometry geo { };
		fd.ioctl(HDIO_GETGEO, &geo);
		uint32_t data_start_abs_offset = static_cast<uint32_t>((geo.start << 9) + (data_start_lsn << bytes_per_logical_sector_shift));
		if ((data_start_abs_offset & (UINT32_C(1) << cluster_shift) - 1) == 0) {
			alignment_offset_clusters = (-data_start_abs_offset & (UINT32_C(1) << buf_size_shift) - 1) >> cluster_shift;
		}
	}
	catch (const std::system_error &) {
		// swallow; don't align cluster I/O
	}

	uint32_t marked_bad = 0, marked_free = 0, zeroed_out = 0, discarded = 0, trashed = 0, misplaced = 0;
	auto const buf1 = new(std::align_val_t(page_size)) std::byte[size_t(1) << buf_size_shift];
	auto const buf2 = new(std::align_val_t(page_size)) std::byte[size_t(1) << buf_size_shift];
	for (uint32_t from_cluster = 2, to_cluster, error_end = 0, progress = 0;
		from_cluster <= max_cluster;
		from_cluster = to_cluster)
	{
		to_cluster = from_cluster + 1;
		const Actions *actions;
		auto const entry = get_fat_entry(fat, from_cluster);
		if (entry == 0) {
			actions = &free_clusters_option.value();
		}
		else if (entry == bad_cluster) {
			actions = &bad_clusters_option.value();
		}
		else {
			continue;
		}
		if (actions->empty()) {
			continue;
		}
		auto actions_itr = actions->begin();
restart_action:
		if (from_cluster >= error_end) {
			for (uint32_t max_to_cluster = static_cast<uint32_t>(std::min<uint64_t>(from_cluster + (UINT64_C(1) << buf_size_shift - cluster_shift), max_cluster + 1));
				to_cluster <= max_cluster && get_fat_entry(fat, to_cluster) == entry;)
			{
				if (++to_cluster > max_to_cluster) {
					to_cluster = (from_cluster + alignment_offset_clusters + (UINT32_C(1) << buf_size_shift - cluster_shift) & ~((UINT32_C(1) << buf_size_shift - cluster_shift) - 1)) - alignment_offset_clusters;
					break;
				}
			}
		}
		const uint32_t clusters = to_cluster - from_cluster;
		const size_t chunk_size = size_t { clusters } << cluster_shift;
		const off_t offset = data_start_lsn + (off_t { from_cluster - 2 } << logical_sectors_per_cluster_shift) << bytes_per_logical_sector_shift;
		auto const mark = [fat, &get_fat_entry, &put_fat_entry, &marked_bad, &marked_free, fs_info](const char message[], uint32_t cluster, off_t offset, uint32_t new_entry) {
			if (message) {
				std::clog << message << " cluster #" << cluster << " at offset " << std::hex << offset << std::dec << std::endl;
			}
			if (auto old_entry = get_fat_entry(fat, cluster); new_entry != old_entry) {
				put_fat_entry(fat, cluster, new_entry);
				if (!new_entry != !old_entry) {
					++(new_entry ? marked_bad : marked_free);
				}
			}
		};
		bool buf1_valid = false;
		for (; actions_itr != actions->end(); ++actions_itr) {
			switch (Action action = *actions_itr) {
				case Action::READ:
					try {
						fd.pread_fully(buf1, chunk_size, offset);
						buf1_valid = true;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						if (clusters > 1) {
							error_end = to_cluster, to_cluster = from_cluster + 1;
							goto restart_action;
						}
						mark("\rerror while reading", from_cluster, offset, bad_cluster);
						goto next_chunk;
					}
					break;
				case Action::READZEROS:
					std::memset(buf1, 0, chunk_size);
					buf1_valid = true;
					[[fallthrough]];
				case Action::REREAD:
					try {
						if (!buf1_valid) {
							fd.pread_fully(buf1, chunk_size, offset);
							buf1_valid = true;
						}
						fd.pread_fully(buf2, chunk_size, offset);
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						if (clusters > 1) {
							error_end = to_cluster, to_cluster = from_cluster + 1;
							goto restart_action;
						}
						mark("\rerror while reading", from_cluster, offset, bad_cluster);
						goto next_chunk;
					}
					for (uint32_t cluster = from_cluster, o = 0; cluster < to_cluster; ++cluster, o += cluster_size) {
						if (get_fat_entry(fat, cluster) != 1 && std::memcmp(buf1 + o, buf2 + o, cluster_size) != 0) {
							mark("\rflaky", cluster, offset + o, 1);
						}
					}
					break;
				case Action::ZEROOUT:
					if (!buf1_valid || std::any_of(buf1, buf1 + chunk_size, std::identity { })) {
						try {
							uint64_t span[2] = { static_cast<uint64_t>(offset), chunk_size };
							fd.ioctl(BLKZEROOUT, span);
							zeroed_out += clusters;
							std::memset(buf1, 0, chunk_size);
							buf1_valid = true;
						}
						catch (const std::system_error &e) {
							if (e.code().value() != EIO) {
								throw;
							}
							if (clusters > 1) {
								error_end = to_cluster, to_cluster = from_cluster + 1;
								goto restart_action;
							}
							mark("\rerror while zeroing", from_cluster, offset, bad_cluster);
							goto next_chunk;
						}
					}
					break;
				case Action::F3WRITE: {
					bool need_write = !buf1_valid;
					for (uint32_t o = 0; o < chunk_size; o += cluster_size) {
						need_write |= f3_fill(buf1 + o, cluster_size, offset + o);
					}
					if (need_write) {
						goto write_trash;
					}
					break;
				}
				case Action::F3READ:
					try {
						fd.pread_fully(buf1, chunk_size, offset);
						buf1_valid = true;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						if (clusters > 1) {
							error_end = to_cluster, to_cluster = from_cluster + 1;
							goto restart_action;
						}
						mark("\rerror while reading", from_cluster, offset, bad_cluster);
						goto next_chunk;
					}
					for (uint32_t cluster = from_cluster, o = 0; cluster < to_cluster; ++cluster, o += cluster_size) {
						if (get_fat_entry(fat, cluster) != 1 && (f3_fill(buf2 + o, cluster_size, offset + o), std::memcmp(buf1 + o, buf2 + o, cluster_size) != 0)) {
							if (count_flipped_bits(buf1 + o, buf2 + o, cluster_size) > cluster_size) {
								if (off_t found_offset = static_cast<off_t>(*reinterpret_cast<le<uint64_t> *>(buf1 + o));
									found_offset != offset + o && (f3_fill(buf2 + o, cluster_size, found_offset), std::memcmp(buf1 + o, buf2 + o, cluster_size) == 0))
								{
									++misplaced;
									std::clog << "\rdata intended for offset " << std::hex << found_offset << std::dec << " were found in";
								}
								else {
									std::clog << "\rcorrupted";
								}
								std::clog << " cluster #" << cluster << " at offset " << std::hex << offset + o << std::dec << std::endl;
							}
							else {
								mark("\rflaky", cluster, offset + o, 1);
							}
						}
					}
					break;
				case Action::SECDISCARD:
				case Action::DISCARD:
					try {
						uint64_t span[2] = { static_cast<uint64_t>(offset), chunk_size };
						fd.ioctl(action == Action::SECDISCARD ? BLKSECDISCARD : BLKDISCARD, span);
						discarded += clusters;
						buf1_valid = false;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						if (clusters > 1) {
							error_end = to_cluster, to_cluster = from_cluster + 1;
							goto restart_action;
						}
						mark("\rerror while discarding", from_cluster, offset, bad_cluster);
						goto next_chunk;
					}
					break;
				case Action::TRASH:
					getrandom_fully(buf1, chunk_size);
write_trash:
					try {
						fd.pwrite_fully(buf1, chunk_size, offset);
						trashed += clusters;
						buf1_valid = true;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						if (clusters > 1) {
							error_end = to_cluster, to_cluster = from_cluster + 1;
							goto restart_action;
						}
						mark("\rerror while writing", from_cluster, offset, bad_cluster);
						goto next_chunk;
					}
					break;
				case Action::BAD:
					for (uint32_t cluster = from_cluster, o = 0; cluster < to_cluster; ++cluster, o += cluster_size) {
						mark(nullptr, cluster, offset + o, bad_cluster);
					}
					goto next_chunk;
				case Action::FREE:
					for (uint32_t cluster = from_cluster, o = 0; cluster < to_cluster; ++cluster, o += cluster_size) {
						mark(nullptr, cluster, offset + o, 0);
					}
					break;
				case Action::LIST:
					for (uint32_t cluster = from_cluster; cluster < to_cluster; ++cluster) {
						std::cout << cluster << '\n';
					}
					break;
			}
		}
next_chunk:
		if (auto old_progress = progress; (progress += to_cluster - from_cluster) / 1024 != old_progress / 1024) {
			uint32_t total = free_clusters + bad_clusters;
			std::clog.put('\r') << static_cast<unsigned>((uint64_t { progress } * 100 + total / 2) / total) << '%' << std::flush;
		}
	}
	std::cout << std::flush;
	std::clog << "\r\033[K";
	if ((marked_bad || marked_free) && !dry_run_option) {
		for (uint32_t cluster = 2; cluster <= max_cluster; ++cluster) {
			if (get_fat_entry(fat, cluster) == 1) {
				put_fat_entry(fat, cluster, bad_cluster);
			}
		}
		std::clog << "writing modified FAT";
		if (exfat) {
			std::clog << " and allocation bitmap... " << std::flush;
			auto saved_volume_flags = exfat->volume_flags;
			static_assert(std::is_same_v<decltype(saved_volume_flags), le<exfat::VolumeFlags>>);
			if ((exfat->volume_flags & (exfat::VolumeFlags::VOLUME_DIRTY | exfat::VolumeFlags::CLEAR_TO_ZERO)) != exfat::VolumeFlags::VOLUME_DIRTY) {
				exfat->volume_flags &= ~exfat::VolumeFlags::CLEAR_TO_ZERO;
				saved_volume_flags = exfat->volume_flags;
				exfat->volume_flags |= exfat::VolumeFlags::VOLUME_DIRTY;
				fd.pwrite_fully(exfat, sizeof *exfat, 0);
			}
			fd.pwrite_fully(fat, fat_size, (reserved_logical_sectors << bytes_per_logical_sector_shift) + active_fat * fat_size);
			exfat::ClusterChainIO(fd, *exfat, reinterpret_cast<const le<uint32_t> *>(fat), bitmap_first_cluster).write_fully(bitmap.get(), bitmap_size);
			if (auto percent_in_use = static_cast<unsigned>((total_data_clusters - (free_clusters - marked_bad + marked_free)) * UINT64_C(100) / total_data_clusters);
				!(saved_volume_flags & exfat::VolumeFlags::VOLUME_DIRTY) ||
				exfat->percent_in_use != percent_in_use)
			{
				exfat->volume_flags = saved_volume_flags;
				exfat->percent_in_use = static_cast<uint8_t>(percent_in_use);
				fd.pwrite_fully(exfat, sizeof *exfat, 0);
			}
		}
		else {
			std::clog << (fats == 1 ? "" : "s") << "... " << std::flush;
			for (unsigned fat_idx = 0; fat_idx < fats; ++fat_idx) {
				fd.pwrite_fully(fat, fat_size, (reserved_logical_sectors << bytes_per_logical_sector_shift) + fat_idx * fat_size);
			}
			if (fs_info && marked_bad != marked_free) {
				fs_info->last_known_free_data_clusters = free_clusters - marked_bad + marked_free;
				fd.pwrite_fully(fs_info, sizeof *fs_info, fat32->fs_info_lsn << bytes_per_logical_sector_shift);
			}
		}
		std::clog << "done." << std::endl;
	}
	if (marked_bad || verbose_option) {
		std::clog << marked_bad << " cluster" << (marked_bad == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { marked_bad } << cluster_shift) << ')' <<
				(dry_run_option ? " would have been" : "") << " marked bad\n";
	}
	if (marked_free || verbose_option) {
		std::clog << marked_free << " cluster" << (marked_free == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { marked_free } << cluster_shift) << ')' <<
				(dry_run_option ? " would have been" : "") << " marked free\n";
	}
	if (zeroed_out || verbose_option) {
		std::clog << zeroed_out << " cluster" << (zeroed_out == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { zeroed_out } << cluster_shift) << ')' <<
				(dry_run_option ? " would have been" : "") << " zeroed out\n";
	}
	if (discarded || verbose_option) {
		std::clog << discarded << " cluster" << (discarded == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { discarded } << cluster_shift) << ')' <<
				(dry_run_option ? " would have been" : "") << " discarded\n";
	}
	if (trashed || verbose_option) {
		std::clog << trashed << " cluster" << (trashed == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { trashed } << cluster_shift) << ')' <<
				(dry_run_option ? " would have been" : "") << " trashed\n";
	}
	if (misplaced) {
		std::clog << misplaced << " cluster" << (misplaced == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { misplaced } << cluster_shift) << ") "
				"contained data intended for other clusters. This\n"
				"may indicate that your flash media is fraudulent. For more information, see\n"
				"https://github.com/AltraMayor/f3." << std::endl;
		return 2;
	}
	std::clog.flush();
	return !!marked_bad;
}
