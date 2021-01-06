#include <cmath>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>

#include <sysexits.h>
#include <linux/fs.h>
#include <sys/random.h>

#include "common/cli.h"
#include "common/endian.h"
#include "common/fd.h"
#include "common/format.h"


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
	std::byte jump_instruction[3];
	char oem_name[8];
	le_packed<uint16_t> bytes_per_logical_sector;
	uint8_t logical_sectors_per_cluster;
	le_packed<uint16_t> reserved_logical_sectors;
	uint8_t fats;
	le_packed<uint16_t> root_dir_entries;
	le_packed<uint16_t> old_total_logical_sectors;
	std::byte media_descriptor;
	le_packed<uint16_t> logical_sectors_per_fat;
	le_packed<uint16_t> physical_sectors_per_track;
	le_packed<uint16_t> heads;
	le_packed<uint32_t> hidden_sectors;
	le_packed<uint32_t> total_logical_sectors;
	std::byte padding[0x1FD - 0x024];
	uint8_t old_physical_drive_number;
	std::byte boot_sector_signature[2]; // 0x55, 0xAA
};
static_assert(sizeof(BootSector) == 512);

struct FAT32Params {
	le_packed<uint32_t> logical_sectors_per_fat;
	le_packed<uint16_t> mirroring_flags;
	le_packed<uint16_t> version;
	le_packed<uint32_t> root_dir_start_cluster;
	le_packed<uint16_t> fs_info_lsn;
	le_packed<uint16_t> boot_sector_backup_lsn;
	std::byte reserved[12];
};
static_assert(sizeof(FAT32Params) == 28);

struct EBPB {
	uint8_t physical_drive_number;
	std::byte reserved;
	std::byte extended_boot_signature;
	le_packed<uint32_t> volume_id;
	char volume_label[11];
	char file_system_type[8];
};
static_assert(sizeof(EBPB) == 26);

struct FSInfoSector {
	std::byte fs_info_sector_signature1[4]; // "RRaA"
	std::byte reserved1[480];
	std::byte fs_info_sector_signature2[4]; // "rrAa"
	le_packed<uint32_t> last_known_free_data_clusters;
	le_packed<uint32_t> most_recently_allocated_data_cluster;
	std::byte reserved2[12];
	std::byte fs_info_sector_signature3[4]; // 0x00, 0x00, 0x55, 0xAA
};
static_assert(sizeof(FSInfoSector) == 512);


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

static void getrandom_fully(void *buf, size_t buflen, unsigned flags = 0) {
	for (ssize_t r; (r = ::getrandom(buf, buflen, flags)) >= 0;) {
		if ((buflen -= r) == 0) {
			return;
		}
		buf = static_cast<std::byte *>(buf) + r;
	}
	throw std::system_error(errno, std::system_category(), "getrandom");
}

enum class Action {
	READ, REREAD, ZEROOUT, SECDISCARD, DISCARD, TRASH, BAD, FREE
};

static Action parse_action(std::string_view sv) {
	if (sv == "read") {
		return Action::READ;
	}
	if (sv == "reread") {
		return Action::REREAD;
	}
	if (sv == "zeroout") {
		return Action::ZEROOUT;
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
};

int main(int argc, char *argv[]) {
	std::ios_base::sync_with_stdio(false);
	std::clog << std::showbase << std::internal;
	cli::Option<Actions>
			bad_clusters_option { "bad-clusters", 'b' },
			free_clusters_option { "free-clusters", 'f' };
	cli::Option<>
			verbose_option { "verbose", 'v' },
			help_option { "help" };
	bad_clusters_option.args.emplace_back();
	free_clusters_option.args.emplace_back(Actions { Action::READ, Action::REREAD });
	if ((argc = cli::parse(argc, argv, { &bad_clusters_option, &free_clusters_option, &verbose_option, &help_option })) < 2 || help_option) {
		std::clog << "usage: " << argv[0] << " [options] <block-device>\n"
				"\n"
				"options:\n"
				"\t-b,--bad-clusters=[<action>,...]\n"
				"\t-f,--free-clusters=[<action>,...]\n"
				"\t-v,--verbose\n"
				"\n"
				"actions:\n"
				"\tread: read cluster; mark bad if device errors\n"
				"\treread: re-read cluster; mark bad if different\n"
				"\tzeroout: issue BLKZEROOUT ioctl on cluster\n"
				"\t         (elided if a previous \"read\" found cluster already zeroed)\n"
				"\tsecdiscard: issue BLKSECDISCARD ioctl on cluster\n"
				"\tdiscard: issue BLKDISCARD ioctl on cluster\n"
				"\ttrash: fill cluster with pseudorandom garbage\n"
				"\tbad: mark cluster as bad unconditionally\n"
				"\tfree: mark cluster as free unconditionally\n"
				"\n"
				"defaults:\n"
				"\t--bad-clusters=\n"
				"\t--free-clusters=read,reread\n";
		return EX_USAGE;
	}
	auto const page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size < 0) {
		throw std::system_error(errno, std::system_category(), "sysconf(_SC_PAGE_SIZE)");
	}

	FileDescriptor fd(argv[1], O_RDWR | O_EXCL | O_DIRECT | O_CLOEXEC);

	auto const bs = new(std::align_val_t(page_size)) struct BootSector;
	fd.pread_fully(bs, sizeof *bs, 0);
	uint32_t total_logical_sectors, logical_sectors_per_fat;
	const struct FAT32Params *fat32 = nullptr;
	if (bs->boot_sector_signature[0] != static_cast<std::byte>(0x55) ||
		bs->boot_sector_signature[1] != static_cast<std::byte>(0xAA) ||
		std::memcmp(bs->oem_name, "EXFAT   ", 8) == 0 ||
		std::memcmp(bs->oem_name, "NTFS    ", 8) == 0 ||
		!std::has_single_bit(letoh(bs->bytes_per_logical_sector)) ||
		!std::has_single_bit(bs->logical_sectors_per_cluster) ||
		bs->reserved_logical_sectors == uint16_t(0) ||
		bs->fats == 0 ||
		static_cast<uint8_t>(bs->media_descriptor) < 0xF8 &&
			bs->media_descriptor != static_cast<std::byte>(0xF0) ||
		(total_logical_sectors = bs->old_total_logical_sectors) == 0 &&
			(total_logical_sectors = bs->total_logical_sectors) == 0 ||
		(logical_sectors_per_fat = bs->logical_sectors_per_fat) == 0 &&
			(logical_sectors_per_fat = (fat32 = reinterpret_cast<const FAT32Params *>(bs->padding))->logical_sectors_per_fat) == 0)
	{
		std::clog << argv[1] << ": device does not contain a FAT file system" << std::endl;
		return EX_DATAERR;
	}
	if (fat32 && fat32->version != uint16_t(0)) {
		std::clog << argv[1] << ": device contains unsupported FAT32 version " << (fat32->version >> 8) << '.' << (fat32->version & 0xFF) << std::endl;
		return EX_DATAERR;
	}
	unsigned active_fat = 0;
	if (fat32 && (fat32->mirroring_flags & 0x80) && (active_fat = fat32->mirroring_flags & 0xF) >= bs->fats) {
		std::clog << argv[1] << ": active FAT #" << active_fat << " does not exist on a volume with " << +bs->fats << " FAT" << (bs->fats == 1 ? "" : "s") << std::endl;
		return EX_DATAERR;
	}
	auto ebpb = reinterpret_cast<const struct EBPB *>(bs->padding + (fat32 ? sizeof *fat32 : 0));
	if (ebpb->extended_boot_signature != static_cast<std::byte>(0x29) &&
		ebpb->extended_boot_signature != static_cast<std::byte>(0x28))
	{
		ebpb = nullptr;
	}
	if (verbose_option) {
		std::clog <<
				"bs.jump_instruction = " << bs->jump_instruction << "\n"
				"bs.oem_name = " << std::quoted(std::string_view { bs->oem_name, sizeof bs->oem_name }) << "\n"
				"bs.bytes_per_logical_sector = " << +bs->bytes_per_logical_sector << "\n"
				"bs.logical_sectors_per_cluster = " << +bs->logical_sectors_per_cluster <<
					" (" << byte_count(bs->logical_sectors_per_cluster * bs->bytes_per_logical_sector) << ")\n"
				"bs.reserved_logical_sectors = " << +bs->reserved_logical_sectors <<
					" (" << byte_count(bs->reserved_logical_sectors * bs->bytes_per_logical_sector) << ")\n"
				"bs.fats = " << +bs->fats << "\n"
				"bs.root_dir_entries = " << +bs->root_dir_entries << "\n"
				"bs.old_total_logical_sectors = " << +bs->old_total_logical_sectors <<
					" (" << byte_count(bs->old_total_logical_sectors * bs->bytes_per_logical_sector) << ")\n"
				"bs.media_descriptor = " << bs->media_descriptor << "\n"
				"bs.logical_sectors_per_fat = " << +bs->logical_sectors_per_fat <<
					" (" << byte_count(bs->logical_sectors_per_fat * bs->bytes_per_logical_sector) << ")\n"
				"bs.physical_sectors_per_track = " << +bs->physical_sectors_per_track << "\n"
				"bs.heads = " << +bs->heads << '\n';
		if (bs->old_total_logical_sectors == uint16_t(0)) {
			std::clog <<
					"bs.hidden_sectors = " << +bs->hidden_sectors << "\n"
					"bs.total_logical_sectors = " << +bs->total_logical_sectors <<
						" (" << byte_count(uintmax_t { bs->total_logical_sectors } * bs->bytes_per_logical_sector) << ")\n";
		}
		if (fat32) {
			std::clog <<
					"fat32.logical_sectors_per_fat = " << +fat32->logical_sectors_per_fat <<
						" (" << byte_count(uintmax_t { fat32->logical_sectors_per_fat } * bs->bytes_per_logical_sector) << ")\n"
					"fat32.mirroring_flags = " << std::hex << +fat32->mirroring_flags << std::dec << "\n"
					"fat32.version = " << (fat32->version >> 8) << '.' << (fat32->version & 0xFF) << "\n"
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
				"bs.boot_sector_signature = " << bs->boot_sector_signature << '\n';
	}

	const uint32_t data_start_lsn = bs->reserved_logical_sectors + bs->fats * logical_sectors_per_fat + (bs->root_dir_entries * 32 + bs->bytes_per_logical_sector - 1) / bs->bytes_per_logical_sector;
	const uint32_t total_data_clusters = (total_logical_sectors - data_start_lsn) / bs->logical_sectors_per_cluster;
	uint32_t (*get_fat_entry)(const void *fat, uint32_t cluster) noexcept;
	void (*put_fat_entry)(void *fat, uint32_t cluster, uint32_t next);
	uint32_t fat_entry_width, expected_fat_id, bad_cluster, min_fat_size;
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
		fat_entry_width = 12;
		expected_fat_id = 0xF00 | static_cast<uint8_t>(bs->media_descriptor);
		bad_cluster = 0xFF7;
		min_fat_size = ((total_data_clusters + 2) * 3 + 1) / 2;
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
		fat_entry_width = 16;
		expected_fat_id = 0xFF00 | static_cast<uint8_t>(bs->media_descriptor);
		bad_cluster = 0xFFF7;
		min_fat_size = (total_data_clusters + 2) * sizeof(uint16_t);
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
		fat_entry_width = 32;
		expected_fat_id = 0x0FFFFF00 | static_cast<uint8_t>(bs->media_descriptor);
		bad_cluster = 0x0FFFFFF7;
		min_fat_size = (total_data_clusters + 2) * sizeof(uint32_t);
	}
	if (logical_sectors_per_fat < (min_fat_size + bs->bytes_per_logical_sector - 1) / bs->bytes_per_logical_sector) {
		std::clog << argv[1] << ": logical_sectors_per_fat=" << logical_sectors_per_fat << " is too small for total_data_clusters=" << total_data_clusters << std::endl;
		return EX_DATAERR;
	}
	const size_t cluster_size = bs->logical_sectors_per_cluster * bs->bytes_per_logical_sector;
	if (verbose_option) {
		std::clog <<
				"data_start_lsn = " << data_start_lsn << "\n"
				"total_data_clusters = " << total_data_clusters <<
					" (" << byte_count(uintmax_t { total_data_clusters } * cluster_size) << ")"
					" [FAT" << fat_entry_width << "]\n";
	}
	std::clog.flush();

	FSInfoSector *fs_info = nullptr;
	if (fat32 && fat32->fs_info_lsn != uint16_t(0) && fat32->fs_info_lsn != uint16_t(0xFFFF)) {
		fs_info = new(std::align_val_t(page_size)) struct FSInfoSector;
		fd.pread_fully(fs_info, sizeof *fs_info, fat32->fs_info_lsn * bs->bytes_per_logical_sector);
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
						" (" << byte_count(uintmax_t { fs_info->last_known_free_data_clusters } * cluster_size) << ')';
			}
			std::clog << "\n"
					"fs_info.most_recently_allocated_data_cluster = " << (fs_info->most_recently_allocated_data_cluster == 0xFFFFFFFF ? std::hex : std::dec) << +fs_info->most_recently_allocated_data_cluster << std::dec << '\n';
		}
	}
	std::clog.flush();

	const size_t fat_size = logical_sectors_per_fat * bs->bytes_per_logical_sector;
	auto const fat = new(std::align_val_t(page_size)) std::byte[fat_size];
	fd.pread_fully(fat, fat_size, bs->reserved_logical_sectors * bs->bytes_per_logical_sector + active_fat * fat_size);
	if (auto entry = get_fat_entry(fat, 0); entry != expected_fat_id) {
		std::clog << argv[1] << ": FAT ID is " << std::hex << entry << " but should be " << expected_fat_id << std::dec << '\n';
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
					" (" << std::setw(8) << byte_count(uintmax_t { used_clusters } * cluster_size) << ")\n" <<
				std::setw(10) << free_clusters << " free cluster" << (free_clusters == 1 ? ' ' : 's') <<
					" (" << std::setw(8) << byte_count(uintmax_t { free_clusters } * cluster_size) << ")\n" <<
				std::setw(10) << bad_clusters << "  bad cluster" << (bad_clusters == 1 ? ' ' : 's') <<
					" (" << std::setw(8) << byte_count(uintmax_t { bad_clusters } * cluster_size) << ")\n";
	}
	if (fs_info && fs_info->last_known_free_data_clusters != free_clusters && fs_info->last_known_free_data_clusters != 0xFFFFFFFF) {
		std::clog << argv[1] << ": FS Information Sector free cluster count is incorrect\n";
	}
	std::clog.flush();

	if (bad_clusters_option.value().empty() && free_clusters_option.value().empty()) {
		return EX_OK;
	}

	uint32_t marked_bad = 0, marked_free = 0, zeroed_out = 0, discarded = 0, trashed = 0;
	auto const buf1 = new(std::align_val_t(page_size)) std::byte[cluster_size];
	auto const buf2 = new(std::align_val_t(page_size)) std::byte[cluster_size];
	for (uint32_t cluster = 2, progress = 0; cluster <= max_cluster; ++cluster) {
		const Actions *actions;
		auto const entry = get_fat_entry(fat, cluster);
		if (entry == 0) {
			actions = &free_clusters_option.value();
		}
		else if (entry == bad_cluster) {
			actions = &bad_clusters_option.value();
		}
		else {
			continue;
		}
		if (++progress % 1024 == 0) {
			std::clog.put('\r') << static_cast<unsigned>(std::round(static_cast<double>(progress) / (free_clusters + bad_clusters) * 100)) << '%' << std::flush;
		}
		const off_t offset = (data_start_lsn + off_t { cluster - 2 } * bs->logical_sectors_per_cluster) * bs->bytes_per_logical_sector;
		bool buf1_valid = false;
		auto new_entry = entry;
		for (Action action : *actions) {
			switch (action) {
				case Action::READ:
					try {
						fd.pread_fully(buf1, cluster_size, offset);
						buf1_valid = true;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						std::clog << "\rerror while reading";
						goto error;
					}
					break;
				case Action::REREAD:
					try {
						if (!buf1_valid) {
							fd.pread_fully(buf1, cluster_size, offset);
							buf1_valid = true;
						}
						fd.pread_fully(buf2, cluster_size, offset);
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						std::clog << "\rerror while reading";
						goto error;
					}
					if (std::memcmp(buf1, buf2, cluster_size) != 0) {
						std::clog << "\rflaky";
						goto error;
					}
					break;
				case Action::ZEROOUT:
					if (!buf1_valid || std::any_of(buf1, buf1 + cluster_size, std::identity { })) {
						try {
							uint64_t span[2] = { static_cast<uint64_t>(offset), cluster_size };
							fd.ioctl(BLKZEROOUT, span);
							++zeroed_out;
							std::memset(buf1, 0, cluster_size);
							buf1_valid = true;
						}
						catch (const std::system_error &e) {
							if (e.code().value() != EIO) {
								throw;
							}
							std::clog << "\rerror while zeroing";
							goto error;
						}
					}
					break;
				case Action::SECDISCARD:
				case Action::DISCARD:
					try {
						uint64_t span[2] = { static_cast<uint64_t>(offset), cluster_size };
						fd.ioctl(action == Action::SECDISCARD ? BLKSECDISCARD : BLKDISCARD, span);
						++discarded;
						buf1_valid = false;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						std::clog << "\rerror while discarding";
						goto error;
					}
					break;
				case Action::TRASH:
					getrandom_fully(buf1, cluster_size);
					try {
						fd.pwrite_fully(buf1, cluster_size, offset);
						++trashed;
						buf1_valid = true;
					}
					catch (const std::system_error &e) {
						if (e.code().value() != EIO) {
							throw;
						}
						std::clog << "\rerror while writing";
						goto error;
					}
					break;
				case Action::BAD:
					new_entry = bad_cluster;
					break;
				case Action::FREE:
					new_entry = 0;
					break;
			}
		}
		if (new_entry == entry) {
			continue;
error:
			new_entry = bad_cluster;
		}
		else {
			std::clog << (new_entry ? "marking bad" : "marking free");
		}
		std::clog << " cluster #" << cluster << " at offset " << std::hex << offset << std::dec << std::endl;
		if (new_entry != entry) {
			put_fat_entry(fat, cluster, new_entry);
			++(new_entry ? marked_bad : marked_free);
			if (fs_info) {
				fs_info->most_recently_allocated_data_cluster = cluster;
			}
		}
	}
	std::clog << "\r\033[K";
	if (marked_bad || marked_free) {
		std::clog << "writing modified FAT" << (bs->fats == 1 ? "" : "s") << "... " << std::flush;
		for (unsigned fat_idx = 0; fat_idx < bs->fats; ++fat_idx) {
			fd.pwrite_fully(fat, fat_size, bs->reserved_logical_sectors * bs->bytes_per_logical_sector + fat_idx * fat_size);
		}
		if (fs_info && marked_bad != marked_free) {
			fs_info->last_known_free_data_clusters = free_clusters - marked_bad + marked_free;
			fd.pwrite_fully(fs_info, sizeof *fs_info, fat32->fs_info_lsn * bs->bytes_per_logical_sector);
		}
		std::clog << "done." << std::endl;
	}
	if (marked_bad || verbose_option) {
		std::clog << marked_bad << " cluster" << (marked_bad == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { marked_bad } * cluster_size) << ") marked bad\n";
	}
	if (marked_free || verbose_option) {
		std::clog << marked_free << " cluster" << (marked_free == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { marked_free } * cluster_size) << ") marked free\n";
	}
	if (zeroed_out || verbose_option) {
		std::clog << zeroed_out << " cluster" << (zeroed_out == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { zeroed_out } * cluster_size) << ") zeroed out\n";
	}
	if (discarded || verbose_option) {
		std::clog << discarded << " cluster" << (discarded == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { discarded } * cluster_size) << ") discarded\n";
	}
	if (trashed || verbose_option) {
		std::clog << trashed << " cluster" << (trashed == 1 ? "" : "s") <<
				" (" << byte_count(uintmax_t { trashed } * cluster_size) << ") trashed\n";
	}
	std::clog.flush();
	return !!marked_bad;
}
