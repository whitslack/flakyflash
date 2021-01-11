#include "exfat.h"

#include <stdexcept>


namespace exfat {


void timestamp_to_tm(struct tm &tm, Timestamp timestamp) noexcept {
	tm.tm_sec = ((timestamp >> DOUBLE_SECONDS_SHIFT) & (1u << DOUBLE_SECONDS_WIDTH) - 1) * 2;
	tm.tm_min = (timestamp >> MINUTE_SHIFT) & (1u << MINUTE_WIDTH) - 1;
	tm.tm_hour = (timestamp >> HOUR_SHIFT) & (1u << HOUR_WIDTH) - 1;
	tm.tm_mday = (timestamp >> DAY_SHIFT) & (1u << DAY_WIDTH) - 1;
	tm.tm_mon = ((timestamp >> MONTH_SHIFT) & (1u << MONTH_WIDTH) - 1) - 1;
	tm.tm_year = ((timestamp >> YEAR_SHIFT) & (1u << YEAR_WIDTH) - 1) + 80;
	tm.tm_wday = -1;
	tm.tm_yday = -1;
	tm.tm_isdst = -1;
}

Timestamp timestamp_from_tm(const struct tm &tm) noexcept {
	return Timestamp {
		(static_cast<unsigned>(tm.tm_sec) / 2 & (1u << DOUBLE_SECONDS_WIDTH) - 1) << DOUBLE_SECONDS_SHIFT |
		(static_cast<unsigned>(tm.tm_min) & (1u << MINUTE_WIDTH) - 1) << MINUTE_SHIFT |
		(static_cast<unsigned>(tm.tm_hour) & (1u << HOUR_WIDTH) - 1) << HOUR_SHIFT |
		(static_cast<unsigned>(tm.tm_mday) & (1u << DAY_WIDTH) - 1) << DAY_SHIFT |
		(static_cast<unsigned>(tm.tm_mon) + 1 & (1u << MONTH_WIDTH) - 1) << MONTH_SHIFT |
		(static_cast<unsigned>(tm.tm_year) - 80 & (1u << YEAR_WIDTH) - 1) << YEAR_SHIFT
	};
}


ClusterChainIO::ClusterChainIO(FileDescriptor &dev_fd, const struct BootSector &bs, const le<uint32_t> *fat, uint32_t starting_cluster, uint64_t starting_position) :
	dev_fd(dev_fd), bs(bs), fat(fat), cluster(starting_cluster)
{
	const uint32_t cluster_size = UINT32_C(1) << bs.logical_sectors_per_cluster_shift + bs.bytes_per_logical_sector_shift;
	const uint32_t max_cluster = bs.total_data_clusters + 1;
	while (starting_position > cluster_size) {
		if (_unlikely((cluster = fat[cluster]) > max_cluster || cluster < 2)) {
			throw std::underflow_error(cluster == 0 ? "premature end of cluster chain" : "FAT references invalid cluster");
		}
		starting_position -= cluster_size;
	}
	cluster_position = static_cast<uint32_t>(starting_position);
}

_nodiscard ssize_t ClusterChainIO::read(void *buf, size_t n) {
	if (_unlikely(n == 0)) {
		return 0;
	}
	ssize_t ret = 0;
	const uint32_t cluster_size = UINT32_C(1) << bs.logical_sectors_per_cluster_shift + bs.bytes_per_logical_sector_shift;
	const uint32_t max_cluster = bs.total_data_clusters + 1;
	uint32_t cluster_remain = cluster_size - cluster_position;
	do {
		if (cluster_remain == 0) {
			uint32_t next_cluster = fat[cluster];
			if (_unlikely(next_cluster < 2 || next_cluster > max_cluster)) {
				if (!~next_cluster) { // end of cluster chain
					return ret ?: -1;
				}
				throw std::underflow_error("FAT references invalid cluster");
			}
			cluster = next_cluster, cluster_position = 0, cluster_remain = cluster_size;
		}
		ssize_t r = dev_fd.pread(buf, std::min<size_t>(n, cluster_remain), (bs.data_start_lsn + (uint64_t { cluster - 2 } << bs.logical_sectors_per_cluster_shift) << bs.bytes_per_logical_sector_shift) + cluster_position);
		if (_unlikely(r <= 0)) {
			if (r == 0) {
				break;
			}
			throw std::underflow_error("read past end of device");
		}
		buf = static_cast<std::byte *>(buf) + r, n -= r;
		cluster_position += static_cast<uint32_t>(r), cluster_remain -= static_cast<uint32_t>(r);
		ret += r;
	} while (n > 0);
	return ret;
}

_nodiscard size_t ClusterChainIO::write(const void *buf, size_t n) {
	if (_unlikely(n == 0)) {
		return 0;
	}
	size_t ret = 0;
	const uint32_t cluster_size = UINT32_C(1) << bs.logical_sectors_per_cluster_shift + bs.bytes_per_logical_sector_shift;
	const uint32_t max_cluster = bs.total_data_clusters + 1;
	uint32_t cluster_remain = cluster_size - cluster_position;
	do {
		if (cluster_remain == 0) {
			uint32_t next_cluster = fat[cluster];
			if (_unlikely(next_cluster < 2 || next_cluster > max_cluster)) {
				if (!~next_cluster) { // end of cluster chain
					return ret;
				}
				throw std::underflow_error("FAT references invalid cluster");
			}
			cluster = next_cluster, cluster_position = 0, cluster_remain = cluster_size;
		}
		size_t w = dev_fd.pwrite(buf, std::min<size_t>(n, cluster_remain), (bs.data_start_lsn + (uint64_t { cluster - 2 } << bs.logical_sectors_per_cluster_shift) << bs.bytes_per_logical_sector_shift) + cluster_position);
		if (_unlikely(w == 0)) {
			break;
		}
		buf = static_cast<const std::byte *>(buf) + w, n -= w;
		cluster_position += static_cast<uint32_t>(w), cluster_remain -= static_cast<uint32_t>(w);
		ret += w;
	} while (n > 0);
	return ret;
}


_nodiscard const union DirectoryEntry * Directory::next_entry() {
	if (!buffer.grem()) {
		buffer.clear();
		ssize_t r = source.read(buffer.pptr, buffer.prem());
		if (r <= 0) {
			return nullptr;
		}
		buffer.pptr += r;
		if (auto n = static_cast<size_t>(r) % sizeof(union DirectoryEntry)) {
			source.read_fully(buffer.pptr, n);
			buffer.pptr += n;
		}
	}
	auto ret = reinterpret_cast<const union DirectoryEntry *>(buffer.gptr);
	if (ret->generic.entry_type == EntryType { }) { // end of directory
		return nullptr;
	}
	buffer.gptr += sizeof(union DirectoryEntry);
	return ret;
}


} // namespace exfat


#include "common/io.tcc"

template class Readable<exfat::ClusterChainIO>;
template class Writable<exfat::ClusterChainIO>;
