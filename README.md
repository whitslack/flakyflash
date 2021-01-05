[F3]: https://github.com/AltraMayor/f3 "F3 - Fight Flash Fraud"

[fatgen103.doc]: http://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc


# Flakyflash

Flakyflash is a Linux-based tool for diagnosing and salvaging FAT-formatted flash media having flaky sectors that do not retain data correctly. Note, it is not intended for diagnosing "fake flash" (a.k.a. "fraudulent flash") media; see [F3][] for that.

Flakyflash works by reading each free data cluster in a FAT file system and then *re-reading* it and comparing the two reads. If they differ, then the cluster is assumed to be "flaky," and Flakyflash marks the cluster as bad in the file allocation table so that file system drivers will not allocate data to it. Only free data clusters (and, as an option, already marked-bad data clusters) are checked. Clusters that are currently in use by files and subdirectory metadata are not touched in any way. Obviously, for the most thorough checking, one should run this tool on a completely empty file system so that every data cluster may be checked for flakiness.

## Usage

```
usage: flakyflash [options] <block-device>

options:
	-b,--bad-clusters=[<action>,...]
	-f,--free-clusters=[<action>,...]
	-v,--verbose

actions:
	read: read cluster; mark bad if device errors
	reread: re-read cluster; mark bad if different
	zeroout: issue BLKZEROOUT ioctl on cluster
		(elided if a previous "read" found cluster already zeroed)
	readzeros: read cluster; mark bad if not zeroed
	f3write: fill cluster with reproducible data
		(elided if a previous "read" found cluster already correct)
	f3read: read cluster; mark bad if subtly changed
	secdiscard: issue BLKSECDISCARD ioctl on cluster
	discard: issue BLKDISCARD ioctl on cluster
	trash: fill cluster with pseudorandom garbage
	bad: mark cluster as bad unconditionally
	free: mark cluster as free unconditionally

defaults:
	--bad-clusters=
	--free-clusters=read,reread
```

If run with the `--verbose` option, Flakyflash outputs a human-readable decoding of all [standard FAT file system][fatgen103.doc] superblock fields, including FAT32-specific fields (if applicable) and the fields of the File System Information sector (if present).

For each free cluster (and, optionally, for each bad cluster), Flakyflash performs a user-specified sequence of actions, which may comprise:

* **`read`** – Reads the cluster from the media.

* **`reread`** – Reads the cluster from the media again. If the data retrieved do not match the data retrieved by the previous `read` action (or written by the previous `zeroout`, `f3write`, or `trash` action), then Flakyflash marks the cluster as bad and continues immediately to the next cluster. If no previous action had established a baseline for the current cluster, then `reread` implicitly performs a `read` first.

* **`zeroout`** – Issues a `BLKZEROOUT` `ioctl` on the cluster, which causes the kernel to overwrite the cluster on the media with null bytes. If a previous action had already established that the cluster contains only null bytes, then the `zeroout` action is skipped to avoid excessive writing to the flash media. The `zeroout` action itself establishes that the cluster contains only null bytes, which implies that multiple `zeroout` actions in a row will collapse to a single action.

* **`readzeros`** – Reads the cluster from the media. If the data retrieved are not all null bytes, then Flakyflash marks the cluster as bad and continues immediately to the next cluster. This action may be used to check for spurious bit flips (a.k.a. "bit rot") if it is known for certain that the clusters should contain only null bytes, such as if a previous session of Flakyflash had zeroed them out using the `zeroout` action.

* **`f3write`** – Overwrites the entire cluster on the media with reproducible data derived from the cluster's offset by the same linear congruential generator as [F3][] uses. If a previous action had already established that the cluster contains exactly these data, then the `f3write` action is skipped to avoid excessive writing to the flash media. The `f3write` action itself establishes that the cluster contains exactly these data, which implies that multiple `f3write` actions in a row will collapse to a single action.

* **`f3read`** – Reads the cluster from the media and compares the data retrieved versus the data that the `f3write` action would write to the same cluster. If (and only if) more than zero but fewer than one eighth of the bits differ, then Flakyflash marks the cluster as bad and continues immediately to the next cluster. If the cluster appears to contain data that the `f3write` action would write to some other cluster, then Flakyflash emits a warning message suggesting that the flash media may be fraudulent. Otherwise, if more than one eighth of the bits differ from the intended data, then Flakyflash emits a warning message indicating that the cluster is corrupted. This action may be used to check for spurious bit flips (a.k.a. "bit rot") if it is known for certain that the clusters were most recently written using the `f3write` action.

* **`secdiscard`** – Issues a `BLKSECDISCARD` `ioctl` on the cluster, which is supposed to cause the cluster to be erased irrecoverably, although hardware support for this is spotty. If the device does not support this action, then Flakyflash will emit an error message and abort with status code 134 (indicating `SIGABRT`).

* **`discard`** – Issues a `BLKDISCARD` `ioctl` on the cluster, which indicates to the device that the data contents of the cluster are no longer needed. Some devices will immediately begin reading a discarded cluster as all null bytes, whereas others will put the cluster into an indeterminate state. If the device does not support this action, then Flakyflash will emit an error message and abort with status code 134 (indicating `SIGABRT`).

* **`trash`** – Overwrites the entire cluster on the media with pseudorandom garbage generated by the kernel. The `trash` action establishes a new baseline for the cluster, against which a subsequent `reread` action may compare to determine if the write succeeded.

* **`bad`** – Unconditionally marks the cluster as bad. There may be no good use for this action, but it is included for completeness.

* **`free`** – Unconditionally marks the cluster as free. This action may be used to effect retesting of clusters previously marked as bad by specifying it as an action to perform on bad clusters.

If any action encounters a hardware error (i.e., a system call returns error code `EIO`), then Flakyflash marks the current cluster as bad and continues immediately to the next cluster.

Any changes to the FAT are written to the media only once at the completion of testing. Interrupting Flakyflash before it has finished will cause any pending FAT changes to be lost. Note that writes to data clusters are performed *during* testing and are not deferred to the end.

## Examples

	flakyflash --verbose --bad-clusters= --free-clusters= /dev/sdX1

Only outputs a human-readable decoding of the file system superblocks but does not test any data clusters. Note that the default action list for bad clusters is empty, so the `--bad-clusters=` argument may be omitted with the same effect.

	flakyflash --free-clusters=read,reread /dev/sdX1

Tests each free data cluster by reading it and re-reading it. Marks as bad any clusters that do not read the same on the second read. Note that the default action list for free clusters is `read,reread`, so the `--free-clusters=read,reread` argument may be omitted with the same effect.

	flakyflash --free-clusters=read,reread,reread,reread /dev/sdX1

Almost the same as the preceding example except that each free data cluster is read a total of four times instead of twice. If any read of the cluster fails to match any other read of the same cluster, then Flakyflash marks the cluster as bad.

	flakyflash --free-clusters=read,zeroout,reread /dev/sdX1

Reads each free data cluster, and if it does not already contain only null bytes, then fills the cluster with null bytes. Re-reads the cluster afterward, and if it does not then contain only null bytes, then marks the cluster as bad.

	flakyflash --free-clusters=zeroout,reread /dev/sdX1

Almost the same as the preceding example except that every free cluster is overwritten with null bytes unconditionally, without first checking whether the cluster already contains only null bytes.

	flakyflash --free-clusters=zeroout,reread,trash,reread,zeroout,reread,discard /dev/sdX1

Really exercises each free data cluster by overwriting it with null bytes, verifying that it reads back as all null bytes, overwriting it with pseudorandom garbage, verifying that the garbage reads back correctly, overwriting it null bytes again, verifying that it reads back as all null bytes, and finally discarding it. This will very likely detect most weak clusters except if the device has an onboard cache.

	flakyflash --free-clusters=read,f3write,reread /dev/sdX1

Reads each free data cluster, and if it does not already contain exactly the data that `f3write` would write to it, then overwrites the cluster with those deterministic data. Re-reads the cluster afterward, and if it does not then contain the intended data, then marks the cluster as bad. This may be used to prepare the media for a data retention test. After thusly preparing the media, it should be placed in storage for a period of time. Upon retrieval of the media from storage, the next example shall conclude the test.

	flakyflash --free-clusters=f3read /dev/sdX1

Reads each free data cluster and verifies that it contains the same deterministic data that the previous example wrote to it. Marks as bad any clusters whose data have changed subtly since they were written. Emits warnings about any clusters whose data have changed more than subtly or whose data were supposed to have been written to some other cluster. These latter cases may indicate that the flash media is fraudulent, and [F3][] may be further employed to diagnose such media.

	flakyflash --bad-clusters=free,read,reread --free-clusters= /dev/sdX1

Retests all data clusters previously marked as bad. Each bad cluster is first marked as free (i.e., not bad) and is then read and re-read. If the two reads do not match, then the cluster is marked as bad again. Note that any changes to the FAT are written to the media only once at the completion of testing, so this will not issue redundant writes to the media.


## Building

You'll need GCC 9 or newer to build Flakyflash.

	git clone --recurse-submodules https://github.com/whitslack/flakyflash.git
	cd flakyflash
	make

There is no installation needed, but you can install the compiled binary if you want to:

	install -Dt /usr/local/sbin "out/$(gcc -dumpmachine)/flakyflash"
