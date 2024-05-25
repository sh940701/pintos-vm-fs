#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot
{
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. */ // -> fat 가 몇 개의 sector 를 차지하는가
	unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs
{
	struct fat_boot bs;
	unsigned int *fat;
	unsigned int fat_length;
	disk_sector_t data_start;
	cluster_t last_clst;
	struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create(void);
void fat_fs_init(void);

void fat_init(void)
{
	fat_fs = calloc(1, sizeof(struct fat_fs));
	if (fat_fs == NULL)
		PANIC("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc(DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC("FAT init failed");
	// 여기서 boot sector 의 데이터를 읽어서 bounce 에 담아준다.
	disk_read(filesys_disk, FAT_BOOT_SECTOR, bounce);
	// fat_fs 에 boot sector 데이터 복사
	memcpy(&fat_fs->bs, bounce, sizeof(fat_fs->bs));
	free(bounce);

	// Extract FAT info
	// fat_fs 부팅
	// 이 때 FAT-MAGIC 값을 통해서 유효한 boot_sector 데이터인지 확인하고 create 실행
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create();
	fat_fs_init();
}

void fat_open(void)
{
	fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t));
	if (fat_fs->fat == NULL)
		PANIC("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *)fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof(fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++)
	{
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE)
		{
			disk_read(filesys_disk, fat_fs->bs.fat_start + i,
					  buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		}
		else
		{
			uint8_t *bounce = malloc(DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC("FAT load failed");
			disk_read(filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy(buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free(bounce);
		}
	}
}

void fat_close(void)
{
	// Write FAT boot sector
	uint8_t *bounce = calloc(1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC("FAT close failed");
	memcpy(bounce, &fat_fs->bs, sizeof(fat_fs->bs));
	disk_write(filesys_disk, FAT_BOOT_SECTOR, bounce);
	free(bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *)fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof(fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++)
	{
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE)
		{
			disk_write(filesys_disk, fat_fs->bs.fat_start + i,
					   buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		}
		else
		{
			bounce = calloc(1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC("FAT close failed");
			memcpy(bounce, buffer + bytes_wrote, bytes_left);
			disk_write(filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free(bounce);
		}
	}
}

void fat_create(void)
{
	// Create FAT boot
	fat_boot_create();
	fat_fs_init();

	// Create FAT table
	fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t)); // fat 테이블 생성
	if (fat_fs->fat == NULL)
		PANIC("FAT creation failed");

	// Set up ROOT_DIR_CLST
	// fat 의 0 번은 boot sector, 1 번은 root directory 로 설정
	// todo 근데 이 때 boot sector 는 0번에 언제 넣어주는걸까?
	fat_put(ROOT_DIR_CLUSTER, EOChain);

	// Fill up ROOT_DIR_CLUSTER region with 0
	uint8_t *buf = calloc(1, DISK_SECTOR_SIZE);
	if (buf == NULL)
		PANIC("FAT create failed due to OOM");
	disk_write(filesys_disk, cluster_to_sector(ROOT_DIR_CLUSTER), buf);
	free(buf);
}

void fat_boot_create(void)
{
	unsigned int fat_sectors =
		// 디스크 전체 byte 수 / (sector 한 개 사이즈(512) / fat element size(4) * 1 + 1) + 1
		(disk_size(filesys_disk) - 1) / (DISK_SECTOR_SIZE / sizeof(cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
		.magic = FAT_MAGIC,
		.sectors_per_cluster = SECTORS_PER_CLUSTER,
		.total_sectors = disk_size(filesys_disk),
		.fat_start = 1,
		.fat_sectors = fat_sectors,
		.root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

void fat_fs_init(void)
{
	// 전체 디스크의 element 수 - fat 이 차지하는 
	fat_fs->fat_length = disk_size(filesys_disk) - 1 - fat_fs->bs.fat_sectors;
	fat_fs->data_start = fat_fs->bs.fat_start + fat_fs->bs.fat_sectors;
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain(cluster_t clst)
{
	int available_idx = find_empty_fat();
	cluster_t available_clst = available_idx;
	if (available_idx == EOChain)
		return 0;

	if (clst == 0)
	{
		fat_fs->fat[available_idx] = EOChain;
	}
	else
	{
		cluster_t tmp = fat_fs->fat[clst];
		fat_fs->fat[clst] = available_clst;
		fat_fs->fat[available_clst] = tmp;
	}

	return available_clst;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void fat_remove_chain(cluster_t clst, cluster_t pclst)
{
	/* TODO: Your code goes here. */
	if (pclst == 0)
	{
		fat_fs->fat[clst] = 0;
	}
	else
	{
		while (1)
		{
			cluster_t tmp = fat_fs->fat[clst];
			fat_fs->fat[clst] = 0;
			clst = tmp;

			if (clst == EOChain)
				break;
		}
	}
}

/* Update a value in the FAT table. */
void fat_put(cluster_t clst, cluster_t val)
{
	/* TODO: Your code goes here. */
	fat_fs->fat[clst] = val;
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get(cluster_t clst)
{
	/* TODO: Your code goes here. */
	return fat_fs->fat[clst];
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector(cluster_t clst)
{
	/* TODO: Your code goes here. */
	return clst + fat_fs->data_start;
}

int find_empty_fat()
{
	for (int i = fat_fs->bs.fat_start; i < fat_fs->fat_length; i++)
	{
		if (fat_fs->fat[i] == 0)
		{
			return i;
		}
	}

	return EOChain;
}

cluster_t sector_to_cluster(disk_sector_t sector) {
	cluster_t clst = sector - fat_fs->data_start;

	if (clst < 2)
		return 0;

	return clst;
}
