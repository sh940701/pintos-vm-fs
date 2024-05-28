#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		// fat 를 새로 만들어서 disk 에 저장해줌
		do_format ();

	// disk 로부터 fat 를 읽어서 fat_fs 에 저장
	fat_open ();

	thread_current()->cwd = dir_open_root();
	dir_add(thread_current()->cwd, ".", inode_get_inumber(dir_get_inode(thread_current()->cwd)));
	dir_add(thread_current()->cwd, "..", inode_get_inumber(dir_get_inode(thread_current()->cwd)));
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = fat_create_chain(0);

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);

	struct dir *dir = parse_path(cp_name, file_name);

	bool success = (dir != NULL
			&& inode_create (cluster_to_sector(inode_sector), initial_size, 0)
			&& dir_add (dir, file_name, cluster_to_sector(inode_sector)));

	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);

	dir_close (dir);
	free(cp_name);
	free(file_name);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	disk_sector_t inode_sector = fat_create_chain(0);

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);

	struct dir *dir = parse_path(cp_name, file_name);

	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, file_name, &inode);

	dir_close (dir);
	free(cp_name);
	free(file_name);

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	// disk_sector_t inode_sector = fat_create_chain(0);

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);
	struct dir *dir = parse_path(cp_name, file_name);

	struct inode *inode = NULL;
	bool success = false;

	if (dir != NULL) {
		dir_lookup(dir, file_name, &inode);

		if (inode == NULL)
			return false;

		// directory 타입인지 먼저 확인
		if (inode_is_dir(inode)) {
			struct dir *cur_dir = dir_open(inode);
			char *tmp = (char *)malloc(NAME_MAX + 1);
			// ".", ".." 을 건너뛰자!
			dir_seek(cur_dir, 2 * sizeof(struct dir_entry));
			
			if (!dir_readdir(cur_dir, tmp)) { // 이거 근데 그냥 dir_lookup 으로 바꿔도 되지 않을까?
				// 현재 실행중인 directory 가 아닌지 검사
				if (inode_get_inumber(thread_current()->cwd) != inode_get_inumber(dir_get_inode(cur_dir))) {
					success = dir_remove(dir, file_name);
				}
			} else {
				success = dir_remove(cur_dir, file_name); // 이건 진짜 왜인지 꼭 파악하기
			}

			dir_close(cur_dir);
			free(tmp);
		} else { // 그냥 파일이라면
			inode_close(inode);
			success = dir_remove(dir, file_name);
		}
	}

	dir_close (dir);
	free(cp_name);
	free(file_name);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_put(ROOT_DIR_CLUSTER, EOChain);
	if (!dir_create (cluster_to_sector(ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

// 경로 분석 함수 구현
struct dir *parse_path(char *path_name, char *file_name) {  // file_name: path_name을 분석하여 파일, 디렉터리의 이름을 포인팅
    struct dir *dir = NULL;
    if (path_name == NULL || file_name == NULL)
        return NULL;
    if (strlen(path_name) == 0)
        return NULL;

    // path_name의 절대/상대 경로에 따른 디렉터리 정보 저장
    if(path_name[0] == '/') {
        dir = dir_open_root();
    }
    else {
        dir = dir_reopen(thread_current()->cwd);
	}

    char *token, *nextToken, *savePtr;
    token = strtok_r(path_name, "/", &savePtr);
    nextToken = strtok_r(NULL, "/", &savePtr);

    // "/"를 open하려는 케이스
    if(token == NULL) {
        token = (char*)malloc(2);
        strlcpy(token, ".", 2);
    }

    struct inode *inode;
    while (token != NULL && nextToken != NULL) {
        // dir에서 token이름의 파일을 검색하여 inode의 정보를 저장
        if (!dir_lookup(dir, token, &inode)) {
            dir_close(dir);
            return NULL;
        }
        
        // inode가 파일일 경우 NULL 반환
        if(!inode_is_dir(inode)) {
            dir_close(dir);
            inode_close(inode);
            return NULL;
        }
        // dir의 디렉터리 정보를 메모리에서 해지
        dir_close(dir);

        // inode의 디렉터리 정보를 dir에 저장
        dir = dir_open(inode);

        // token에 검색할 경로이름 저장
        token = nextToken;
        nextToken = strtok_r(NULL, "/", &savePtr);
    }
    // token의 파일이름을 file_name에 저장
    strlcpy (file_name, token, strlen(token) + 1);

    // dir정보반환
    return dir;
}

bool filesys_create_directory(char *name) {
	disk_sector_t inode_sector = fat_create_chain(0);

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);

	struct dir *dir = parse_path(cp_name, file_name);

	bool success = (dir != NULL
		&& inode_create (cluster_to_sector(inode_sector), 16 * sizeof(struct dir_entry), 1)
		&& dir_add (dir, file_name, cluster_to_sector(inode_sector))
	);

	struct inode *inode = NULL;

	if (!dir_lookup (dir, file_name, &inode)) {
		return false;
	}

	struct dir *child = dir_open(inode);

	if (!dir_add(child, ".", dir_get_inode(child))) {
		return false;
	}

	if (!dir_add(child, "..", dir_get_inode(dir))) {
		return false;
	}

	free(cp_name);
	free(file_name);
	return true;
}

bool filesys_change_directory(char *name) {
	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);

	struct dir *dir = parse_path(cp_name, file_name);

	struct inode *inode = NULL;

	if (!dir_lookup (dir, file_name, &inode) || !inode_is_dir(inode)) {
		return false;
	}

	struct dir* next_dir = dir_open(inode);

	dir_close(thread_current()->cwd);
	thread_current()->cwd = next_dir;

	free(cp_name);
	free(file_name);
	return true;
}