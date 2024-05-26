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
#include "include/threads/thread.h"

struct dir *parse_path(char *path_name, char *file_name);
// struct lock filesys_lock;

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
filesys_create (const char *name, off_t initial_size) { // 파일의 이름과 크기를 받아서 초기화		
	bool success = false;
	// struct disk_inode 를 저장할 새로운 cluster 할당

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);
	struct dir *dir = parse_path(cp_name, file_name);

	if (strlen(file_name) > NAME_MAX + 1) {
		return false;
	}

	cluster_t disk_inode_cluster = fat_create_chain(0);

	success = (dir != NULL
		&& inode_create (disk_inode_cluster, initial_size, 0)
		&& dir_add (dir, file_name, disk_inode_cluster)
	);

	// root directory 를 연다.
	// 여기서 연게 0번째 데이터에 있는 directory 데이터의 inode 였구나!
	// struct dir *dir = dir_open_root();

	if (!success && disk_inode_cluster != 0)
		fat_remove_chain(disk_inode_cluster, 1);
	
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
	char *cp_name = (char *)malloc(strlen(name) + 1);
	char *file_name = (char *)malloc(strlen(name) + 1);

	struct dir *dir = NULL;
	struct inode *inode = NULL;

	while(1) {
		strlcpy(cp_name, name, strlen(name) + 1);
		dir = parse_path(cp_name, file_name);

		if (dir != NULL) {
			dir_lookup(dir, file_name, &inode);
			// if(inode && inode->data.is_link) {
			// 	dir_close(dir);
			// 	name = inode->data.link_name;
			// 	continue;
			// }
		}

		free(cp_name);
		free(file_name);
		dir_close(dir);
		break;
	}

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);
	struct dir *dir = parse_path(cp_name, file_name);

	struct inode *inode = NULL;
	bool success = false;

	if (dir != NULL) {
		dir_lookup(dir, file_name, &inode);

		if (inode_is_dir(inode)) {
			struct dir *cur_dir = dir_open(inode);
			char *tmp = (char *)malloc(NAME_MAX + 1);
			dir_seek(cur_dir, 2 * sizeof(struct dir_entry));

			if (!dir_readdir(cur_dir, tmp)) {
				if (inode_get_inumber(dir_get_inode(thread_current()->cwd)) != inode_get_inumber(dir_get_inode(cur_dir))) {
					success = dir_remove(dir, file_name);
				}
			} else {
				success = dir_remove(cur_dir, file_name); // 이건 뭘까? 왜 하는걸까?
			}

			dir_close(cur_dir);
			free(tmp);
		} else {
			inode_close(inode);
			success = dir_remove(dir, file_name);
		}
	}

	dir_close(dir);
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

	if (!dir_create (cluster_to_sector(ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed");
	struct dir* root_dir = dir_open_root();
	dir_add(root_dir, ".", ROOT_DIR_CLUSTER);
	dir_add(root_dir, "..", ROOT_DIR_CLUSTER);
	dir_close(root_dir);

	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

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

        // if(inode->data.is_link) {   // 링크 파일인 경우
        //     char* new_path = (char*)malloc(sizeof(strlen(inode->data.link_name)) + 1);
        //     strlcpy(new_path, inode->data.link_name, strlen(inode->data.link_name) + 1);

        //     strlcpy(path_name, new_path, strlen(new_path) + 1);
        //     free(new_path);
 
        //     strlcat(path_name, "/", strlen(path_name) + 2);
        //     strlcat(path_name, nextToken, strlen(path_name) + strlen(nextToken) + 1);
        //     strlcat(path_name, savePtr, strlen(path_name) + strlen(savePtr) + 1);

        //     dir_close(dir);

        //     // 파싱된 경로로 다시 시작한다
        //     if(path_name[0] == '/') {
        //         dir = dir_open_root();
        //     }
        //     else {
        //         dir = dir_reopen(thread_current()->cwd);
        //     }


        //     token = strtok_r(path_name, "/", &savePtr);
        //     nextToken = strtok_r(NULL, "/", &savePtr);

        //     continue;
        // }
        
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

bool filesys_create_dir(const char *name) {
	bool success = false;

	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);
	struct dir *dir = parse_path(cp_name, file_name);

	cluster_t inode_cluster = fat_create_chain(0);
	struct inode *sub_dir_inode;
	struct dir *sub_dir = NULL;

	success = (
		dir != NULL
		&& dir_create(inode_cluster, 16)
		&& dir_add(dir, file_name, inode_cluster)
		&& dir_lookup(dir, file_name, &sub_dir_inode)
		&& dir_add(sub_dir = dir_open(sub_dir_inode), ".", inode_cluster)
		&& dir_add(sub_dir, "..", inode_get_inumber(dir_get_inode(dir)))
	);

	if (!success && inode_cluster != 0) {
		fat_remove_chain(inode_cluster, 0); // 1로?
	}

	dir_close(sub_dir);
	dir_close(dir);

	free(cp_name);
	free(file_name);

	return success;
}

bool filesys_chdir(const char *path_name) {
	if (path_name == NULL) {
		return false;
	}

	char *cp_name = (char *)malloc(strlen(path_name) + 1);
	strlcpy(cp_name, path_name, strlen(path_name) + 1);

	struct dir *chdir = NULL;

	if (cp_name[0] == '/') {
		chdir = dir_open_root();
	} else {
		chdir = dir_reopen(thread_current()->cwd);
	}

	char *token, *save_ptr;
	token = strtok_r(cp_name, "/", &save_ptr);

	struct inode *inode = NULL;
	while (token != NULL) {
		if (!dir_lookup(chdir, token, &inode)) {
			dir_close(chdir);
			return false;
		}

		if (!inode_is_dir(inode)) {
			dir_close(chdir);
			return false;
		}

		dir_close(chdir);

		chdir = dir_open(inode);

		token = strtok_r(NULL, "/", &save_ptr);
	}

	dir_close(thread_current()->cwd);
	thread_current()->cwd = chdir;
	free(cp_name);

	return true;
}