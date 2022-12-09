#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

/* TODO: update if it doesn't work. Copied from pwd.c (MAX_LEVEL * 3 + 1 + READDIR_MAX_LEN) */
#define DIR_NAME_MAX 20 * 3 + 1 + 14

#define PATH_NAME_MAX DIR_NAME_MAX + NAME_MAX

/* Block device that contains the file system. */
extern struct block* fs_device;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size, bool is_dir);
struct file* filesys_open(const char* name);
bool filesys_remove(const char* name);

#endif /* filesys/filesys.h */
