#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
void split_path(char* path, char* dir_name, char filename[NAME_MAX + 1]);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();

  /* first user process should have the root directory as its cwd. */
  thread_current()->pcb->cwd = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool is_dir) {
  block_sector_t inode_sector = 0;
  // struct dir* dir = dir_open_root();
  struct dir* dir = NULL;
  char filename[NAME_MAX + 1];
  char dir_name[DIR_NAME_MAX + 1];
  char path[PATH_NAME_MAX + 1];

  if (strlen(name) > PATH_NAME_MAX)
    return false;

  strlcpy(path, name, sizeof(char) * (strlen(name) + 1));
  split_path(path, dir_name, filename);
  if (strcmp(dir_name, ".") == 0) { // TODO: remove this after . and .. handled in dir_get
    dir = dir_open_root();
  } else {
    dir = dir_get(dir_name);
  }

  bool success =
      (dir != NULL && free_map_allocate(1, &inode_sector) &&
       inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, filename, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  // struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  struct dir* dir = NULL;
  char filename[NAME_MAX + 1];
  char dir_name[DIR_NAME_MAX + 1];
  char path[PATH_NAME_MAX + 1];

  if (strlen(name) > PATH_NAME_MAX)
    return NULL;

  strlcpy(path, name, sizeof(char) * (strlen(name) + 1));
  split_path(path, dir_name, filename);
  if (strcmp(dir_name, ".") == 0) { // TODO: remove this after . and .. handled in dir_get
    dir = dir_open_root();
  } else {
    dir = dir_get(dir_name);
  }

  if (dir != NULL)
    dir_lookup(dir, filename, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  // struct dir* dir = dir_open_root();
  struct dir* dir = NULL;
  char filename[NAME_MAX + 1];
  char dir_name[DIR_NAME_MAX + 1];
  char path[PATH_NAME_MAX + 1];

  if (strlen(name) > PATH_NAME_MAX)
    return false;

  strlcpy(path, name, sizeof(char) * (strlen(name) + 1));
  split_path(path, dir_name, filename);
  if (strcmp(dir_name, ".") == 0) { // TODO: remove this after . and .. handled in dir_get
    dir = dir_open_root();
  } else {
    dir = dir_get(dir_name);
  }

  bool success = dir != NULL && dir_remove(dir, filename);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/*
  ### Helper Functions ###
*/

/* Splits path and store directory name in dir_name and file name in filename.
  If path is a directory, sets filename to new directory that's to be created/removed
  and dir_name to existing directory. */
void split_path(char* path, char* dir_name, char filename[NAME_MAX + 1]) {
  // if path ends in a trailing slash, strip it off
  if (path[strlen(path) - 1] == '/') {
    path[strlen(path) - 1] = '\0';
  }

  // find last occurence of /
  char* pivot = strrchr(path, '/');

  if (pivot == NULL) { // TODO: update this after . and .. handled in dir_get
    // path = 'filename'.
    strlcpy(dir_name, ".", sizeof(char) * (1 + 1));
    strlcpy(filename, path, sizeof(char) * (strlen(path) + 1));
    return;
  }

  int len = strlen(path);
  int file_len = strlen(pivot);
  int dir_len = len - file_len;

  strlcpy(dir_name, path, sizeof(char) * (dir_len + 1));
  strlcpy(filename, path, sizeof(char) * (file_len + 1));
}
