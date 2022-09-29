#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* I added these libs: not sure if allowed */
#include "lib/kernel/stdio.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  // thread safety: need to acquire a lock? global lock?
  // static struct lock lock;
  // lock_init(&lock);
  // lock_acquire(&lock);

  // do stuff

  // lock_release(&lock);


  // use hashmap + a counter to keep track of pointer to files?

  int syscall_num = args[0];
  switch (syscall_num) {
    case SYS_EXIT:
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
    case SYS_CREATE:
      // 2 args: char *file, unsigned initial_size
      char *file_name = args[1];
      off_t initial_size = args[2];
      bool is_success = filesys_create(file_name, initial_size);
      f->eax = is_success;
      break;
    case SYS_REMOVE:
      // 1 arg: char *file
      // requirement: "when a file is removed any process which has a file descriptor for that file may continue to use that descriptor"
        // does our implementation satisfy this requirement?
      char *file_name = args[1];
      bool is_success = filesys_remove(file_name);
      f->eax = is_success;
      break;
    case SYS_OPEN:
      // 1 arg:  char *file
      // TODO: When a single file is opened more than once, each open must return a new file descriptor
        // already done? see comment above file_open() in file.c

      // before returning verify file descriptors are not 0 or 1
      char *file_name = args[1];
      struct file *file_ptr = filesys_open(file_name);
      // save file pointer to the file descriptor table and return the fd
      save_file_ptr(file_ptr);
      if (file_ptr == NULL) {
        f->eax = -1;
      } else {
        // file descriptor is a number that uniquely identifies an open file
        // pointer to address of file structs unique?
          // what happens if we call open file on same file? pointer (fd) still unique?
        f->eax = (uint32_t) file_ptr;
      }
      break;
    case SYS_FILESIZE:
      // 1 arg: int fd
      int fd = args[1];

      struct file *file_ptr = get_file(fd);

      off_t size = file_length(file_ptr);
      f->eax = size;
      break;
    case SYS_READ:
      // 3 args: int fd, void *buffer, unsigned size
      int fd = args[1];
      char *buffer = args[2];
      unsigned size = args[3];

      if (fd == 0) { // read from STDIN_FILENO (0th index in fd table)
        uint8_t key = input_getc();
        // TODO

      } else {
        struct file *file_ptr = get_file(fd);
        
        off_t bytes_read = file_read(file_ptr, buffer, size);
        f->eax = bytes_read;
      }
      break;
    case SYS_WRITE:
      // 3 args: int fd, const void* buffer, unsigned size
      int fd = args[1];
      char *buffer = args[2];
      unsigned size = args[3];
      if (fd == 1) { // write to console: STDOUT
        putbuf(buffer, size);
        f->eax = size;
      } else {
        struct file *file_ptr = get_file(fd);

        off_t bytes_written = file_write(file_ptr, buffer, size);
        f->eax = bytes_written;
      }
      break;
    case SYS_SEEK:
      // 2 args: int fd, unsigned position
      int fd = args[1];
      unsigned position = args[2];

      struct file *file_ptr = get_file(fd);

      file_seek(file_ptr, position);
      break;
    case SYS_TELL:
      // 1 arg: int fd
      int fd = args[1];

      struct file *file_ptr = get_file(fd);

      off_t curr_pos = file_tell(file_ptr);
      f->eax = curr_pos;
      break;
    case SYS_CLOSE:
      // 1 arg: int fd
      int fd = args[1];

      struct file *file_ptr = get_file(fd);

      file_close(file_ptr);
      break;
    default:
      break;
  }
}


struct fd_entry {
  // struct list_elem elem;
  int fd;
  struct file *file_ptr;
}

int save_file_ptr(struct file* file_ptr) {
  // get the last element from fd_table
  
  struct fd_entry *entry = malloc(sizeof(struct fd_entry));
  if (entry != NULL) {
    entry->file_ptr = file_ptr;
    // entry->fd = last_elem->fd + 1
  }
  return -1;
}

struct file *get_file(int fd) {
  // can cast (void *) to any type; here we cast it to struct pointer (struct file *)
  struct file *opened_file = (void *) fd; // TODO: will this give us the file struct back?
  return opened_file;
}

