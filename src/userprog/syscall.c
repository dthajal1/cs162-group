#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "lib/kernel/stdio.h"
#include "devices/input.h"
#include "filesys/file.h"

/* File Descriptor Entry. It should be allocated on the heap and 
  added to fd_table on every call to open(). */
struct fd_entry {
  struct list_elem elem; // doubly linked list functionality
  int fd;
  struct file* file;
}

static void
syscall_handler(struct intr_frame*);

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

  int syscall_num = args[0];
  switch (syscall_num) {
    case SYS_EXIT:
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
    case SYS_CREATE:
      // verify args: char *file, unsigned initial_size
      char* file_name = args[1];
      off_t initial_size = args[2];
      bool is_success = filesys_create(file_name, initial_size);
      f->eax = is_success;
      break;
    case SYS_REMOVE:
      // verify args: char *file
      char* file_name = args[1];
      bool is_success = filesys_remove(file_name);
      f->eax = is_success;
      break;
    case SYS_OPEN:
      // verify args:  char *file
      char* file_name = args[1];
      struct file* file = filesys_open(file_name);

      int new_fd = add_to_fd_table(file);
      f->eax = new_fd;
      break;
    case SYS_FILESIZE:
      // verify args: int fd
      int fd = args[1];
      struct file* file = get_from_fd_table(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        off_t size = file_length(file);
        f->eax = size;
      }
      break;
    case SYS_READ:
      // verify args: int fd, void *buffer, unsigned size
      int fd = args[1];
      char* buffer = args[2];
      unsigned size = args[3];

      if (fd == 0) { // read from STDIN_FILENO
        uint8_t key = input_getc();
        // TODO: read to buffer
      } else {
        struct file* file = get_from_fd_table(fd);
        if (file == NULL) {
          f->eax = -1;
        } else {
          off_t bytes_read = file_read(file, buffer, size);
          f->eax = bytes_read;
        }
      }
      break;
    case SYS_WRITE:
      // verify args: int fd, const void* buffer, unsigned size
      int fd = args[1];
      char* buffer = args[2];
      unsigned size = args[3];
      if (fd == 1) { // write to console: STDOUT
        putbuf(buffer, size);
        f->eax = size;
      } else {
        struct file* file = get_from_fd_table(fd);
        if (file == NULL) {
          f->eax = -1;
        } else {
          off_t bytes_written = file_write(file, buffer, size);
          f->eax = bytes_written;
        }
      }
      break;
    case SYS_SEEK:
      // verify args: int fd, unsigned position
      int fd = args[1];
      unsigned position = args[2];

      struct file* file = get_from_fd_table(fd);
      if (file != NULL) {
        file_seek(file, position);
      }
      break;
    case SYS_TELL:
      // verify args: int fd
      int fd = args[1];

      struct file* file = get_from_fd_table(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        off_t curr_pos = file_tell(file);
        f->eax = curr_pos;
      }
      break;
    case SYS_CLOSE:
      // verify args: int fd
      int fd = args[1];

      struct file* file = get_from_fd_table(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        file_close(file);
      }
      break;
    default:
      break;
  }
}

/* Helper function for File Operation Syscalls. On success, 
  returns a new file descriptor that points to FILE in fd_table
  and -1 otherwise.
*/
int add_to_fd_table(struct file* file) {
  struct thread* t = thread_current();

  struct fd_entry* new_entry = malloc(sizeof(struct fd_entry));
  if (new_entry != NULL) {
    new_entry->file = file;
    new_entry->fd = t->fd_table->next_fd;
    list_push_back(&(t->fd_table->fd_entries), &(new_entry->elem));

    t->fd_table->next_fd++; // increment next_fd to next available location

    return new_entry->fd;
  }
  return -1;
}

/* Helper function for File Operation Syscalls. On success,
  returns the file pointed to by FD in fd_table and NULL 
  otherwise.
*/
struct file* get_from_fd_table(int fd) {
  struct thread* t = thread_current();

  struct list_elem* e;

  for (e = list_begin(&(t->fd_table->fd_entries)); e != list_end(&(t->fd_table->fd_entries));
       e = list_next(e)) {
    struct fd_entry* entry = list_entry(e, struct fd_entry, list_elem);
    if (entry->fd == fd) {
      return entry->file;
    }
  }
  return NULL;
}
