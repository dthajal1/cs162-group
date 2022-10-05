#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "lib/kernel/stdio.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame*);

struct file* get_from_fd_table(int fd);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Returns true if PTR is not: a null pointer, a pointer to unmapped 
    virtual memory, or a pointer to kernel virtual address space 
    (above PHYS_BASE). False otherwise. */
static bool is_pointer_valid(void* ptr) {
  struct thread* t = thread_current();
  return ptr != NULL && pagedir_get_page(t->pcb->pagedir, ptr) != NULL && !is_kernel_vaddr(ptr);
}

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
  if (syscall_num == SYS_EXIT) { /** PROCESS CONTROL SYSCALLS **/
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
    return;
  } else if (syscall_num == SYS_PRACTICE) {
    f->eax = args[1] + 1;
    return;
  } else if (syscall_num == SYS_WRITE) { /** FILE OPERATION SYSCALLS **/
    int fd = args[1];
    if (!is_pointer_valid((void*)args[2])) {
      f->eax = -1;
      return;
    }
    void* buf = (void*)args[2];
    size_t size = args[3];

    if (fd == 1) { // STDOUT
      putbuf(buf, size);
      f->eax = size;
    } else {
      // file* file; // todo: get file from fdt
      // off_t bytes_written = file_write(file, buf, size);
      // f->eax = bytes_written;
    }
    return;
  } else if (syscall_num == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if (syscall_num == SYS_CREATE) {
    if (!is_pointer_valid(args[1])) {
      f->eax = -1;
      return;
    }
    char* file_name = args[1];
    off_t initial_size = args[2];
    lock_acquire(&file_lock);
    bool is_success = filesys_create(file_name, initial_size);
    lock_release(&file_lock);
    f->eax = is_success;
  } else if (syscall_num == SYS_REMOVE) {
    if (!is_pointer_valid(args[1])) {
      f->eax = -1;
      return;
    }
    char* file_name = args[1];
    lock_acquire(&file_lock);
    bool is_success = filesys_remove(file_name);
    lock_release(&file_lock);
    f->eax = is_success;
  } else if (syscall_num == SYS_OPEN) {
    if (!is_pointer_valid(args[1])) {
      f->eax = -1;
      return;
    }
    char* file_name = args[1];
    lock_acquire(&file_lock);
    struct file* file = filesys_open(file_name);
    lock_release(&file_lock);
    if (file == NULL) {
      f->eax = -1;
      return;
    }

    int new_fd = add_to_fd_table(file);
    f->eax = new_fd;
  } else if (syscall_num == SYS_FILESIZE) {
    // args: int fd
    int fd = args[1];
    struct file* file = get_from_fd_table(fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    lock_acquire(&file_lock);
    off_t size = file_length(file);
    lock_release(&file_lock);
    f->eax = size;
  } else if (syscall_num == SYS_READ) {
    int fd = args[1];
    if (!is_pointer_valid(args[2])) {
      f->eax = -1;
      return;
    }
    char* buffer = args[2];
    unsigned size = args[3];

    if (fd == 0) { // read from STDIN_FILENO
      uint8_t key = input_getc();
      // TODO: read to buffer
    } else {
      struct file* file = get_from_fd_table(fd);
      if (file == NULL) {
        f->eax = -1;
        return;
      }
      lock_acquire(&file_lock);
      off_t bytes_read = file_read(file, buffer, size);
      lock_release(&file_lock);
      f->eax = bytes_read;
    }
  } else if (syscall_num == SYS_WRITE) {
    // args: int fd, const void* buffer, unsigned size
    int fd = args[1];
    if (!is_pointer_valid(args[2])) {
      f->eax = -1;
      return;
    }
    char* buffer = args[2];
    unsigned size = args[3];
    if (fd == 1) { // write to console: STDOUT
      putbuf(buffer, size);
      f->eax = size;
    } else {
      struct file* file = get_from_fd_table(fd);
      if (file == NULL) {
        f->eax = -1;
        return;
      }
      lock_acquire(&file_lock);
      off_t bytes_written = file_write(file, buffer, size);
      lock_release(&file_lock);
      f->eax = bytes_written;
    }
  } else if (syscall_num == SYS_SEEK) {
    // args: int fd, unsigned position
    int fd = args[1];
    unsigned position = args[2];

    struct file* file = get_from_fd_table(fd);
    if (file != NULL) {
      lock_acquire(&file_lock);
      file_seek(file, position);
      lock_release(&file_lock);
    }
  } else if (syscall_num == SYS_TELL) {
    // args: int fd
    int fd = args[1];

    struct file* file = get_from_fd_table(fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    lock_acquire(&file_lock);
    off_t curr_pos = file_tell(file);
    lock_release(&file_lock);
    f->eax = curr_pos;
  } else if (syscall_num == SYS_CLOSE) {
    // args: int fd
    int fd = args[1];

    struct file* file = get_from_fd_table(fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    remove_from_fd_table(fd);
    lock_acquire(&file_lock);
    file_close(file);
    lock_release(&file_lock);
  } else { // syscall DNE
    process_exit();
    return;
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
    struct fd_entry* entry = list_entry(e, struct fd_entry, elem);
    if (entry->fd == fd) {
      return entry->file;
    }
  }
  return NULL;
}

/* Helper function for File Operation Syscalls. Removes fd from 
  fd_table.
*/
void remove_from_fd_table(int fd) {
  struct thread* t = thread_current();

  struct fd_entry* entry_to_remove = NULL;

  struct list_elem* e;
  for (e = list_begin(&(t->fd_table->fd_entries)); e != list_end(&(t->fd_table->fd_entries));
       e = list_next(e)) {
    struct fd_entry* entry = list_entry(e, struct fd_entry, elem);
    if (entry->fd == fd) {
      entry_to_remove = entry;
      break;
    }
  }

  if (entry_to_remove != NULL) {
    struct list_elem* elm_to_remove = &(entry_to_remove->elem);
    elm_to_remove->prev->next = elm_to_remove->next;
    elm_to_remove->next->prev = elm_to_remove->prev;

    free(entry_to_remove);
  }
}