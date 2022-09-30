#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

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

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
}

/* Helper function for File Operation Syscalls. */
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

/* Helper function for File Operation Syscalls. */
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
