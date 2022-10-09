#include "devices/shutdown.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "lib/kernel/stdio.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Returns true if PTR is not: a null pointer, a pointer to unmapped 
    virtual memory, or a pointer to kernel virtual address space 
    (above PHYS_BASE). False otherwise. */

static bool is_string_valid(void* str) {
  struct thread* t = thread_current();
  int offset = 0;
  while (pagedir_get_page(t->pcb->pagedir, str + offset) != NULL) {
    if ((char)((char*)str + offset) == '\0') {
      return true;
    }
    offset += 1;
  }
  return false;
}

static bool is_pointer_valid(void* ptr) {
  struct thread* t = thread_current();
  for (int offset = 0; offset < 4; offset++) {
    if (ptr + offset == NULL || pagedir_get_page(t->pcb->pagedir, ptr + offset) == NULL) {
      return false;
    }
  }
  return true;
  // return ptr != NULL && pagedir_get_page(t->pcb->pagedir, ptr) != NULL && is_user_vaddr(ptr);
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
  } else if (syscall_num == SYS_HALT) {
    shutdown_power_off();
  } else if (syscall_num == SYS_EXEC) {
    // error-check that args[1] is a string located in valid user memory && the argument address is in valid user memory
    if (!is_pointer_valid((void*)args) || !is_pointer_valid((void*)(args + 1)) ||
        !is_string_valid((void*)args[1])) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    char* cmd = (char*)args[1];
    int child_pid = process_execute(cmd);
    if (child_pid == -1) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      f->eax = -1;
      process_exit();
    }
    shared_status_t* shared = get_shared_struct(child_pid);
    f->eax = shared->exit_code;
    return;
  } else if (syscall_num == SYS_WAIT) {
    // QUESTION: todo as per gradescope design doc rubric: Error-check that args[1] argument address is in valid user memory. BUT isn't args[1] just an int???
    int exit_code = process_wait(args[1]);
    f->eax = exit_code;
    return;
    /** FILE OPERATION SYSCALLS (below) **/
  } else if (syscall_num == SYS_WRITE) { /** FILE OPERATION SYSCALLS **/
    int fd = args[1];
    if (!is_pointer_valid((void*)args[2])) {
      f->eax = -1;
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
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
  } else { // syscall DNE
    printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
    process_exit();
  }
}