#include "filesys/file.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "lib/kernel/stdio.h"

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

  int syscall_num = args[0];
  if (syscall_num == SYS_EXIT) { /** PROCESS CONTROL SYSCALLS **/
    if (args[1] == NULL)
      process_exit();
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if (syscall_num == SYS_PRACTICE) {
    // todo: error check
    f->eax = args[1] + 1;
    return;
  } else if (syscall_num == SYS_WRITE) { /** FILE OPERATION SYSCALLS **/
    // todo: error check
    int fd = args[1];
    void* buf = (void*)args[2];
    size_t size = args[3];

    if (fd == 1) {       // STDOUT
      putbuf(buf, size); // q: should we put anything into eax register here? or just null lol
      f->eax = size;
    } else {
      // file* file; // todo: get file from fdt
      // off_t bytes_written = file_write(file, buf, size);
      // f->eax = bytes_written;
    }
    return;
  } else { // syscall DNE
    process_exit();
  }
}
