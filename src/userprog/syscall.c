#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "devices/shutdown.h"
#include "lib/float.h"

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

  // validate args
  int syscall_num = args[0];
  switch (syscall_num) {
    case SYS_PRACTICE:
      int i = args[1];
      f->eax = i + 1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXEC:
    // fixme cuz need to add synchronization / locking logic; parent cannot return until child proc successfuly exits
    // parent thread = thread_current(), parent thread id = thread_tid()
      char *cmd_line = args[1];
      process_execute(cmd_line);
      break;
    case SYS_WAIT:
      pid_t child_pid = args[1];
      process_wait(child_pid);
      break;
    case SYS_EXIT:
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
    default:
      break;
  }
}
