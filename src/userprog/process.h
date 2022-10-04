#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/** Shared status struct to help parent-child processes keep 
 * track of respective statuses **/
typedef struct shared_status {
  pid_t child_pid;
  struct semaphore* sema;

  int exit_code;
  bool exited;

  struct lock ref_lock;
  int ref_cnt;
} shared_status_t;

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  // Add synchronization for parent-child shared struct info
  struct list children;              // List of my children processes
  struct list_elem children_elem;    // List elem for this process to be in parents' list
  struct process* parent;            // Ptr to parent process
  shared_status_t* my_shared_status; // Ptr to MY shared_status_t w/ my parent
};

void userprog_init(void);

pid_t process_execute(const char* cmd);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

shared_status_t* get_shared_struct(pid_t);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
