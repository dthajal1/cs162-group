#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(char* file_name, void (**eip)(void), void** esp, int argc, char* argv[]);
bool setup_thread(void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Initialize global file lock. */
  lock_init(&file_lock);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  list_init(&t->pcb->children_shared_structs);
}

struct new_thread_arg_struct {
  char* cmd;
  shared_status_t* shared;
};

/* Initialize a shared struct for this current process & the given child process. 
@returns NULL if errored. */
static shared_status_t* shared_struct_init(void) {
  shared_status_t* shared = (shared_status_t*)malloc(sizeof(shared_status_t));
  if (shared == NULL)
    return NULL;
  sema_init(&shared->sema, 0);
  lock_init(&shared->ref_lock);
  shared->exit_code = 0;
  shared->exited = false;
  shared->already_waiting = false;
  shared->ref_cnt = 2; // ??? right? do we init as 2???

  return shared;
}

/* Helper fxn to decrement ref cnt while acquiring lock. */
static void decrement_ref_cnt(shared_status_t* shared) {
  lock_acquire(&shared->ref_lock);
  shared->ref_cnt--;
  lock_release(&shared->ref_lock);
  if (shared->ref_cnt == 0) { // If ref_cnt = 0, free shared struct
    list_remove(&shared->shared_elem);
    free(shared);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(char* cmd) {
  char* cmd_copy;
  tid_t tid;

  sema_init(&temporary, 0);
  /* Make a copy of CMD.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page(0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy(cmd_copy, cmd, PGSIZE);
  /* Make a copy of CMD.
     To use for strtok LOL. */
  char* cmd_copy2 = palloc_get_page(0);
  if (cmd_copy2 == NULL)
    return TID_ERROR;
  strlcpy(cmd_copy2, cmd, PGSIZE);

  char* saveptr;
  char* file_name = strtok_r(cmd_copy2, " ", &saveptr);

  shared_status_t* shared = shared_struct_init();
  list_push_back(&thread_current()->pcb->children_shared_structs, &shared->shared_elem);

  struct new_thread_arg_struct args;
  args.cmd = cmd_copy;
  args.shared = shared;

  /* Create a new thread to execute CMD. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, &args);
  if (tid == TID_ERROR) {
    palloc_free_page(cmd_copy);
    decrement_ref_cnt(shared);
  }

  /* Set the shared's PID, then WAIT. Will end wait when loaded. */
  shared->child_pid = tid; // QUESTION11: IS TID == PID HERE LOL
  sema_down(&shared->sema);
  if (shared->failed_load) {
    // decrement_ref_cnt(shared); // SHOLD WE DECREMENT REF CNT IF FAILED?
    return TID_ERROR; // could not load cmd
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* arguments) {
  struct new_thread_arg_struct* args = (struct new_thread_arg_struct*)arguments;
  char* cmd = args->cmd;
  shared_status_t* shared = args->shared;

  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success, fd_tbl_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  if (strcmp(cmd, "") == 0 || cmd == NULL) {
    success = false;
  }

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    /* Initialize file descriptor table, its entries and next_fd. */
    t->pcb->fd_table = (struct fd_table*)malloc(sizeof(struct fd_table));
    if (t->pcb->fd_table == NULL) {
      fd_tbl_success = false;
    } else {
      fd_tbl_success = true;
      list_init(&(t->pcb->fd_table->fd_entries));
      t->pcb->fd_table->next_fd = 3; // 0, 1, 2 reserved for Standard FDs
    }

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    list_init(&t->pcb->children_shared_structs);
    t->pcb->my_shared_status = shared;
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    uint8_t curr_fpu[108];
    asm volatile("fsave (%0); fninit; fsave (%1)" : : "g"(&curr_fpu), "g"(&if_.fpu_registers));
    asm volatile("frstor (%0)" : : "g"(&curr_fpu));

    // Parse thru file_name
    int argc = 0;
    size_t argv_size = 2; // Init to default size of 2
    char** argv = (char**)malloc(argv_size * sizeof(char*));
    char** temp;
    if (argv == NULL) {
      success = false;
    }

    if (success) {
      char* saveptr;

      for (char* token = strtok_r(cmd, " ", &saveptr); token != NULL;
           token = strtok_r(NULL, " ", &saveptr)) {

        if (argc == argv_size) {
          // Reallocate argv array size
          argv_size *= 2;
          temp = realloc(argv, argv_size * sizeof(char*));
          if (temp == NULL) {
            free(argv);
            success = false;
            break;
          } else {
            argv = temp;
          }
        }
        argv[argc] = (char*)malloc(sizeof(char) * (strlen(token) + 1));
        if (argv[argc] == NULL) {
          free(argv);
          success = false;
          break;
        }
        strlcpy(argv[argc], token, strlen(token) + 1);
        argc++;
      }

      // Load executable
      if (success) {
        success = load(cmd, &if_.eip, &if_.esp, argc, argv);
      }
    }
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // on failure to load executable file, allow write on them again
    file_close(t->pcb->exec_file);

    // free fd_table
    if (fd_tbl_success) {
      struct fd_table* fd_tbl_to_free = t->pcb->fd_table;
      t->pcb->fd_table = NULL;
      free(fd_tbl_to_free);
    }

    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(cmd);
  if (!success) {
    shared->failed_load = true;
    decrement_ref_cnt(shared);
    sema_up(&shared->sema);
    sema_up(&temporary);
    thread_exit();
  }

  /* End process_execute's waiting before jumping to userspace. */
  sema_up(&shared->sema);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Helper func to get the shared struct from a child pid. 
Returns NULL if DNE. */
shared_status_t* get_shared_struct(pid_t child_pid) {
  struct list* children = &thread_current()->pcb->children_shared_structs;
  // get matching child shared struct via children list of shared structs
  struct list_elem* e;
  for (e = list_begin(children); e != list_end(children); e = list_next(e)) {
    shared_status_t* shared = list_entry(e, shared_status_t, shared_elem);
    if (shared->child_pid == child_pid)
      return shared;
  }

  return NULL;
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  shared_status_t* child_shared = get_shared_struct(child_pid);
  if (child_shared == NULL) {
    // could not find child from this parent
    return -1;
  } else if (child_shared->already_waiting) {
    // error if this process has already called process_wait on this child
    return -1;
  }
  child_shared->already_waiting = true;
  sema_down(&child_shared->sema);
  child_shared->already_waiting = false;
  int exit_code = child_shared->exit_code;

  decrement_ref_cnt(child_shared);

  return exit_code;
  // return 0;
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Clean up shared thread scheduling logic, free shared if ref_cnt=0 */
  shared_status_t* shared = cur->pcb->my_shared_status;
  shared->exit_code = exit_code;
  shared->exited = true;
  sema_up(&shared->sema);
  decrement_ref_cnt(shared);

  /* Clean up fd_table of this process if it exists. */
  if (cur->pcb->fd_table != NULL) {
    struct fd_table* fd_tbl_to_free = cur->pcb->fd_table;

    while (!list_empty(&(fd_tbl_to_free->fd_entries))) {
      struct list_elem* e = list_pop_front(&(fd_tbl_to_free->fd_entries));
      struct fd_entry* entry = list_entry(e, struct fd_entry, elem);
      file_close(entry->file);
      free(entry);
    }

    cur->pcb->fd_table = NULL;
    free(fd_tbl_to_free);
  }

  // Close excetuable file and set it to be modifiable
  file_close(cur->pcb->exec_file);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  sema_up(&temporary);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, int argc, char* argv[]);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(char* file_name, void (**eip)(void), void** esp, int argc, char* argv[]) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* save exec_file so we can allow write on them when process exits or if load fails. */
  t->pcb->exec_file = file;

  /* Running executables shouldn't be modified. */
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  argv[0] = file_name;
  if (!setup_stack(esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  // file_close(file); // want to move this to process_exit to support lazy loading
  /* "because an operating system may load code pages from the file lazily, or may page 
    out some code pages and reload them from the file later." -- 162 Pintos Doc */

  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, int argc, char* argv[]) {
  uint8_t* kpage;
  bool success = false;
  char** stack_ptr = (char**)esp;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *stack_ptr = PHYS_BASE;
      // ADDDRESSES:
      // [0...argc-1] for args' addresses
      // [argc] for NULL ptr
      // [argc+1] for address of argv itself
      char** addresses = (char**)malloc(
          (argc + 2) *
          sizeof(char*)); // one extra space for null at the end, one extra for beginning of argv
      addresses[argc] = NULL;
      for (int i = argc - 1; i >= 0; i--) {
        *stack_ptr -= (strlen(argv[i]) + 1);
        memset(*stack_ptr + strlen(argv[i]), 0, 1);
        memcpy(*stack_ptr, argv[i], strlen(argv[i]));
        memcpy(&addresses[i], stack_ptr, sizeof *stack_ptr);
      }

      // stack align (account for all args plus null pointer and argv/argc)
      // Stack align the stack pointer by decrementing esp such that the pointer will be at 16 -
      // byte boundary by the time it pushes on argv and argc.
      while ((int)(*stack_ptr - (argc + 3) * 4) % 16 != 0) {
        *stack_ptr -= 1;
      }

      // Iteratively push the values of `addresses` onto the stack from last to first, decrementing `esp` by 4 each time.
      for (int j = argc; j >= 0; j--) {
        *stack_ptr -= 4;
        char* address = addresses[j];
        memcpy(*stack_ptr, &address, 4);
      }
      addresses[argc + 1] = *stack_ptr;

      *stack_ptr -= 12;
      memmove(*stack_ptr + 8, &addresses[argc + 1],
              4);                       // set argv (location of argv[0] on the stack)
      memcpy(*stack_ptr + 4, &argc, 4); // set argc
      memset(*stack_ptr, 0, 4);         // set return

      free(addresses);
      free(argv);
    } else {
      palloc_free_page(kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}