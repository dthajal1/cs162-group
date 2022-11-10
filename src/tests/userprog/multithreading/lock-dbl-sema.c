/* Ensures two acquire and releases that happen interwovenly along with semaphores passes */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  lock_t lock;
  lock_t lock2;
  sema_t sema;
  lock_check_init(&lock);
  lock_check_init(&lock2);
  lock_acquire(&lock);
  lock_acquire(&lock2);
  sema_check_init(&sema, 0);
  sema_up(&sema);
  sema_down(&sema);
  lock_release(&lock);
  lock_release(&lock2);
  msg("PASS");
}
