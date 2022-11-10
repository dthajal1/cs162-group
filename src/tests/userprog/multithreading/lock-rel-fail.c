/* Ensure release on uninitializezd lock fails */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  lock_t lock;
  lock_release(&lock);
  fail("Uninitialized release succeeded");
}