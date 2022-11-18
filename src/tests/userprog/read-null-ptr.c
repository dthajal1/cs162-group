/* Passes a null pointer to the read system call.
   The process must be terminated with -1 exit code. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle;
  CHECK((handle = open("sample.txt")) > 1, "open \"sample.txt\"");

  read(handle, NULL, 123);
  fail("should not have survived read()");
}
