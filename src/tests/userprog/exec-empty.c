/* This test invokes the exec system call and makes sure that  */

#include <syscall-nr.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) { msg("exec(\"\"): %d", exec("")); }