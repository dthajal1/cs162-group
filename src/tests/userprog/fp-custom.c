/* Tests compute-e validation to ensure it does not calculate the value when the input is negative */

#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FPU_SIZE 108

void test_main(void) {
  test_name = "fp-custom";
  double invalid_negative;
  invalid_negative = compute_e(-97);
  if (invalid_negative >= 1) {
    msg("Failure: Should error but instead was valid");
    exit(126);
  } else {
    msg("Success!");
    exit(162);
  }
}
