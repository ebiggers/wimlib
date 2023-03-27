#define ENABLE_TEST_SUPPORT 1
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <wimlib.h>
#include <wimlib/test_support.h>

bool
setup_fault_nth(const uint8_t **in, size_t *insize, uint16_t *fault_nth);
