#include "DiemSecretMemory.h"

void diem_clear(void *buffer, size_t count) {
  volatile unsigned char *p = (volatile unsigned char *)buffer;
  while (count--) *p++ = 0;
}
