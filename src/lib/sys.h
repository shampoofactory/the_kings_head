#ifndef SYS_H_052964A747A7197B
#define SYS_H_052964A747A7197B

#include <stdint.h>

void sys_exit(int32_t status);

uint64_t sys_print(const char *str, uint32_t len);

uint64_t sys_write(uint32_t fd, const uint8_t *buf, uint64_t count);

uint64_t sys_time();

#endif