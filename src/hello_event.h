#pragma once

#include <linux/types.h>

struct hello_event {
  __u32 pid;
  __u32 count;
  char message[10];
};