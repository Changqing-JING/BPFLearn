#define __TARGET_ARCH_x86

#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include <linux/bpf.h>

#include <bpf/bpf_tracing.h>

#include <asm/ptrace.h>
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);         /* class; u32 required */
  __type(value, __u32);       /* count of mads read */
  __uint(max_entries, 1024U); /* Room for all Classes */
} my_map SEC(".maps");

SEC("uprobe///lib/x86_64-linux-gnu/libc.so.6:printf")
int bpf_prog1(struct pt_regs *ctx) {
  char fmt[20];
  void *address = (void *)PT_REGS_PARM1(ctx);
  int res = bpf_probe_read(&fmt, sizeof(fmt), address);
  bpf_printk("printf called with address %lx, res %d, format string: %s\n",
             (unsigned long)address, res, fmt);
  return 0;
}
char _license[] SEC("license") = "GPL";
