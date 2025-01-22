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
  char fmt[256];
  void *address = (void *)ctx->rdi;
  bpf_probe_read_user(&fmt, sizeof(fmt), address);
  bpf_printk("printf called with address %p, format string: %s\n", address,
             fmt);
  return 0;
}
char _license[] SEC("license") = "GPL";
