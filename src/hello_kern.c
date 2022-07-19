#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include <linux/bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);         /* class; u32 required */
  __type(value, __u32);       /* count of mads read */
  __uint(max_entries, 1024U); /* Room for all Classes */
} my_map SEC(".maps");

SEC("kprobe/__seccomp_filter")

int bpf_prog1(struct pt_regs *ctx) {
  __u32 const key = 0;

  __u32 *val = bpf_map_lookup_elem(&my_map, &key);
  if (val != NULL) {
    *(val) += 1U;
    bpf_map_update_elem(&my_map, &key, val, BPF_ANY);
  }

  const char msg[] = {'h', 'e', 'l', 'l', 'o', ' ', 'b', 'p', 'f', '\n', 0};

  bpf_trace_printk(msg, sizeof(msg));

  return 0;
}

char _license[] SEC("license") = "GPL";
