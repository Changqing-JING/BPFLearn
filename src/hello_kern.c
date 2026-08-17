#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include <linux/bpf.h>

#include "hello_event.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);         /* class; u32 required */
  __type(value, __u32);       /* count of mads read */
  __uint(max_entries, 1024U); /* Room for all Classes */
} my_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1U << 24);
} events SEC(".maps");

SEC("kprobe/__seccomp_filter")

int bpf_prog1(struct pt_regs *ctx) {
  __u32 const key = 0;

  __u32 *val = bpf_map_lookup_elem(&my_map, &key);
  if (val != NULL) {
    *(val) += 1U;
    bpf_map_update_elem(&my_map, &key, val, BPF_ANY);
  }

  struct hello_event *event =
      bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event != NULL) {
    event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event->count = val != NULL ? *val : 0;
    event->message[0] = 'h';
    event->message[1] = 'e';
    event->message[2] = 'l';
    event->message[3] = 'l';
    event->message[4] = 'o';
    event->message[5] = ' ';
    event->message[6] = 'b';
    event->message[7] = 'p';
    event->message[8] = 'f';
    event->message[9] = '\n';
    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
