
//#include <uapi/linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>


SEC("kprobe/__seccomp_filter")
int bpf_prog1(struct pt_regs *ctx)
{
    const char msg[] = {'h', 'e', 'l', 'l', 'o', ' ', 'b', 'p', 'f', '\n', 0};
 
    bpf_trace_printk(msg, sizeof(msg));

	return 0;
}

char _license[] SEC("license") = "GPL";

