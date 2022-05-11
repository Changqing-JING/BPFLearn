// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include "helper/trace_helpers.hpp"

int main(int ac, char **argv) {
  struct bpf_link *link = NULL;
  struct bpf_program *prog;
  struct bpf_object *obj;
  char filename[256];
  try {
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
      fprintf(stderr, "ERROR: opening BPF object file failed\n");
      return 0;
    }

    prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (!prog) {
      printf("finding a prog in obj file failed\n");
      throw std::runtime_error("bpf_object__find_program_by_name failed");
    }

    /* load BPF program */
    if (bpf_object__load(obj)) {
      fprintf(stderr, "ERROR: loading BPF object file failed\n");
      throw std::runtime_error("bpf_object__load failed");
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
      fprintf(stderr, "ERROR: bpf_program__attach failed\n");
      link = NULL;
      throw std::runtime_error("bpf_program__attach failed");
    }

    read_trace_pipe();
  }

  catch (...) {
    bpf_link__destroy(link);
    bpf_object__close(obj);
  }
  return 0;
}
