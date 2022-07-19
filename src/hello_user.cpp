// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

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

    const char *mapName = "my_map";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, mapName);

    if (libbpf_get_error(map)) {
      throw std::runtime_error("bpf_object__find_map_by_name failed");
    }

    uint32_t const mapSize = bpf_map__max_entries(map);

    if (mapSize == 0) {
      throw std::runtime_error("wrong mapSize");
    }

    int32_t const mapFd = bpf_object__find_map_fd_by_name(obj, mapName);

    uint32_t key = 0;
    uint32_t value = 0;

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
      fprintf(stderr, "ERROR: bpf_program__attach failed\n");
      link = NULL;
      throw std::runtime_error("bpf_program__attach failed");
    }

    int32_t const trace_fd =
        open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0) {
      throw std::runtime_error("open trace_pipe failed\n");
    }

    int32_t error;

    error = bpf_map_update_elem(mapFd, &key, &value, BPF_ANY);

    if (error != 0) {
      throw std::runtime_error("bpf_map_update_elem failed");
    }

    while (true) {

      static char buf[4096];

      ssize_t const sz = read(trace_fd, buf, sizeof(buf) - 1);
      if (sz > 0) {
        buf[sz] = 0;
        puts(buf);
      }

      error = bpf_map_lookup_elem(mapFd, &key, &value);

      if (error != 0) {
        throw std::runtime_error("bpf_map_lookup_elem failed");
      }

      printf("bpf_map_lookup_elem get value %d\n", value);
    }

  }

  catch (...) {
    bpf_link__destroy(link);
    bpf_object__close(obj);
  }
  return 0;
}
