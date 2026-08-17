// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "hello_event.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <filesystem>
#include <stdexcept>

static int handle_event(void *, void *data, size_t dataSize) {
  if (dataSize != sizeof(hello_event)) {
    fprintf(stderr, "ERROR: unexpected ring buffer sample size\n");
    return 0;
  }

  auto const *event = static_cast<const hello_event *>(data);
  printf("pid %u: %.*s count %u\n", event->pid,
         static_cast<int>(sizeof(event->message) - 1), event->message,
         event->count);
  return 0;
}

int main(int ac, char **argv) {
  struct bpf_link *link = NULL;
  struct ring_buffer *ringBuffer = NULL;

  struct bpf_object *obj = NULL;

  try {
    std::filesystem::path const execPath(argv[0]);

    std::filesystem::path const filename = execPath.filename();

    std::filesystem::path const bpfname =
        execPath.parent_path() / (filename.string() + "_kern.o");

    obj = bpf_object__open_file(bpfname.c_str(), NULL);
    if (libbpf_get_error(obj)) {
      fprintf(stderr, "ERROR: opening BPF object file failed\n");
      return 0;
    }

    struct bpf_program *const prog =
        bpf_object__find_program_by_name(obj, "bpf_prog1");
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

    int const eventFd = bpf_object__find_map_fd_by_name(obj, "events");
    if (eventFd < 0) {
      throw std::runtime_error("bpf_object__find_map_fd_by_name failed");
    }

    ringBuffer = ring_buffer__new(eventFd, handle_event, NULL, NULL);
    if (ringBuffer == NULL) {
      throw std::runtime_error("ring_buffer__new failed");
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

    int32_t error;

    error = bpf_map_update_elem(mapFd, &key, &value, BPF_ANY);

    if (error != 0) {
      throw std::runtime_error("bpf_map_update_elem failed");
    }

    while (true) {
      int const pollResult = ring_buffer__poll(ringBuffer, 100);
      if (pollResult < 0 && pollResult != -EINTR) {
        throw std::runtime_error("ring_buffer__poll failed");
      }

      error = bpf_map_lookup_elem(mapFd, &key, &value);

      if (error != 0) {
        throw std::runtime_error("bpf_map_lookup_elem failed");
      }

      printf("bpf_map_lookup_elem get value %d\n", value);
    }

  }

  catch (const std::exception &exception) {
    fprintf(stderr, "ERROR: %s\n", exception.what());
    ring_buffer__free(ringBuffer);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 1;
  }

  catch (...) {
    fprintf(stderr, "ERROR: unknown failure\n");
    ring_buffer__free(ringBuffer);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 1;
  }
  return 0;
}
