// +build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct event {
  u8 pathname[128];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct execve_args *ctx) {
  struct event event;
  char *pathname;
  long res = bpf_probe_read(&pathname, sizeof(pathname), &ctx->filename);
  if (res != 0) return 0;

  __builtin_memset(&event, 0, sizeof(event));
  char buf[128];
  bpf_probe_read_str(buf, sizeof(buf), pathname);
  bpf_probe_read(&event.pathname, sizeof(event.pathname), buf);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  return 0;
}
