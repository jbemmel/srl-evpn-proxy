#!/usr/bin/env python3  # Originally python2

# Sample from https://www.collabora.com/news-and-blog/blog/2019/05/14/an-ebpf-overview-part-5-tracing-user-processes/
# Python program with embedded C eBPF program

from bcc import BPF, USDT
import sys

bpf = """
#include <uapi/linux/ptrace.h>
BPF_PERF_OUTPUT(events);
struct file_transf {
    char client_ip_str[20];
    char file_path[300];
    u32 file_size;
    u64 timestamp;
};
int trace_file_transfers(struct pt_regs *ctx, char *ipstrptr, char *pathptr, u32 file_size) {
    struct file_transf ft = {0};
    ft.file_size = file_size;
    ft.timestamp = bpf_ktime_get_ns();
    bpf_probe_read(&ft.client_ip_str, sizeof(ft.client_ip_str), (void *)ipstrptr);
    bpf_probe_read(&ft.file_path, sizeof(ft.file_path), (void *)pathptr);
    events.perf_submit(ctx, &ft, sizeof(ft));
    return 0;
};
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("{0}: {1} is downloding file {2} ({3} bytes)".format(
    event.timestamp, event.client_ip_str, event.file_path, event.file_size))

u = USDT(pid=int(sys.argv[1]))
u.enable_probe(probe="file_transfer", fn_name="trace_file_transfers")
b = BPF(text=bpf, usdt_contexts=[u])
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
