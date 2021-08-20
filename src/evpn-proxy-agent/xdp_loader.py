#!/usr/bin/env python3

#
# To run: ip netns exec srbase-default python3 ./xdp_loader.py
#

from bcc import BPF

# device = "e1-1.0" # Spine facing interface in srbase-default
device = "mgmt0.0" # for debugging with ping

bpf = BPF(src_file="arpnd_filter.c")
fn = bpf.load_func("arpnd_filter", BPF.XDP)
bpf.attach_xdp(device, fn, 0)

# process ARP events from XDP kernel program
def print_arp_event(cpu, data, size):
    arp_event = bpf["events"].event(data)
    print( f"Userspace got ARP event: {arp_event}" )

# loop with callback to print_event
bpf["events"].open_perf_buffer(print_arp_event)
while 1:
    bpf.perf_buffer_poll()

    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields( nonblocking=True )
        print( f'trace_fields: {msg}' )
    except ValueError:
        continue

# Wait for KeyboardInterrupt? Cannot access /sys/kernel/debug/tracing/trace_pipe inside SRL netns
#try:
  # BPF.trace_print() performs a blocking read on the kernel's trace buffer file (/sys/kernel/debug/tracing/trace_pipe)
#  bpf.trace_print()
#except KeyboardInterrupt:
#  pass

bpf.remove_xdp(device, 0)
