#!/usr/bin/env python3

from bcc import BPF

device = "lo"
bpf = BPF(src_file="arpnd_filter.c")
fn = bpf.load_func("arpnd_filter", BPF.XDP)
bpf.attach_xdp(device, fn, 0)

# Wait for KeyboardInterrupt
try:
  b.trace_print()
except KeyboardInterrupt:
  pass

bpf.remove_xdp(device, 0)
