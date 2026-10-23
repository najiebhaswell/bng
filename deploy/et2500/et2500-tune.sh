#!/bin/bash
# Keep CPU0 for housekeeping (management, the CPLD watchdog, the BNG control
# plane), so overload cannot starve them and get the board reset:
#  - RSS spreads traffic over RX queues 1-7 only (queue 0 stays idle). The
#    queue count stays 8: the driver picks the XDP TX queue by CPU number.
#  - The IRQ of queue i goes to CPU i, so NAPI (softirq, which runs where
#    its IRQ fired) never runs on CPU0.
# Threaded NAPI would also do, but costs ~10-15% of the packet rate here.
# Run after the BNG has attached its XDP programs, which re-creates queues.
set -e
for p in Ethernet12 Ethernet13; do
  # The SMMU defaults to strict mode: every DMA unmap (each packet sent with
  # XDP_REDIRECT) waits for an IOTLB invalidation, ~40% of the packet CPU.
  # Lazy invalidation (flush queue) can be switched to at runtime.
  t="/sys/class/net/$p/device/iommu_group/type"
  [ "$(cat "$t")" = DMA ] && echo DMA-FQ > "$t"
  ethtool -X "$p" weight 0 1 1 1 1 1 1 1
  # Bigger interrupt batches: each NAPI poll reads the CQ status with a slow
  # MMIO atomic, so fewer, fuller polls (the driver caps usecs at 25)
  ethtool -C "$p" rx-usecs 25 rx-frames 64 tx-usecs 25 tx-frames 64
  echo 0 > "/sys/class/net/$p/threaded"
  for irq in $(awk -v q="$p-rxtx-" "index(\$NF, q) == 1 {sub(\":\", \"\", \$1); print \$1}" /proc/interrupts); do
    q=$(awk -v i="$irq:" "\$1 == i {n = split(\$NF, a, \"-\"); print a[n]}" /proc/interrupts)
    echo "$q" > "/proc/irq/$irq/smp_affinity_list"
  done
done
echo "CPU0 reserved: RSS on queues 1-7, IRQ of queue i on CPU i; coalescing 25us/64; IOMMU $(cat /sys/class/net/Ethernet12/device/iommu_group/type)"
