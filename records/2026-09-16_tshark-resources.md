# tshark resource usage (30-second sample)

| Field | Value |
|---|---|
| Date and time | 2026-09-16, 03:43 BST (08:13 IST) |
| Evidence type | MEASUREMENT |
| Process measured | `tshark` only (not the Python engine, Scapy thread or dashboard) |
| Traffic | idle sensor, no attack running |
| Source | `tshark_load.log` (`top` snapshots plus a `ps` sample once per second for 30 s) |

## Result

| Measure | Value |
|---|---|
| Resident memory | 156,016 KiB (≈ 152 MiB), 4.0 % of RAM; 156,300 KiB at the end |
| Virtual memory | 583,836 KiB (≈ 570 MiB); 588,540 KiB at the end |
| CPU time used | 0.57 s in total |
| Average CPU (`ps`, since start) | 54.2 % at 1 s, falling to 1.9 % at 30 s |
| CPU in the `top` snapshots | 0.0 % |

## Reading the numbers

`ps` reports CPU as a running average since the process started, so the falling figure is a short startup burst (0.57 s of CPU) followed by an almost idle process. It is not a load that eased off. The first two samples in the source (200 % and 300 % at 0 s elapsed) are artifacts of dividing by a near-zero elapsed time and are ignored.

## Limits

This measures tshark alone, with no attack in progress. The whole engine under attack has not been measured. **TODO:** `top -b -d 2 -n 30 | grep -E "python3|tshark"` with the engine running, ideally also during an attack. The exact tshark command line used for this run was not recorded.
