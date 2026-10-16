# Engine run of 13 October 2026 (rolling log)

| Field | Value |
|---|---|
| Date and time | 2026-10-13, 01:20–01:37 BST (05:50–06:07 IST) |
| Evidence type | LIVE |
| Detectors | BEACON, PCAP_SNIFF |
| Source | `wifi_log.json`, saved when the engine stopped (masked copy: [data/2026-10-13_wifi_log_masked.json](data/2026-10-13_wifi_log_masked.json)) |
| Engine version | before the permanent event log and the own-MAC allowlist were added |
| Thresholds | defaults (deauth ≥ 2/s, beacon ≥ 15 unique BSSIDs in 10 s, probe ≥ 3/s) |

The file holds 17 events, well under its 50-event cap, so it is the complete event history of that run: 16 `PCAP_SNIFF`, 1 `BEACON`, and no `DEAUTH` or `EVIL_TWIN`. All times are the Pi's clock at the time (BST).

## BEACON

| Time | Detail |
|---|---|
| 01:32:41 | 164 unique BSSIDs in 10 s |

The threshold is 15, so the count was about 11 times higher. It was the only `BEACON` event in 17 minutes, so the ambient count stayed under 15 for the rest of the run. The result is consistent with a beacon flood. **TODO:** note which tool and mode caused it; it was not recorded.

## PCAP_SNIFF

| Source (masked) | Events | Probes/s | Identity |
|---|---|---|---|
| `2c:cf:67:xx:xx:xx` | 11 | 3–8 | **the sensor's own `wlan0`** (its MAC was confirmed with `cat /sys/class/net/wlan0/address`) |
| `02:00:00:xx:xx:xx` | 2 | 3 | a locally-administered placeholder address |
| `92:e2:23:xx:xx:xx` | 2 (two different addresses) | 5, 7 | randomised MACs sharing a prefix, likely one phone |
| `4e:b0:e1:xx:xx:xx` | 1 | 23 | randomised MAC, a single burst of 23 probes in one second |

## Findings

1. **False positive found and fixed.** 11 of the 16 sniffer events were the Pi's own built-in Wi-Fi probing for saved networks. The engine now ignores every interface MAC of the Pi (`IGNORE_OWN_MACS`).
2. The remaining events are normal client probing (phones waking, Wi-Fi toggles). A probe-rate rule cannot tell a curious phone from a sniffer, which is why the threshold is configurable ([docs/DETECTION_RULES.md](../docs/DETECTION_RULES.md)).
3. This run has no `DEAUTH` or `EVIL_TWIN` events, so it is not evidence for those detectors.
