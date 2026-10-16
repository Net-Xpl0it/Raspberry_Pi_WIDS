# Test log

| # | Date | Type | Detector | Result | Record |
|---|---|---|---|---|---|
| 1 | 2026-09-16 | MEASUREMENT | tshark process | ≈152 MiB resident, ≈1.9 % average CPU over 30 s, idle | [tshark resources](2026-09-16_tshark-resources.md) |
| 2 | 2026-10-13 | LIVE | BEACON | fired: 164 unique BSSIDs in 10 s (threshold 15) | [engine run](2026-10-13_engine-run.md) |
| 3 | 2026-10-13 | LIVE | PCAP_SNIFF | 16 events; 11 were the sensor's own `wlan0` (false positive, fixed) | [engine run](2026-10-13_engine-run.md) |
| 4 | TODO | LIVE | DEAUTH | detected (photo); no log lines | [live demo](live-demo-hackcat.md) |
| 5 | TODO | LIVE | EVIL_TWIN | detected (photo); no log lines | [live demo](live-demo-hackcat.md) |
| 6 | TODO | LIVE | PCAP_SNIFF | detected (photo); no log lines | [live demo](live-demo-hackcat.md) |
| 7 | TODO | LIVE | BEACON | detected (photo); no log lines | [live demo](live-demo-hackcat.md) |
| 8 | 2026-10-16 | SOFTWARE | all four | 11 / 11 checks passed (development machine) | [software test](2026-10-16_software-test.md) |

Environment and clock notes: [environment.md](environment.md).

## Open items

- Time to fire and time to clear under a live attack (rows 4–7 have no timings).
- A short live run with the optional event log on (`WIDS_EVENTS`), to get log lines for DEAUTH and EVIL_TWIN.
- CPU and memory of the whole engine, idle and under attack.
- A long idle run (hours) to count false positives.
- Dates of rows 4–7, tool and tshark/Python/Scapy/Streamlit versions ([environment.md](environment.md)).
- Re-run `tests/test_engine.py` on the Pi.
