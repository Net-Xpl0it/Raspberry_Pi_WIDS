# Architecture

## Components

| Component | File | Role |
|---|---|---|
| Monitor-mode script | `scripts/monitor-mode.sh` | finds the AP's 2.4 GHz channel, switches `wlan1` to monitor mode, locks the channel |
| Detection engine | `real_time_capture.py` | two capture threads, shared state, writes the two output files |
| Dashboard | `dashboard.py` | Streamlit page that reads `wifi_log.json`; no capture logic |

The engine and the dashboard share nothing except a file, so the dashboard can be restarted without affecting detection.

## Data flow

```
monitor-mode.sh ──► wlan1 (monitor, locked channel)
                       │
         ┌─────────────┴──────────────┐
   tshark thread                 Scapy thread
   deauth / beacon / twin        probe requests
         └─────────────┬──────────────┘
                shared dict + RLock
                       │
   main loop, every 1 s: expire timers, write snapshot
                       │
          ┌────────────┴─────────────┐
   wifi_log.json  (replaced every second, last 50 events)
          │
   Streamlit dashboard (reads every 1 s)
```

## The tshark thread

Starts `tshark -i wlan1 -f "type mgt" -l -T fields` with five fields (subtype, source, BSSID, SSID, signal) and reads one tab-separated line per management frame. `-l` flushes every line so detection is real time. The thread keeps a 1 s window of deauth timestamps, a last-seen time per beaconing BSSID, and the time of the last rogue frame, and evaluates the beacon window once per second.

## The Scapy thread

Sniffs probe requests, counts them per source MAC in 1 s windows, and keeps a confirmed time per MAC for the persistence timer. It runs in its own thread, so probe counting never shares a read loop with the tshark rules.

## Shared state

One dict guarded by a re-entrant lock (`RLock`; a plain `Lock` deadlocked because the logging helper takes the lock inside code that already holds it). It holds the four detector flags, a few internal timers, and a 200-entry deque of recent events.

## Output files

**`wifi_log.json`** — live snapshot, rewritten every second:

```json
{
  "DEAUTH": 0, "BEACON": 0, "EVIL_TWIN": 0, "PCAP_SNIFF": 1,
  "events": [{"time": "2026-10-16 09:12:03", "type": "PCAP_SNIFF", "detail": "aa:bb:cc:xx:xx:xx sent 4 probes/1s"}],
  "updated": "2026-10-16 09:12:04"
}
```

Only the last 50 events are kept and the file is replaced on every engine start, so it is a live view, not a history.

**`wifi_events.jsonl`** (optional, off by default) — set `WIDS_EVENTS=/path/wifi_events.jsonl` to turn it on. One JSON object per line, appended and flushed to disk for every event:

| Field | Meaning |
|---|---|
| `ts` | ISO 8601 time with the local UTC offset, millisecond precision |
| `type` | `ENGINE`, `DEAUTH`, `BEACON`, `EVIL_TWIN`, `PCAP_SNIFF` |
| `state` | `START` / `STOP` (engine), `FIRED` / `CLEARED` (detectors), `HIT` (one probe burst) |
| `detail` | human-readable context: rates, counts, MACs, thresholds in use |

Use it for short, deliberate test runs. It is not meant to run continuously on this hardware (next section).

## Design constraints

The sensor is intentionally modest, and the design follows from that:

- **Storage.** The microSD card is a basic SanDisk card below Class 10, so small, frequent writes are slow and wear it. The engine therefore keeps no permanent log by default; the only output is the small `wifi_log.json`, replaced once a second. The append-only event log is opt-in.
- **Memory.** About 2.9 GB of RAM is free after the OS install, shared by tshark (≈152 MiB resident when sampled alone), the Python engine and the Streamlit dashboard. History is capped in memory (200 events in the engine, 50 in the snapshot) and raw packets are never stored.
- **CPU.** Every rule is a counter or a set lookup per frame, so the engine stays light on a Cortex-A72 core.
- **Optional, to spare the SD card:** point both programs at RAM-backed storage with `WIDS_LOG=/dev/shm/wifi_log.json` (set it for the engine and the dashboard). The snapshot then disappears on reboot, which is fine for a live view.

## Design decisions

- **Rules, not models.** Every alert can be explained from one threshold and one frame count, and the engine needs no training data.
- **Pinned BSSID in the monitor script.** The script accepts only the AP whose BSSID you give it, so an Evil Twin present during the channel scan cannot steer the sensor to another channel.
- **A scan failure never stops the engine.** The script falls back to the last known channel, so it is safe as a `systemd` `ExecStartPre`.
- **Fail loudly.** The dashboard goes dark with `ENGINE OFFLINE` if the log is older than 5 s.
- **One small live file.** A rolling snapshot for the dashboard; permanent evidence is optional and off by default.
- **Files next to the script.** Both output files default to the script's own folder, so the engine and dashboard agree no matter where you start them (override with `WIDS_LOG`).
