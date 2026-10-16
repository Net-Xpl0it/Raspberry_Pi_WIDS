# Detection rules

All rules are deterministic thresholds with hold timers. No training data, no models. Every value below is a constant at the top of `real_time_capture.py`.

## Configuration

| Constant | Default | Meaning |
|---|---|---|
| `IFACE` | `wlan1` | monitor-mode interface |
| `DEAUTH_THRESHOLD` | 2 | deauth frames in a 1 s sliding window that count as a flood |
| `DEAUTH_HOLD_SEC` | 3 | `DEAUTH` clears this long after the last flood frame |
| `BEACON_WINDOW_SEC` | 10 | sliding window for counting unique beaconing BSSIDs |
| `BEACON_UNIQUE_BSSID_THRESHOLD` | 15 | unique BSSIDs in the window that count as beacon spam |
| `TRUSTED_APS` | placeholder | `{SSID: [trusted BSSIDs]}`; only these SSIDs are protected |
| `ROGUE_HOLD_SEC` | 30 | `EVIL_TWIN` clears this long after the last rogue frame |
| `PROBE_THRESHOLD` | 3 | probe requests from one MAC per window that count as a hit |
| `PROBE_WINDOW_SEC` | 1 | probe counting window |
| `SNIFFER_PERSIST_SEC` | 30 | `PCAP_SNIFF` stays on this long after the last hit |
| `IGNORE_MACS` | empty | extra MACs never flagged as sniffers |
| `IGNORE_OWN_MACS` | `True` | also ignore every interface MAC of the Pi itself |

## Frame fields (tshark)

| Field | Use |
|---|---|
| `wlan.fc.type_subtype` | `0x000c` deauth, `0x0008` beacon, `0x0005` probe response, `0x0004` probe request |
| `wlan.sa` | transmitter MAC (reported as the source in deauth events) |
| `wlan.bssid` | AP identity for the beacon and Evil Twin rules |
| `wlan.ssid` | network name (hex in tshark output, decoded by the engine) |
| `radiotap.dbm_antsignal` | signal strength, captured for future use |

## DEAUTH

- **Fires** when `DEAUTH_THRESHOLD` or more deauth frames arrive within 1 s. With the optional event log on, one `FIRED` line is written per flood.
- **Clears** `DEAUTH_HOLD_SEC` after the last flagged frame. The `CLEARED` line gives the flood duration, the frames counted after detection, and the peak frames per second.
- The dashboard's rolling event feed (`wifi_log.json`) gets one entry per flagged frame; the permanent log does not, so a flood of ~90 frames/s cannot bury other events.
- **Known false positives:** a legitimate AP restart or client roaming can send a few deauths. The default is deliberately sensitive; raise `DEAUTH_THRESHOLD` on busy networks.

## BEACON

- Counts only beacons (`0x0008`); probe responses are not counted.
- Every second, BSSIDs not heard in the last `BEACON_WINDOW_SEC` are dropped and the unique count is compared with the threshold.
- **Fires** on the rising edge (`FIRED`, with the unique count) and **clears** when the count drops below the threshold (`CLEARED`, with the duration and peak count).
- The threshold must sit above the number of real APs you can hear. On the author's network the ambient count stayed under 15 for a 17-minute run; the only event was a flood of 164 unique BSSIDs in 10 s.

## EVIL_TWIN

- Looks at beacons and probe responses, since both advertise an SSID.
- **Fires** when the SSID is a key in `TRUSTED_APS` and the BSSID is not in its list. One `FIRED` line names the rogue BSSID and the frame type.
- **Clears** `ROGUE_HOLD_SEC` after the last rogue frame. The `CLEARED` line lists the rogue BSSIDs, frame count and how long the rogue was heard.
- List **every** BSSID of your own AP (each band, mesh node, guest network that reuses the SSID).
- **Limitation:** an attacker who spoofs your router's BSSID as well is not detected. Detecting that needs sequence-number or signal-strength analysis, which is future work.

## PCAP_SNIFF (Scapy thread)

- Counts probe requests per source MAC in `PROBE_WINDOW_SEC` windows. A MAC at or above `PROBE_THRESHOLD` is a **hit**: one `HIT` line per MAC per window.
- The detector is **on** while any MAC was a hit within `SNIFFER_PERSIST_SEC`. `FIRED` and `CLEARED` mark the transitions.
- MACs in `IGNORE_MACS`, and (by default) every interface MAC of the Pi, are never counted. This matters: in the first 17-minute run, 11 of 16 sniffer events came from the sensor's own `wlan0` probing for saved networks.
- **Known false positives:** phones send probe bursts when the screen wakes or Wi-Fi is toggled, often from randomised MACs (a locally-administered address, second hex digit 2, 6, a or e). Raise `PROBE_THRESHOLD` in crowded places.

## Why hold timers

Management-frame attacks arrive in bursts. Without hold timers a detector would flip on and off with every gap between bursts, and the dashboard would show a flickering state. The timers turn bursts into one alert with a start and an end, which is also what the permanent log records.
