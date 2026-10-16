# Live demo with a HackCat (photos)

| Field | Value |
|---|---|
| Date | **TODO** (the photos show only the Pi clock; take the date from the photo files' metadata) |
| Evidence type | LIVE |
| Detectors | DEAUTH, EVIL_TWIN, PCAP_SNIFF, BEACON |
| Attack tool | HackCat, own network only |
| Evidence | four photos of the Pi touchscreen beside the HackCat |

## Observations

| Photo | Pi clock | HackCat screen | Dashboard |
|---|---|---|---|
| [live-deauth.png](../docs/images/live-deauth.png) | 08:57 | "Deauthing", red LED | Deauth Flood **DETECTED** and Probe Sniffer **DETECTED**; Beacon Spam and Evil Twin SECURE |
| [live-evil-twin.png](../docs/images/live-evil-twin.png) | 09:00 | "No HTML file selected" (a portal-mode screen, **TODO** confirm) | Evil Twin **DETECTED**; the other three SECURE |
| [live-probe-sniffer.png](../docs/images/live-probe-sniffer.png) | 09:01 | "CH: 3  Pkts: 10 Deauth" with a packet graph | Probe Sniffer **DETECTED**; the other three SECURE |
| [live-beacon-spam.png](../docs/images/live-beacon-spam.png) | 09:03 | "start broadcast" | Beacon Spam **DETECTED**; the other three SECURE |

In each photo the dashboard shows `ENGINE ONLINE` with a log age under a second.

## What this proves

All four detector cards were seen going to `DETECTED` on a live network, one at a time, while the tool was running. The cards returned to `SECURE` between attacks.

## What it does not prove

- **No log lines survive** from these runs. The engine keeps no permanent log by default, and the rolling `wifi_log.json` was overwritten by later engine starts. Time to fire and time to clear were not measured.
- The Probe Sniffer card can be triggered by ordinary phones as well as by the tool, so that photo does not show which device caused it.
- In the probe-sniffer photo the HackCat is on channel 3 (the AP's channel) showing a packet counter, and the Deauth card stayed SECURE, so it was probably not flooding at that moment. **TODO:** confirm what the tool was doing.

## Notes

- A phone near the tool lost cellular service while it was transmitting. Keep phones away and keep bursts short ([docs/TESTING.md](../docs/TESTING.md)).
- **TODO (optional):** repeat a short run with `WIDS_EVENTS` set to get log lines and timings.
