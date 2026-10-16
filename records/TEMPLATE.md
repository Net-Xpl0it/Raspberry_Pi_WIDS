# <Test name>

| Field | Value |
|---|---|
| Date and time | YYYY-MM-DD HH:MM–HH:MM, timezone |
| Evidence type | LIVE / SOFTWARE / MEASUREMENT |
| Detector(s) | DEAUTH / BEACON / EVIL_TWIN / PCAP_SNIFF |
| Engine version | `git rev-parse --short HEAD` |
| Thresholds | from the `ENGINE START` line of `wifi_events.jsonl` (if the event log was on), else the defaults |
| Attack tool and mode | |
| Target | own router / own device only |

## Procedure

What was done, in order, and for how long.

## Result

| Event | Time | Detail |
|---|---|---|
| FIRED | | |
| CLEARED | | |

Time to fire: ___ s after the attack started. Time to clear: ___ s after it stopped.

## Evidence

- Log excerpt (masked): `data/<file>`
- Screenshot: `docs/images/<file>`

## Notes

False positives, surprises, anything that limits what this result proves.
