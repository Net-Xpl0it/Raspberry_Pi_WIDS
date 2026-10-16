# Testing

Results live in [`records/`](../records/TEST_LOG.md). This page explains how to produce them.

## Rules of engagement

- Test **only on your own network and devices**, or with written permission. Deauth and beacon floods disrupt every nearby device, and doing that to others is illegal in many places.
- Keep each attack to **10–15 seconds**. Every detector fires within about 1–2 seconds, so longer adds nothing but disruption.
- Use Ethernet for the Pi and the laptop that shows the dashboard; the attacks take Wi-Fi down.
- Keep phones away from the attack tool. During the author's tests a nearby phone lost cellular service while the tool was transmitting.

## Equipment

- The sensor: Pi + AR9271 in monitor mode, engine and dashboard running ([SETUP.md](SETUP.md)).
- An attack tool for your own network. The author used a **HackCat** (ESP32-class pentest board) for deauth, beacon spam and a cloned-SSID access point.
- A phone or laptop as an ordinary source of probe requests.

## Procedure for one live test

1. Start monitor mode, the engine (with `WIDS_EVENTS=$PWD/wifi_events.jsonl` if you want a permanent record of this run), and the dashboard. Note the time.
2. Wait until all four cards show `SECURE`.
3. Start the attack for 10–15 s, then stop it.
4. Watch the card go to `DETECTED`, then back to `SECURE`. Take a screenshot while it is `DETECTED`.
5. Copy the evidence:

   ```bash
   cp wifi_events.jsonl records/raw/$(date +%F_%H%M)_<test>.jsonl     # only if you started the engine with WIDS_EVENTS set
   ```
6. Fill in [`records/TEMPLATE.md`](../records/TEMPLATE.md), masking MACs first ([PRIVACY.md](PRIVACY.md)).

## What each detector should do

| Detector | How to trigger | Expected (dashboard; and in `wifi_events.jsonl` if enabled) |
|---|---|---|
| `DEAUTH` | tool's deauth mode against your own AP | `FIRED` within ~1–2 s; `CLEARED` ≈3 s after the attack stops, with duration, frame count and peak rate |
| `BEACON` | tool's beacon-spam mode with ≥ 15 SSIDs | `FIRED` within ~1–2 s with the unique BSSID count; `CLEARED` when the count drops |
| `EVIL_TWIN` | advertise your own SSID from a different BSSID (tool's cloned AP, or a phone hotspot with the same name) | `FIRED` on the first beacon/probe response naming the rogue BSSID; `CLEARED` 30 s after it stops |
| `PCAP_SNIFF` | toggle Wi-Fi on a phone, or run a probe flood | `HIT` lines per burst, `FIRED`, then `CLEARED` 30 s after the last burst |

## What to record

Date and time (and the Pi's timezone), engine version (`git rev-parse --short HEAD`), thresholds (the `ENGINE START` line has them), attack tool and mode, target, the `wifi_events.jsonl` lines, a screenshot, and the observed time to fire and to clear.

## Test without any radio

`tests/test_engine.py` feeds the real engine a synthetic stream of fake deauth, beacon-flood, Evil Twin and probe frames, replacing tshark and Scapy, and checks the `FIRED` / `CLEARED` records and that the Pi's own MAC is never flagged:

```bash
python3 tests/test_engine.py          # ~17 s, no root, no adapter, no tshark
```

It proves the rule logic and the log format. It does **not** prove anything about over-the-air reception, the adapter, or real-world false positives; label it that way in any report.

## Optional: raw captures

Run the rolling `dumpcap` command in [SETUP.md](SETUP.md#7-optional-keep-raw-packets) during a test, so the raw frames behind every record are on disk.
