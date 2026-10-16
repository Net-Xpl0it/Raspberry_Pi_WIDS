# Software test of all four detectors

| Field | Value |
|---|---|
| Date | 2026-10-16 |
| Evidence type | SOFTWARE |
| Detectors | DEAUTH, BEACON, EVIL_TWIN, PCAP_SNIFF |
| Where it ran | a Linux development machine (Python 3.11.15), **not** the Pi |
| Command | `python3 tests/test_engine.py` |
| Result | **11 / 11 checks passed** |

## Method

The real engine ran with tshark and Scapy replaced by scripted fakes that replay a synthetic frame stream: 3 normal beacons, a deauth flood of 30 frames (~33 frames/s), 5 beacons for the protected SSID from an untrusted BSSID, a flood of 20 unique beacon BSSIDs, and probe bursts from one phone MAC plus probes from the sensor's own MAC. Hold timers were shortened to 1–2 s so the run takes 17 s; thresholds are the defaults.

## Output

```
[*] WIDS starting on wlan1
[*] live log  : <tmp>/wifi_log.json
[*] event log : <tmp>/wifi_events.jsonl
[*] tshark thread started (deauth / beacon spam / evil twin)
[*] Scapy thread started (probe sniffer detection)
[*] WIDS stopped

=== wifi_events.jsonl ===
2026-10-16T03:42:10.231+00:00 ENGINE     START    iface=wlan1 deauth>=2/s beacon>=15/2s probe>=3/1s trusted_ssids=['MyHomeWiFi'] ignored_macs=['02:11:22:33:44:55']
2026-10-16T03:42:10.714+00:00 DEAUTH     FIRED    2 deauth frames/s from aa:bb:cc:dd:ee:ff (bssid aa:bb:cc:dd:ee:ff)
2026-10-16T03:42:12.838+00:00 PCAP_SNIFF FIRED    1 source(s) probing
2026-10-16T03:42:12.838+00:00 PCAP_SNIFF HIT      ca:fe:00:00:00:01 sent 9 probes/1s
2026-10-16T03:42:13.235+00:00 DEAUTH     CLEARED  flood lasted 0.8s, 29 frames after detection, peak 30/s
2026-10-16T03:42:14.596+00:00 EVIL_TWIN  FIRED    SSID 'MyHomeWiFi' advertised by untrusted BSSID de:ad:be:ef:00:01 (frame 0x0008)
2026-10-16T03:42:15.043+00:00 PCAP_SNIFF HIT      ca:fe:00:00:00:01 sent 10 probes/1s
2026-10-16T03:42:16.400+00:00 EVIL_TWIN  CLEARED  no rogue frames for 1s; rogue seen 1s, 5 frames, BSSID(s) de:ad:be:ef:00:01
2026-10-16T03:42:17.446+00:00 PCAP_SNIFF CLEARED  no probe bursts for 2s
2026-10-16T03:42:19.409+00:00 BEACON     FIRED    20 unique BSSIDs in 2s
2026-10-16T03:42:21.412+00:00 BEACON     CLEARED  flood lasted 2s, peak 20 unique BSSIDs in 2s
2026-10-16T03:42:27.231+00:00 ENGINE     STOP     

=== checks ===
PASS first line is ENGINE START
PASS last line is ENGINE STOP
PASS DEAUTH fired then cleared
PASS EVIL_TWIN fired then cleared
PASS BEACON fired then cleared
PASS PCAP_SNIFF fired, hit, cleared
PASS probing phone is in a HIT
PASS own MAC is never flagged
PASS one DEAUTH line per transition (no per-frame spam)
PASS wifi_log.json keeps its keys
PASS dashboard feed still receives events

11/11 checks passed
```

## What it shows

- Every detector writes one `FIRED` and one `CLEARED` line per episode. The deauth flood produces two `DEAUTH` lines, not one per frame.
- `DEAUTH CLEARED` reports duration, frames counted and peak rate; `EVIL_TWIN CLEARED` reports the rogue BSSID and frame count; `BEACON CLEARED` reports duration and peak.
- The sensor's own MAC is never flagged; the phone's burst is.
- `wifi_log.json` keeps its original keys and the dashboard feed still receives events.

## Limits

Synthetic frames prove the rule logic and the log format. They say nothing about over-the-air reception, the adapter or real-world false positives. Re-run the command on the Pi and replace the output above to make it a Pi result.
