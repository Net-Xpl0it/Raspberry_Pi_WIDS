# Test environment

| Item | Value |
|---|---|
| Sensor | Raspberry Pi 4 |
| OS | Raspberry Pi OS (Debian 13 "Trixie") |
| Monitor adapter | Atheros AR9271 USB (`ath9k_htc`), `wlan1` |
| Scan interface | built-in `wlan0` (managed) |
| Protected AP | own router, 2.4 GHz channel 3 during the October 2026 sessions |
| Display | 3.5" Pi touchscreen showing the dashboard (see the live-demo photos) |
| Attack tool | HackCat (ESP32-class board), own network only |
| tshark version | **TODO** (`tshark -v \| head -1`) |
| Python / Scapy / Streamlit | **TODO** (`python3 -V`, `pip list \| grep -iE "scapy\|streamlit"`) |
| Engine version | **TODO** (repository not yet tagged; use `git rev-parse --short HEAD`) |

## Clock and timezone

The Pi ran on British Summer Time (UTC+1) until 2026-10-16, when it was changed to `Asia/Kolkata` (UTC+5:30). Timestamps in records before that date are BST; **add 4 h 30 min for India time**. The live-demo photos show only the Pi's clock (hours and minutes).
