# Setup guide

## 1. Hardware check

```bash
lsusb | grep -i atheros        # the AR9271 adapter should be listed
iw dev                         # wlan0 (built-in) and wlan1 (AR9271)
```

The built-in `wlan0` stays in normal (managed) mode. It is only used to scan for your AP's channel, because an interface in monitor mode cannot scan.

## 2. Install

```bash
sudo apt update && sudo apt install -y tshark iw python3-pip
# "Should non-superusers be able to capture packets?"  ->  No (the engine runs as root)

git clone https://github.com/<your-user>/wids-tshark.git ~/wids && cd ~/wids
pip install --break-system-packages -r requirements.txt     # needed on Debian 12+ / Trixie
```

Set the Pi's timezone so log timestamps match your clock: `sudo timedatectl set-timezone <Region/City>`.

## 3. Configure

Edit `TRUSTED_APS` at the top of `real_time_capture.py`:

```python
TRUSTED_APS = {
    "MyHomeWiFi": ["aa:bb:cc:dd:ee:ff"],     # every BSSID of your router
}
```

Find your router's BSSID(s) with `iw dev wlan0 link` while connected, or `sudo iw dev wlan0 scan | grep -E "BSS|SSID|freq"`. A router that broadcasts both bands uses a different BSSID per band; list both. `EVIL_TWIN` only protects SSIDs listed here.

Thresholds are documented in [DETECTION_RULES.md](DETECTION_RULES.md).

## 4. Monitor mode

```bash
sudo SSID="MyHomeWiFi" BSSID="aa:bb:cc:dd:ee:ff" ./scripts/monitor-mode.sh
```

What it does, in order:

1. Picks the channel: the `CHANNEL` env var, else a live scan on `wlan0`, else the last known channel (`.last_channel`), else channel 1.
2. In the scan it accepts only your pinned BSSID, so a cloned SSID cannot steer the sensor.
3. Stops NetworkManager and `wpa_supplicant` from managing `wlan1`, switches it to monitor mode, brings it up.
4. Locks the channel (retrying if the driver reports "busy"), prints `iw dev wlan1 info` and `READY`, or `FAILED` with a non-zero exit.

Force a channel and skip the scan: `sudo CHANNEL=3 ./scripts/monitor-mode.sh`.

Monitor mode is **not persistent**. Re-run the script after a reboot, an adapter replug, or NetworkManager activity (or use the systemd unit below).

## 5. Run

```bash
sudo python3 real_time_capture.py                      # terminal 1
python3 -m streamlit run dashboard.py \
        --server.address 0.0.0.0 --server.port 8501    # terminal 2, no sudo
```

Open `http://<pi-ip>:8501` from a laptop on the same network. Use Ethernet for the Pi: a deauth attack takes Wi-Fi down.

## 6. Run on boot (systemd)

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo sed -i "s|/home/pi|$HOME|g; s|^User=pi\$|User=$USER|" /etc/systemd/system/wids-*.service
sudo nano /etc/systemd/system/wids-capture.service        # set SSID= and BSSID=
sudo systemctl daemon-reload
sudo systemctl enable --now wids-capture wids-dashboard
journalctl -u wids-capture -f
```

The capture unit runs `monitor-mode.sh` before every start, so monitor mode and the channel survive reboots.

## 7. Optional: keep raw packets

The engine reads tshark fields and does not save packets, because the sensor has a slow SD card and limited free RAM. Only do this for short, deliberate test runs, ideally to a USB stick or `/dev/shm` rather than the SD card. To keep evidence, run a second capture alongside the engine. It stores only management frames in a rolling buffer (a new file every hour or 20 MB, newest 48 files kept):

```bash
mkdir -p ~/wids/pcaps
sudo dumpcap -i wlan1 -f "type mgt" -b duration:3600 -b filesize:20480 -b files:48 -w ~/wids/pcaps/wids.pcapng
```

Pcaps contain every nearby device's MAC and SSID. They are git-ignored; see [PRIVACY.md](PRIVACY.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `command failed: Device or resource busy (-16)` when setting the channel | NetworkManager, `wpa_supplicant` or a stale process holds `wlan1` | run `monitor-mode.sh` (it handles this); if it persists: `sudo nmcli device set wlan1 managed no`, cycle the interface, last resort `sudo modprobe -r ath9k_htc && sudo modprobe ath9k_htc` |
| `iw dev wlan1 info` shows `type managed`, or no `channel` line | monitor mode is lost after reboot/replug; a monitor interface shows no channel until one is set | re-run `monitor-mode.sh` |
| `iw dev wlan1 scan` → `Operation not supported (-95)` | monitor interfaces cannot scan | scan with `wlan0` (the script does) |
| `sudo iw dev set wlan1 type monitor` → `No such device` | wrong argument order | `sudo iw dev wlan1 set type monitor` |
| `streamlit: command not found` | pip's script folder is not on `PATH` | `python3 -m streamlit run dashboard.py`; do not use `sudo` |
| Dashboard shows `ENGINE OFFLINE` | engine not running, or engine and dashboard use different log files | start the engine; both default to `wifi_log.json` next to the scripts (`WIDS_LOG` overrides) |
| No frames / nothing detected | adapter on the wrong channel | check the `channel` line in `iw dev wlan1 info`; re-run the script |
| `PCAP_SNIFF` fires all the time | the Pi's own `wlan0` probing, or nearby phones | own MACs are ignored by default; raise `PROBE_THRESHOLD` or add MACs to `IGNORE_MACS` |
| `EVIL_TWIN` fires on your own router | a BSSID of your router is missing from `TRUSTED_APS` | add every band/radio |
| Log timestamps are hours off | Pi timezone | `sudo timedatectl set-timezone <Region/City>` |
