#!/usr/bin/env python3
"""
WIDS capture + detection engine
Raspberry Pi 4 | wlan1 (monitor mode, Atheros AR9271)

Detectors (all rule/threshold-based, no ML):
  - tshark thread : Deauth flood, Beacon spam, Evil Twin
  - Scapy  thread : Probe sniffer (reconnaissance)

Evil Twin = a protected SSID of ours is advertised by a BSSID we do not trust.
Evil Twin auto-clears 30 s after the last rogue frame.
Deauth status is live: it clears DEAUTH_HOLD_SEC after the last flood frame
(history is only kept if the optional event log is switched on).

Output:
  wifi_log.json     live snapshot rewritten every second (the dashboard reads it;
                    only the last 50 events, replaced on every engine start)

Optional, OFF by default (the sensor has a slow microSD card and little free RAM):
  WIDS_EVENTS=/path/wifi_events.jsonl   append-only record, one JSON line per
                    ENGINE start/stop and per detector FIRED / CLEARED (plus one
                    HIT line per sniffer burst). Each line is fsync'd, so only
                    switch it on for short test runs.
"""

import glob
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque, defaultdict
from datetime import datetime

from scapy.all import sniff, Dot11, Dot11ProbeReq

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
IFACE = "wlan1"

# Files live next to this script, so it does not matter which folder you start
# the engine from (override with WIDS_LOG / WIDS_EVENTS if needed).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.environ.get("WIDS_LOG", os.path.join(BASE_DIR, "wifi_log.json"))
EVENT_LOG_PATH = os.environ.get("WIDS_EVENTS")      # unset = no permanent log (default)

DEAUTH_THRESHOLD = 2                  # deauth frames/sec to flag flood
DEAUTH_HOLD_SEC = 3                   # status clears this long after the last flood frame
BEACON_WINDOW_SEC = 10
BEACON_UNIQUE_BSSID_THRESHOLD = 15

# Protected networks: SSID -> list of TRUSTED BSSIDs (lowercase). Add every
# band/radio of your own router here. Any other BSSID using the SSID = rogue.
TRUSTED_APS = {
    "MyHomeWiFi": ["aa:bb:cc:dd:ee:ff"],   # <- replace with your SSID and router BSSID(s)
}
ROGUE_HOLD_SEC = 30                   # keep EVIL_TWIN lit this long after last rogue frame

PROBE_THRESHOLD = 3                   # probes from one MAC per window
PROBE_WINDOW_SEC = 1
SNIFFER_PERSIST_SEC = 30              # keep sniffer alert active 30s after last hit

# Never flag these MACs as sniffers. The Pi's own wlan0 probes for saved
# networks (e.g. "HomeWiFi") and would otherwise trigger PCAP_SNIFF all day.
# Trade-off: someone spoofing the sensor's own MAC would not be flagged.
IGNORE_MACS = set()                   # extra MACs, lowercase, e.g. {"aa:bb:cc:dd:ee:ff"}
IGNORE_OWN_MACS = True                # also ignore every interface MAC of this Pi


def own_macs():
    """MAC address of every network interface on this machine."""
    macs = set()
    for path in glob.glob("/sys/class/net/*/address"):
        try:
            with open(path) as f:
                mac = f.read().strip().lower()
        except OSError:
            continue
        if mac and mac != "00:00:00:00:00:00":
            macs.add(mac)
    return macs


IGNORED = {m.lower() for m in IGNORE_MACS} | (own_macs() if IGNORE_OWN_MACS else set())

# ---------------------------------------------------------------------------
# SHARED STATE
# ---------------------------------------------------------------------------
state_lock = threading.RLock()
event_lock = threading.Lock()
shared = {
    "DEAUTH": 0,
    "BEACON": 0,
    "EVIL_TWIN": 0,
    "PCAP_SNIFF": 0,
    "_deauth_last": 0.0,              # monotonic time of last flood frame (internal)
    "_deauth_start": 0.0,             # monotonic time the flood was first flagged (internal)
    "_deauth_frames": 0,              # flood frames counted since it was flagged (internal)
    "_deauth_peak": 0,                # highest frames/sec seen in this flood (internal)
    "events": deque(maxlen=200),
}


def log_event(attack_type, detail):
    """Dashboard feed (rolling, lives in wifi_log.json)."""
    with state_lock:
        shared["events"].append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": attack_type,
            "detail": detail,
        })


def record(attack_type, state, detail=""):
    """Permanent record: append one JSON line to wifi_events.jsonl.

    state is one of START / STOP (ENGINE), FIRED / CLEARED (detectors), HIT (one
    sniffer burst). Time carries the local UTC offset, e.g. 2026-10-16T09:12:03.412+05:30
    """
    if not EVENT_LOG_PATH:
        return
    line = json.dumps({
        "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "type": attack_type,
        "state": state,
        "detail": detail,
    })
    with event_lock:
        try:
            with open(EVENT_LOG_PATH, "a") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            print(f"[!] could not write {EVENT_LOG_PATH}: {e}", flush=True)


# ---------------------------------------------------------------------------
# THREAD 1 — tshark: deauth, beacon spam, evil twin
# ---------------------------------------------------------------------------
def tshark_thread():
    print("[*] tshark thread started (deauth / beacon spam / evil twin)", flush=True)

    cmd = [
        "tshark", "-i", IFACE, "-f", "type mgt", "-l", "-T", "fields",
        "-e", "wlan.fc.type_subtype",
        "-e", "wlan.sa",
        "-e", "wlan.bssid",
        "-e", "wlan.ssid",
        "-e", "radiotap.dbm_antsignal",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    deauth_window = deque()
    beacon_seen = {}              # bssid -> last time seen
    beacon_active = False
    beacon_start = 0.0            # when the current beacon flood was first flagged
    beacon_peak = 0               # most unique BSSIDs seen in this flood
    twin_last = 0.0               # last time a rogue twin frame was seen
    twin = {"start": 0.0, "frames": 0, "bssids": set()}
    window_start = time.monotonic()

    for line in proc.stdout:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 5:
            continue
        subtype, sa, bssid, ssid_hex, rssi = fields[:5]
        try:
            ssid = bytes.fromhex(ssid_hex).decode("utf-8", errors="ignore") if ssid_hex else ""
        except ValueError:
            ssid = ssid_hex
        bssid = bssid.lower()
        now = time.monotonic()

        if subtype in ("0x0c", "0x000c"):                       # deauthentication
            deauth_window.append(now)
            while deauth_window and now - deauth_window[0] > 1:
                deauth_window.popleft()
            rate = len(deauth_window)
            if rate >= DEAUTH_THRESHOLD:
                with state_lock:
                    if not shared["DEAUTH"]:
                        shared["_deauth_start"] = now
                        shared["_deauth_frames"] = 0
                        shared["_deauth_peak"] = 0
                        record("DEAUTH", "FIRED", f"{rate} deauth frames/s from {sa} (bssid {bssid})")
                    shared["_deauth_frames"] += 1
                    shared["_deauth_peak"] = max(shared["_deauth_peak"], rate)
                    shared["DEAUTH"] = 1
                    shared["_deauth_last"] = now
                log_event("DEAUTH", f"{rate} deauth frames/sec from {sa}")

        # beacon (0x08) or probe response (0x05): both advertise an SSID
        elif subtype in ("0x08", "0x0008", "0x05", "0x0005") and bssid:
            if subtype in ("0x08", "0x0008"):
                beacon_seen[bssid] = now

            if ssid in TRUSTED_APS and bssid not in TRUSTED_APS[ssid]:
                with state_lock:
                    if not shared["EVIL_TWIN"]:
                        twin = {"start": now, "frames": 0, "bssids": set()}
                        log_event("EVIL_TWIN", f"SSID '{ssid}' advertised by untrusted BSSID {bssid}")
                        record("EVIL_TWIN", "FIRED",
                               f"SSID '{ssid}' advertised by untrusted BSSID {bssid} (frame {subtype})")
                    shared["EVIL_TWIN"] = 1
                twin["frames"] += 1
                twin["bssids"].add(bssid)
                twin_last = now

        if now - window_start >= 1:
            cutoff = now - BEACON_WINDOW_SEC
            for b in [b for b, t in beacon_seen.items() if t < cutoff]:
                del beacon_seen[b]
            unique_count = len(beacon_seen)
            flagged = unique_count >= BEACON_UNIQUE_BSSID_THRESHOLD
            with state_lock:
                shared["BEACON"] = 1 if flagged else 0
                if flagged and not beacon_active:
                    beacon_start = now
                    beacon_peak = 0
                    log_event("BEACON", f"{unique_count} unique BSSIDs in {BEACON_WINDOW_SEC}s")
                    record("BEACON", "FIRED", f"{unique_count} unique BSSIDs in {BEACON_WINDOW_SEC}s")
                if flagged:
                    beacon_peak = max(beacon_peak, unique_count)
                if beacon_active and not flagged:
                    record("BEACON", "CLEARED",
                           f"flood lasted {now - beacon_start:.0f}s, peak {beacon_peak} unique BSSIDs in {BEACON_WINDOW_SEC}s")
                if shared["EVIL_TWIN"] and now - twin_last > ROGUE_HOLD_SEC:
                    shared["EVIL_TWIN"] = 0
                    record("EVIL_TWIN", "CLEARED",
                           f"no rogue frames for {ROGUE_HOLD_SEC}s; rogue seen {twin_last - twin['start']:.0f}s, "
                           f"{twin['frames']} frames, BSSID(s) {', '.join(sorted(twin['bssids']))}")
            beacon_active = flagged
            window_start = now


# ---------------------------------------------------------------------------
# THREAD 2 — Scapy: probe sniffer detection
# ---------------------------------------------------------------------------
def scapy_thread():
    print("[*] Scapy thread started (probe sniffer detection)", flush=True)

    probe_counts = defaultdict(int)
    confirmed_time = {}
    window_start = [time.monotonic()]

    def handle(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            mac = pkt[Dot11].addr2
            if mac and mac.lower() not in IGNORED:
                probe_counts[mac] += 1

        now = time.monotonic()
        if now - window_start[0] >= PROBE_WINDOW_SEC:
            with state_lock:
                hits = [(mac, count) for mac, count in probe_counts.items() if count >= PROBE_THRESHOLD]
                for mac, _ in hits:
                    confirmed_time[mac] = now

                active = [m for m, t in confirmed_time.items() if now - t <= SNIFFER_PERSIST_SEC]
                new_state = 1 if active else 0
                if new_state != shared["PCAP_SNIFF"]:
                    if new_state:
                        record("PCAP_SNIFF", "FIRED", f"{len(active)} source(s) probing")
                    else:
                        record("PCAP_SNIFF", "CLEARED", f"no probe bursts for {SNIFFER_PERSIST_SEC}s")
                shared["PCAP_SNIFF"] = new_state

                for mac, count in hits:
                    detail = f"{mac} sent {count} probes/{PROBE_WINDOW_SEC}s"
                    log_event("PCAP_SNIFF", detail)
                    record("PCAP_SNIFF", "HIT", detail)

            probe_counts.clear()
            window_start[0] = now

    sniff(iface=IFACE, prn=handle, store=False)


# ---------------------------------------------------------------------------
# MAIN — snapshot to wifi_log.json every second
# ---------------------------------------------------------------------------
def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # systemctl stop -> clean STOP record
    print(f"[*] WIDS starting on {IFACE}", flush=True)
    print(f"[*] live log  : {LOG_PATH}", flush=True)
    print(f"[*] event log : {EVENT_LOG_PATH or 'off (set WIDS_EVENTS to enable)'}", flush=True)
    record("ENGINE", "START",
           f"iface={IFACE} deauth>={DEAUTH_THRESHOLD}/s beacon>={BEACON_UNIQUE_BSSID_THRESHOLD}/{BEACON_WINDOW_SEC}s "
           f"probe>={PROBE_THRESHOLD}/{PROBE_WINDOW_SEC}s trusted_ssids={sorted(TRUSTED_APS)} "
           f"ignored_macs={sorted(IGNORED)}")

    threading.Thread(target=tshark_thread, daemon=True).start()
    threading.Thread(target=scapy_thread, daemon=True).start()

    try:
        while True:
            with state_lock:
                # live deauth status: drop it shortly after the flood stops (log keeps history)
                now = time.monotonic()
                if shared["DEAUTH"] and now - shared["_deauth_last"] > DEAUTH_HOLD_SEC:
                    shared["DEAUTH"] = 0
                    record("DEAUTH", "CLEARED",
                           f"flood lasted {shared['_deauth_last'] - shared['_deauth_start']:.1f}s, "
                           f"{shared['_deauth_frames']} frames after detection, peak {shared['_deauth_peak']}/s")
                snapshot = {
                    "DEAUTH": shared["DEAUTH"],
                    "BEACON": shared["BEACON"],
                    "EVIL_TWIN": shared["EVIL_TWIN"],
                    "PCAP_SNIFF": shared["PCAP_SNIFF"],
                    "events": list(shared["events"])[-50:],
                    "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            with open(LOG_PATH, "w") as f:
                json.dump(snapshot, f, indent=2)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        record("ENGINE", "STOP", "")
        print("[*] WIDS stopped", flush=True)


if __name__ == "__main__":
    main()
