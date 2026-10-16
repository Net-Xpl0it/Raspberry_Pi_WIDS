#!/usr/bin/env python3
"""No-radio functional test of the WIDS engine.

Runs the real engine with a fake tshark and a fake Scapy that replay a
synthetic stream of frames, then checks wifi_events.jsonl and wifi_log.json.

    python3 tests/test_engine.py            (~17 s; no root, no adapter, no tshark)

What it proves: the rule logic, the FIRED / CLEARED / HIT records, the own-MAC
allowlist and the output formats. What it does NOT prove: over-the-air
reception, the adapter, or real-world false positives.

Timers are shortened for the test (hold times 1-2 s); thresholds are the defaults.
"""

import importlib.util
import json
import os
import shutil
import signal
import sys
import tempfile
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "real_time_capture.py")
OUT = tempfile.mkdtemp(prefix="wids_test_")

# ---- fake scapy ------------------------------------------------------------
class Dot11: pass
class Dot11ProbeReq: pass


class FakePkt:
    def __init__(self, mac=None):
        self.mac = mac

    def haslayer(self, layer):
        return layer is Dot11ProbeReq and self.mac is not None

    def __getitem__(self, layer):
        return types.SimpleNamespace(addr2=self.mac)


OWN = "02:11:22:33:44:55"        # the sensor's own interface: must never be flagged
PHONE = "ca:fe:00:00:00:01"      # a probing phone: must be flagged


def fake_sniff(iface, prn, store):
    send = lambda mac=None: prn(FakePkt(mac))
    time.sleep(0.5)
    for _ in range(6):
        send(OWN); time.sleep(0.05)              # own MAC probing: ignored
    time.sleep(0.8)
    for _ in range(10):
        send(PHONE); time.sleep(0.01)            # burst 1
    for _ in range(8):
        send(None); time.sleep(0.3)
    for _ in range(10):
        send(PHONE); time.sleep(0.01)            # burst 2 (in case burst 1 straddled a window)
    end = time.time() + 8
    while time.time() < end:
        send(None); time.sleep(0.3)


scapy = types.ModuleType("scapy")
scapy_all = types.ModuleType("scapy.all")
scapy_all.sniff, scapy_all.Dot11, scapy_all.Dot11ProbeReq = fake_sniff, Dot11, Dot11ProbeReq
sys.modules["scapy"], sys.modules["scapy.all"] = scapy, scapy_all

# ---- load the engine and shorten its timers --------------------------------
spec = importlib.util.spec_from_file_location("engine", ENGINE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SSID = "MyHomeWiFi"
TRUST = "aa:bb:cc:dd:ee:ff"
ROGUE = "de:ad:be:ef:00:01"

m.LOG_PATH = os.path.join(OUT, "wifi_log.json")
m.EVENT_LOG_PATH = os.path.join(OUT, "wifi_events.jsonl")
m.TRUSTED_APS = {SSID: [TRUST]}
m.IGNORED = {OWN}
m.DEAUTH_HOLD_SEC = 1
m.ROGUE_HOLD_SEC = 1
m.BEACON_WINDOW_SEC = 2
m.SNIFFER_PERSIST_SEC = 2


# ---- fake tshark -----------------------------------------------------------
def mk(sub, sa, bssid, ssid=""):
    return f"{sub}\t{sa}\t{bssid}\t{ssid.encode().hex()}\t-40\n"


def idle(sec):
    end = time.time() + sec
    while time.time() < end:
        yield mk("0x0004", "aa:00:00:00:00:01", "ff:ff:ff:ff:ff:ff")
        time.sleep(0.2)


def tshark_lines():
    for _ in range(3):
        yield mk("0x0008", TRUST, TRUST, SSID); time.sleep(0.15)       # normal beacons
    for _ in range(30):
        yield mk("0x000c", TRUST, TRUST); time.sleep(0.03)             # deauth flood ~33 frames/s
    yield from idle(3)
    for _ in range(5):
        yield mk("0x0008", ROGUE, ROGUE, SSID); time.sleep(0.2)        # evil twin
    yield from idle(3)
    for i in range(20):
        b = f"02:00:00:00:00:{i:02x}"
        yield mk("0x0008", b, b, f"spam{i}"); time.sleep(0.02)         # beacon flood
    yield from idle(4)


class FakeProc:
    stdout = tshark_lines()


m.subprocess.Popen = lambda *a, **k: FakeProc()


def stop(*_):
    raise KeyboardInterrupt


signal.signal(signal.SIGALRM, stop)
signal.alarm(17)

m.main()          # returns after the alarm, writing the ENGINE STOP record

# ---- report ----------------------------------------------------------------
print("\n=== wifi_events.jsonl ===")
rows = [json.loads(line) for line in open(m.EVENT_LOG_PATH)]
for r in rows:
    print(r["ts"], f'{r["type"]:10s} {r["state"]:8s}', r["detail"])

seq = [(r["type"], r["state"]) for r in rows]
has = lambda t, s: (t, s) in seq
before = lambda a, b: seq.index(a) < seq.index(b)

live = json.load(open(m.LOG_PATH))
checks = {
    "first line is ENGINE START": seq[0] == ("ENGINE", "START"),
    "last line is ENGINE STOP": seq[-1] == ("ENGINE", "STOP"),
    "DEAUTH fired then cleared": has("DEAUTH", "FIRED") and has("DEAUTH", "CLEARED") and before(("DEAUTH", "FIRED"), ("DEAUTH", "CLEARED")),
    "EVIL_TWIN fired then cleared": has("EVIL_TWIN", "FIRED") and has("EVIL_TWIN", "CLEARED") and before(("EVIL_TWIN", "FIRED"), ("EVIL_TWIN", "CLEARED")),
    "BEACON fired then cleared": has("BEACON", "FIRED") and has("BEACON", "CLEARED") and before(("BEACON", "FIRED"), ("BEACON", "CLEARED")),
    "PCAP_SNIFF fired, hit, cleared": has("PCAP_SNIFF", "FIRED") and has("PCAP_SNIFF", "HIT") and has("PCAP_SNIFF", "CLEARED"),
    "probing phone is in a HIT": any(r["state"] == "HIT" and PHONE in r["detail"] for r in rows),
    "own MAC is never flagged": not any(OWN in r["detail"] and r["type"] == "PCAP_SNIFF" for r in rows),
    "one DEAUTH line per transition (no per-frame spam)": sum(1 for r in rows if r["type"] == "DEAUTH") == 2,
    "wifi_log.json keeps its keys": set(live) == {"DEAUTH", "BEACON", "EVIL_TWIN", "PCAP_SNIFF", "events", "updated"},
    "dashboard feed still receives events": any(e["type"] == "DEAUTH" for e in live["events"]),
}

print("\n=== checks ===")
ok = True
for name, passed in checks.items():
    print("PASS" if passed else "FAIL", name)
    ok &= passed
print(f"\n{sum(checks.values())}/{len(checks)} checks passed")

shutil.rmtree(OUT, ignore_errors=True)
sys.exit(0 if ok else 1)
