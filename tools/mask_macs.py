#!/usr/bin/env python3
"""Mask MAC addresses before publishing logs, notes or captures' text dumps.

Keeps the first three bytes (vendor / randomised-address prefix) and replaces
the last three with xx:

    4e:00:00:a1:b2:c3  ->  4e:00:00:xx:xx:xx

Broadcast (ff:ff:ff:ff:ff:ff) and the all-zero address are left alone.

Usage:
    python3 tools/mask_macs.py wifi_events.jsonl > events_masked.jsonl
    cat wifi_log.json | python3 tools/mask_macs.py
    python3 tools/mask_macs.py --ssid "RealName=MyHomeWiFi" wifi_log.json
    python3 tools/mask_macs.py --keep aa:bb:cc:dd:ee:ff wifi_log.json
"""

import argparse
import re
import sys

MAC = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:])")
ALWAYS_KEEP = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def mask(text, keep=(), ssid_map=()):
    """Return text with every MAC masked (except `keep`) and SSIDs replaced."""
    keep = {k.lower() for k in keep} | ALWAYS_KEEP

    def sub(match):
        mac = match.group(1)
        if mac.lower() in keep:
            return mac
        return ":".join(mac.split(":")[:3]) + ":xx:xx:xx"

    text = MAC.sub(sub, text)
    for old, new in ssid_map:
        text = text.replace(old, new)
    return text


def main():
    ap = argparse.ArgumentParser(description="Mask MAC addresses in text files or stdin.")
    ap.add_argument("files", nargs="*", help="files to read (default: stdin)")
    ap.add_argument("--keep", action="append", default=[], metavar="MAC",
                    help="leave this MAC unmasked (repeatable)")
    ap.add_argument("--ssid", action="append", default=[], metavar="OLD=NEW",
                    help="replace an SSID, e.g. RealName=MyHomeWiFi (repeatable)")
    args = ap.parse_args()

    ssid_map = []
    for item in args.ssid:
        if "=" not in item:
            ap.error(f"--ssid expects OLD=NEW, got {item!r}")
        old, new = item.split("=", 1)
        ssid_map.append((old, new))

    if args.files:
        for path in args.files:
            with open(path, encoding="utf-8") as f:
                sys.stdout.write(mask(f.read(), args.keep, ssid_map))
    else:
        sys.stdout.write(mask(sys.stdin.read(), args.keep, ssid_map))


if __name__ == "__main__":
    main()
