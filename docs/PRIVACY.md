# Privacy: what to mask before publishing

A wireless IDS records everything it hears. The logs and captures contain the MAC addresses and network names of **everyone in range**, including neighbours.

| Item | Why it matters | What to do |
|---|---|---|
| Your router's BSSID | it is the value `EVIL_TWIN` trusts, so publishing it tells an attacker which address to spoof; with the SSID it can also be looked up in public Wi-Fi location databases | use a placeholder (`aa:bb:cc:dd:ee:ff`) |
| Your SSID | many default SSIDs end in the last bytes of the BSSID (e.g. `Brand_1A2B`), so masking the BSSID but keeping the SSID gives it away | use a placeholder (`MyHomeWiFi`) |
| Client MACs | a real (non-randomised) MAC identifies a device and its owner | mask the last three bytes |
| `wifi_log.json`, `wifi_events.jsonl`, `*.pcapng` | raw MACs and SSIDs of all nearby devices | never commit; publish masked excerpts |
| Screenshots | dashboards and terminals show MACs | crop or blur |
| Wi-Fi password, router admin page, public IP | credentials and location | never include |

## Masking tool

```bash
python3 tools/mask_macs.py wifi_events.jsonl > records/data/events_masked.jsonl
python3 tools/mask_macs.py --ssid "RealName=MyHomeWiFi" wifi_log.json
python3 tools/mask_macs.py --keep aa:bb:cc:dd:ee:ff wifi_log.json     # leave one MAC unmasked
```

It keeps the first three bytes (the vendor, or the randomised-address prefix) and replaces the last three: `4e:00:00:a1:b2:c3` → `4e:00:00:xx:xx:xx`. Broadcast and all-zero addresses are untouched.

## Before every push

```bash
git diff --cached | grep -inE "([0-9a-f]{2}:){5}[0-9a-f]{2}"       # any full MAC left?
git diff --cached | grep -inE "your-ssid|your-username|192\.168\."  # your own identifiers
```

`.gitignore` already excludes `wifi_log.json`, `wifi_events.jsonl`, `.last_channel`, `*.pcap*` and `records/raw/`.
