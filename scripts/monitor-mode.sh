#!/usr/bin/env bash
# WIDS monitor-mode setup: finds the protected AP's 2.4 GHz channel, puts the
# adapter in monitor mode and locks it to that channel.
#
# Usage:  sudo ./scripts/monitor-mode.sh                      (set SSID / BSSID below first)
#         sudo SSID="MyWiFi" BSSID="aa:bb:cc:dd:ee:ff" ./scripts/monitor-mode.sh
#         sudo CHANNEL=3 ./scripts/monitor-mode.sh            (skip scan, force channel)
#
# Safe by design: it never exits non-zero just because the scan failed, so it can
# sit in front of the engine (systemd ExecStartPre) without breaking startup.
# Channel source order: CHANNEL env  >  live scan  >  last known channel (cache).

SCAN_IF="${SCAN_IF:-wlan0}"          # managed interface used for scanning
MON_IF="${MON_IF:-wlan1}"            # AR9271, becomes the monitor interface
SSID="${SSID:-MyHomeWiFi}"            # protected network name (set yours)
BSSID="${BSSID:-}"                   # its real BSSID (pinned, lowercase); empty = trust by SSID only
CACHE="${CACHE:-$(dirname "$(readlink -f "$0")")/../.last_channel}"
TRIES="${TRIES:-4}"

log() { echo "[monitor-mode] $*"; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
BSSID="$(echo "$BSSID" | tr 'A-F' 'a-f')"

freq_to_chan() {                     # 2.4 GHz only
  local f=${1%.*}
  if   [ "$f" -eq 2484 ]; then echo 14
  elif [ "$f" -ge 2412 ] && [ "$f" -le 2472 ]; then echo $(( (f - 2407) / 5 ))
  fi
}

scan_channel() {
  local out i
  for i in $(seq 1 "$TRIES"); do
    out="$(iw dev "$SCAN_IF" scan 2>/dev/null)" && [ -n "$out" ] && break
    log "scan attempt $i failed, retrying..."; sleep 2; out=""
  done
  [ -n "$out" ] || return 1

  # one line per BSS: "bssid freq ssid"
  local table
  table="$(echo "$out" | awk '
    function flush() { if (b != "") print b "\t" f "\t" s }
    /^BSS /        { flush(); b=tolower($2); sub(/\(.*/,"",b); f=""; s="" }
    /^\tfreq:/     { f=$2 }
    /^\tSSID:/     { sub(/^\tSSID: ?/,""); s=$0 }
    END            { flush() }')"

  # 2.4 GHz candidates for our SSID
  local cands
  cands="$(echo "$table" | awk -F'\t' -v ssid="$SSID" '$3==ssid && $2+0>=2400 && $2+0<2500')"
  [ -n "$cands" ] || { log "SSID '$SSID' not seen on 2.4 GHz"; return 1; }

  local n; n=$(echo "$cands" | wc -l)
  local pick=""
  if [ -n "$BSSID" ]; then
    pick="$(echo "$cands" | awk -F'\t' -v b="$BSSID" '$1==b')"
    if [ -z "$pick" ]; then
      log "WARNING: '$SSID' is on the air but NOT from trusted BSSID $BSSID:"
      echo "$cands" | awk -F'\t' '{print "    seen: " $1 "  freq " $2}'
      return 1                       # refuse to follow an unknown BSSID (possible evil twin)
    fi
    [ "$n" -gt 1 ] && log "WARNING: $n BSSIDs advertise '$SSID' on 2.4 GHz (possible evil twin):" && echo "$cands" | awk -F'\t' '{print "    seen: " $1 "  freq " $2}'
  else
    pick="$(echo "$cands" | head -1)"
    [ "$n" -gt 1 ] && log "WARNING: $n BSSIDs for '$SSID'; using first. Set BSSID= to pin."
  fi

  local pf pb; pf="$(echo "$pick" | cut -f2)"; pb="$(echo "$pick" | cut -f1)"
  CH="$(freq_to_chan "$pf")"; FOUND_BSSID="$pb"
  [ -n "$CH" ]
}

# ---- 1. decide the channel ------------------------------------------------
CH="${CHANNEL:-}"
if [ -z "$CH" ]; then
  if scan_channel; then
    log "found $SSID  bssid=$FOUND_BSSID  channel=$CH"
    echo "$CH" > "$CACHE" 2>/dev/null
  elif [ -s "$CACHE" ]; then
    CH="$(cat "$CACHE")"; log "scan failed, using last known channel $CH"
  else
    CH=1; log "scan failed and no cache, defaulting to channel $CH (set CHANNEL=n to override)"
  fi
else
  log "using forced channel $CH"
fi

# ---- 2. monitor mode ---------------------------------------------------------
nmcli device set "$MON_IF" managed no 2>/dev/null || true
pkill -f "wpa_supplicant.*$MON_IF" 2>/dev/null || true
ip link set "$MON_IF" down
iw dev "$MON_IF" set type monitor || { log "could not set monitor mode"; exit 1; }
ip link set "$MON_IF" up

# ---- 3. lock channel (retry: 'busy' is usually transient) --------------------
ok=0
for i in 1 2 3 4 5; do
  if iw dev "$MON_IF" set channel "$CH" 2>/dev/null; then ok=1; break; fi
  log "set channel busy, retry $i"; ip link set "$MON_IF" down; sleep 1; ip link set "$MON_IF" up; sleep 1
done

# ---- 4. verify ---------------------------------------------------------------
iw dev "$MON_IF" info | grep -E "type|channel"
if [ "$ok" -eq 1 ] && iw dev "$MON_IF" info | grep -q "type monitor"; then
  log "READY: $MON_IF monitor, channel $CH"
else
  log "FAILED to lock channel $CH on $MON_IF"; exit 1
fi
