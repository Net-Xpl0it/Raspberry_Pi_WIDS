#!/usr/bin/env python3
"""
WIDS // SENTINEL — wireless intrusion detection console.

Reads wifi_log.json (written every second by real_time_capture.py).
If the log stops updating, the console goes dark and shows ENGINE OFFLINE, so a
frozen capture engine can never look like "all clear".
"""

import html
import json
import os
import time

import streamlit as st

LOG_PATH = os.environ.get(
    "WIDS_LOG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wifi_log.json")
)
STALE_SEC = 5
REFRESH_SEC = 1
START = time.time()

# key in wifi_log.json, label, what it means, MITRE-style hint
DETECTORS = [
    ("DEAUTH",      "Deauth Flood",  "forced client disconnects"),
    ("BEACON",      "Beacon Spam",   "fake-AP flooding"),
    ("EVIL_TWIN",   "Evil Twin",     "rogue clone of trusted AP"),
    ("PCAP_SNIFF",  "Probe Sniffer", "active wireless recon"),
]

st.set_page_config(page_title="WIDS // SENTINEL", page_icon="🛰", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;700&family=JetBrains+Mono:wght@400;700&display=swap');

:root { --bg:#04070d; --panel:rgba(8,18,28,.88); --line:rgba(80,220,255,.28);
        --cy:#4de8ff; --ok:#3dffa8; --bad:#ff3d6e; --warn:#ffb84d; --dim:#6f8a96; --tx:#d6f3fb; }

header[data-testid="stHeader"], footer, #MainMenu { display:none !important; }
.stApp { background: var(--bg); color: var(--tx); font-family:'JetBrains Mono',monospace; }
.stApp::before { content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
  background:
    radial-gradient(900px 500px at 15% -10%, rgba(77,232,255,.13), transparent 60%),
    radial-gradient(800px 500px at 100% 110%, rgba(255,61,110,.09), transparent 60%),
    linear-gradient(rgba(77,232,255,.04) 1px, transparent 1px) 0 0/38px 38px,
    linear-gradient(90deg, rgba(77,232,255,.04) 1px, transparent 1px) 0 0/38px 38px; }
.block-container { position:relative; z-index:1; max-width:1380px; padding-top:1rem; }

/* header */
.hdr { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;
       padding:10px 0 14px; border-bottom:1px solid var(--line); margin-bottom:14px; }
.logo { font-family:'Chakra Petch'; font-weight:700; font-size:1.9rem; letter-spacing:.2em; color:var(--cy);
        text-shadow:0 0 18px rgba(77,232,255,.55); }
.logo span { color:var(--tx); opacity:.55; font-weight:500; }
.meta { display:flex; gap:18px; font-size:.82rem; color:var(--dim); letter-spacing:.08em; }
.meta b { color:var(--tx); font-weight:400; }

/* big banner */
.banner { font-family:'Chakra Petch'; font-weight:700; letter-spacing:.22em; text-align:center;
          padding:16px 10px; font-size:1.25rem; margin-bottom:16px;
          clip-path:polygon(14px 0,100% 0,calc(100% - 14px) 100%,0 100%); }
.banner.ok   { color:var(--ok);  background:rgba(61,255,168,.09); border:1px solid rgba(61,255,168,.45);
               text-shadow:0 0 14px rgba(61,255,168,.5); }
.banner.bad  { color:#fff; background:rgba(255,61,110,.22); border:1px solid var(--bad);
               text-shadow:0 0 14px rgba(255,61,110,.9); animation:flash 1s infinite; }
.banner.dead { color:var(--warn); background:rgba(255,184,77,.08); border:1px solid var(--warn); animation:blink 1.2s infinite; }

/* layout */
.main { display:grid; grid-template-columns:330px 1fr; gap:18px; }
@media (max-width:980px){ .main{ grid-template-columns:1fr; } }
.panel { background:var(--panel); border:1px solid var(--line); padding:16px; }
.panel h4 { margin:0 0 12px; font-family:'Chakra Petch'; font-weight:500; font-size:.8rem;
            letter-spacing:.3em; color:var(--dim); }

/* radar */
.radar { position:relative; width:250px; height:250px; margin:6px auto 16px; border-radius:50%;
         border:1px solid var(--line);
         background:
           repeating-radial-gradient(circle at 50% 50%, transparent 0 40px, rgba(77,232,255,.22) 40px 41px),
           radial-gradient(circle, rgba(77,232,255,.10), transparent 72%); }
.radar::before, .radar::after { content:""; position:absolute; background:rgba(77,232,255,.22); }
.radar::before { left:50%; top:0; bottom:0; width:1px; }
.radar::after  { top:50%; left:0; right:0; height:1px; }
.sweep { position:absolute; inset:0; border-radius:50%;
         background:conic-gradient(from 0deg, transparent 0 290deg, rgba(77,232,255,.55) 360deg);
         animation:spin 4s linear infinite; }
.radar.alert .sweep { background:conic-gradient(from 0deg, transparent 0 290deg, rgba(255,61,110,.6) 360deg); }
.radar.dead  .sweep { animation:none; background:none; }
.blip { position:absolute; width:11px; height:11px; border-radius:50%; background:var(--bad);
        box-shadow:0 0 12px 3px rgba(255,61,110,.8); animation:blink .7s infinite; }
.b0{ left:68%; top:22%; } .b1{ left:24%; top:30%; } .b2{ left:74%; top:64%; }
.b3{ left:30%; top:72%; } .b4{ left:50%; top:12%; }

.stat { display:flex; justify-content:space-between; font-size:.85rem; padding:6px 0;
        border-bottom:1px dashed rgba(77,232,255,.15); }
.stat span:first-child { color:var(--dim); }

/* detector rows */
.det { display:grid; grid-template-columns:14px 1fr auto; gap:14px; align-items:center;
       padding:14px 14px; margin-bottom:10px; border:1px solid var(--line); border-left-width:4px;
       background:rgba(4,12,20,.7); }
.det .nm { font-family:'Chakra Petch'; font-weight:700; font-size:1.1rem; letter-spacing:.1em; }
.det .ds { font-size:.78rem; color:var(--dim); margin-top:2px; }
.det .rt { text-align:right; }
.pill { display:inline-block; font-family:'Chakra Petch'; font-weight:700; letter-spacing:.16em;
        padding:5px 14px; font-size:.95rem; border:1px solid; }
.det .cnt { font-size:.74rem; color:var(--dim); margin-top:5px; }
.dot { width:12px; height:12px; border-radius:50%; }

.det.ok  { border-color:rgba(61,255,168,.35); border-left-color:var(--ok); }
.det.ok .dot { background:var(--ok); box-shadow:0 0 9px var(--ok); }
.det.ok .pill { color:var(--ok); border-color:rgba(61,255,168,.5); }
.det.bad { border-color:var(--bad); background:rgba(60,6,20,.75); animation:glow 1.1s infinite; }
.det.bad .dot { background:var(--bad); box-shadow:0 0 12px var(--bad); animation:blink .6s infinite; }
.det.bad .pill { color:#fff; background:var(--bad); border-color:var(--bad); }
.det.dead { border-color:#2c3a42; border-left-color:#2c3a42; color:#5d6f77; }
.det.dead .dot { background:#2c3a42; }
.det.dead .pill { color:#5d6f77; border-color:#2c3a42; }

/* event terminal */
.term { margin-top:18px; }
.ev { font-size:.84rem; padding:4px 0; border-bottom:1px dashed rgba(77,232,255,.12);
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.ev .t { color:var(--dim); } .ev .k { font-weight:700; margin:0 6px; } .ev .d { color:var(--tx); }
.k-DEAUTH,.k-EVIL_TWIN { color:var(--bad); }
.k-BEACON { color:var(--warn); } .k-PCAP_SNIFF { color:var(--cy); }
.none { color:var(--dim); font-size:.85rem; }
.cur::after { content:"▋"; color:var(--cy); animation:blink 1s infinite; margin-left:4px; }

@keyframes spin  { to { transform:rotate(360deg); } }
@keyframes blink { 50% { opacity:.2; } }
@keyframes flash { 50% { background:rgba(255,61,110,.38); } }
@keyframes glow  { 50% { box-shadow:0 0 22px rgba(255,61,110,.55); } }
</style>
""",
    unsafe_allow_html=True,
)

view = st.empty()
last_good = None

while True:
    try:
        with open(LOG_PATH) as f:
            last_good = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass

    try:
        age = time.time() - os.path.getmtime(LOG_PATH)
    except OSError:
        age = None

    stalled = last_good is None or age is None or age > STALE_SEC
    events = (last_good or {}).get("events", [])

    # per-detector event count + last-seen time (from the last 50 logged events)
    counts, lastseen = {}, {}
    for e in events:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
        lastseen[e["type"]] = e["time"][11:]

    rows, active = [], []
    for i, (key, label, desc) in enumerate(DETECTORS):
        if stalled:
            cls, pill = "dead", "NO DATA"
        elif last_good.get(key):
            cls, pill = "bad", "DETECTED"
            active.append((i, label))
        else:
            cls, pill = "ok", "CLEAR"
        seen = f'last {lastseen[key]}' if key in lastseen else "no events"
        rows.append(
            f'<div class="det {cls}"><div class="dot"></div>'
            f'<div><div class="nm">{label}</div><div class="ds">{desc}</div></div>'
            f'<div class="rt"><span class="pill">{pill}</span>'
            f'<div class="cnt">{counts.get(key, 0)} events · {seen}</div></div></div>'
        )

    if stalled:
        banner = '<div class="banner dead">ENGINE OFFLINE — SENSOR DATA NOT TRUSTWORTHY</div>'
        radar_cls, blips = "dead", ""
        engine = "OFFLINE"
    elif active:
        names = " · ".join(l.upper() for _, l in active)
        banner = f'<div class="banner bad">⚠ INTRUSION ACTIVE — {html.escape(names)}</div>'
        radar_cls = "alert"
        blips = "".join(f'<div class="blip b{i}"></div>' for i, _ in active)
        engine = "ONLINE"
    else:
        banner = '<div class="banner ok">AIRSPACE NOMINAL — NO THREATS DETECTED</div>'
        radar_cls, blips = "", ""
        engine = "ONLINE"

    up = int(time.time() - START)
    uptime = f"{up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}"
    phase = -(time.time() % 4)          # keep the radar sweep in phase across re-renders

    ev_html = ""
    for e in events[-12:][::-1]:
        ev_html += (f'<div class="ev"><span class="t">[{html.escape(e["time"][11:])}]</span>'
                    f'<span class="k k-{html.escape(e["type"])}">{html.escape(e["type"])}</span>'
                    f'<span class="d">{html.escape(e["detail"])}</span></div>')
    if not ev_html:
        ev_html = '<div class="none">no events recorded</div>'

    age_txt = "—" if age is None else f"{age:.1f}s"
    view.markdown(
        f'<div class="hdr"><div class="logo">WIDS<span> // SENTINEL</span></div>'
        f'<div class="meta"><div>SENSOR <b>wlan1 · monitor</b></div>'
        f'<div>PROTO <b>802.11</b></div>'
        f'<div>{time.strftime("%Y-%m-%d")} <b>{time.strftime("%H:%M:%S")}</b></div></div></div>'
        f'{banner}'
        f'<div class="main">'
        f'<div class="panel"><h4>// AIRSPACE RADAR</h4>'
        f'<div class="radar {radar_cls}"><div class="sweep" style="animation-delay:{phase:.2f}s"></div>{blips}</div>'
        f'<div class="stat"><span>ENGINE</span><span>{engine}</span></div>'
        f'<div class="stat"><span>LOG AGE</span><span>{age_txt}</span></div>'
        f'<div class="stat"><span>ACTIVE THREATS</span><span>{len(active)} / {len(DETECTORS)}</span></div>'
        f'<div class="stat"><span>CONSOLE UPTIME</span><span>{uptime}</span></div></div>'
        f'<div class="panel"><h4>// DETECTION MODULES</h4>{"".join(rows)}</div>'
        f'</div>'
        f'<div class="panel term"><h4>// EVENT STREAM</h4>{ev_html}<div class="cur"></div></div>',
        unsafe_allow_html=True,
    )
    time.sleep(REFRESH_SEC)
