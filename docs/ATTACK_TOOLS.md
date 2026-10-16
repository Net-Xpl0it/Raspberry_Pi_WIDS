# Test attack tools

The repo contains **no attack code**. To check that the detectors fire, I used two small, commercial pentest gadgets against my own network. This page explains briefly what they do and how each action looks to the WIDS.

| Tool | What it is | How it is used here |
|---|---|---|
| **HackCat V3** | A handheld ESP32 board with an OLED screen and two antennas. Its listed features include deauth, beacon spam, evil portal and a packet monitor. [Project page](https://www.hackster.io/hacker_nowful/hackcat-v3-india-s-first-multi-pentesting-device-a1a3bc) | The live demo photos ([records/live-demo-hackcat.md](../records/live-demo-hackcat.md)) |
| **M5Stack device** (Cardputer / M5StickC) running **Bruce** firmware | A pocket ESP32 computer. [Bruce](https://github.com/BruceDevices/firmware) is open-source ESP32 firmware with offensive Wi-Fi tools (deauth, beacon spam, evil portal, RAW sniffer, wardriving). | **TODO:** record which M5 model and Bruce version, and which test it was used for. No photo of it is in this repo yet. |

## How they work

Both tools are built around an **ESP32** microcontroller. The ESP32 radio can transmit hand-built 802.11 management frames, and that is all these attacks need. Management frames carry no encryption or signature on most networks, so anyone in range can forge them.

| Attack | What the tool transmits | Why it works | What the WIDS sees |
|---|---|---|---|
| **Deauth flood** | Forged *deauthentication* frames (subtype `0x000c`) that claim to come from your AP | Clients obey a deauth without checking who sent it, unless the network uses 802.11w (PMF) | Many `0x000c` frames per second → `DEAUTH` |
| **Beacon spam** | Hundreds of fake *beacon* frames (subtype `0x0008`), each with a different SSID and random BSSID | Clients list every beacon they hear | Many unique BSSIDs in a few seconds → `BEACON` |
| **Evil Twin / evil portal** | A rogue AP that advertises **your** SSID from another BSSID, often with a fake login page. If the page is not loaded, the tool says so (the "No HTML file selected" message in one photo). | A client picks the strongest signal for a name it trusts | Your SSID from an untrusted BSSID → `EVIL_TWIN` |
| **Probe flood / scanning** | Many *probe request* frames (subtype `0x0004`) | Probes are unauthenticated and sent to everyone | Many probes per second from one MAC → `PCAP_SNIFF` |

Detection details are in [DETECTION_RULES.md](DETECTION_RULES.md).

## Things to know

- **HackCat firmware:** the project page does not name the firmware the board runs, so this repo does not say.
- **Unintended effects:** during testing a nearby phone lost cellular service. Keep phones away and keep bursts short.
- **Probe rule limits:** a phone toggling Wi-Fi can look the same to the engine as a probe tool, so a `PCAP_SNIFF` alert alone does not identify the device.
- **Legal:** use these only on networks and devices you own or have written permission to test. See [Responsible use](../README.md#responsible-use).
