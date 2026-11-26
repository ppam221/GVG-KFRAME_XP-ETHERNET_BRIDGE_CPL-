# NTv2 — Universal GVG K-Frame CPL Bridge (`V100`)

A Python WebSocket-to-UDP bridge for Grass Valley (GVG) K-Frame video switchers (compatible with firmware `14.7.1` – `20.1.1`). It implements the full GVG UDP handshake, dynamic port negotiation, heartbeat supervision, and real-time TCP ETP tally parsing.
Serial 422 Editor mode is for future implementation.
---

## Features

* **Full GVG UDP Session State Machine**: Executes the two-stage UDP handshake (`5000` / `5001` port announcement -> dynamic comms port), suite selection (`Suite 1`–`4`), packet acknowledgments, and 1-second heartbeat keep-alives with automatic exponential back-off reconnection.
* **5 M/E Bus Support**: Controls and monitors `ME1` (`0`), `ME2` (`1`), `ME3` (`2`), `PGM` (`3`), and `ME4` (`4`).
* **Switcher Control**:
  * **Crosspoints**: Route sources (`1–809`) to A (`pgm`) and B (`pvw`) buses.
  * **Transitions**: Trigger `CUT` and `AUTO` transitions per M/E.
  * **AUX Routing**: Direct source takes on AUX buses `1–48`.
  * **Transition & Keyer Rates**: Set durations in seconds (`0–99s`) or frames (auto-converted via `--fps`).
  * **Keyers**: Turn keyers `1–8` on/off per M/E.
  * **Macro Playback**: Queued execution of macros `1–999` with frame acknowledgment tracking.
* **Dual Real-Time Feedback**:
  * **TCP ETP Tally (`Port 2012`)**: Streams live XML tally updates (`VPEInputContribution` / `VPEOutputContribution`) to resolve actual on-air `PGM` and `PVW` sources.
  * **UDP ME-Bus Subscriptions**: Subscribes directly to A/B bus states across all 5 M/E addresses.
* **Safe Dry-Run Mode**: Runs without `--live` by default to validate JSON payloads and log commands without transmitting packets to the switcher.

---

## Running

Use `CONNECT100.bat` to start the bridge in live mode; it asks for the frame IP, software version, suite, FPS and panel name. `DRY-RUN100.bat` starts it without `--live`, so commands are logged but not sent.

On the GVG frame, add the IP of the bridge machine in two places: under the node control panel, and as the IP port for tally.

To change other options, edit the `python GVG_CPL_V100.py ...` line in `CONNECT100.bat`.

| Flag | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | IP address or hostname of the GVG K-Frame. |
| `--suite` | `1` | Target switcher suite (1, 2, 3 or 4). |
| `--ws-host` | `0.0.0.0` | Local WebSocket bind address. |
| `--ws-port` | `8765` | Local WebSocket bind port. |
| `--live` | off | Enable live UDP/TCP communication with the frame (omit for dry-run). |
| `--name` | `NTv2` | Base panel name shown in K-Frame connections (`<name> - Suite N`, max 24 ASCII chars). |
| `--ports` | auto | Override local UDP MAIN:LISTENER ports per suite, e.g. `1=6130:6131,2=6132:6133`. Defaults to 6130/6131 for suite 1, +2 per suite. |
| `--fps` | `30` | Frame rate used to convert `"frames": n` rates to seconds (e.g. 23.976, 24, 25, 29.97, 30, 50, 59.94, 60). |
| `--version` | `20.1.1` | Software version announced to the frame; set it to match your frame. |
| `--no-aux-sub` | off | Don't subscribe to the AUX buses (the UI then only shows the last AUX route it sent). |
| `--aux-sub-pid` | `0x104A` | Parameter ID used for the AUX subscriptions. |
| `--log-rx` | off | Log every inbound data packet from the frame (hex). |
| `--log-file` | none | Also write the log to this file, e.g. `aux_capture.log`. |

Ask Nava if you are lost. My recommendation is to give `GVG_CPL_V100.py` to your preferred AI assistant and have it build a custom web UI for your needs; the supported actions are documented at the top of the file.

## Requirements

* Python 3.9+
* `websockets` library:
  ```bash
  pip install websockets
  ```
