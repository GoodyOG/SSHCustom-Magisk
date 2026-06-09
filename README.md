# SSHCustom-Magisk

Transparent SSH tunnel proxy for rooted Android. Routes all device **TCP + UDP** traffic through a single SSH connection — no per-app configuration, no VPN slot consumed. Uses TPROXY (mangle table) for zero-destination-rewrite transparent proxying.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Magisk](https://img.shields.io/badge/Magisk-24.0%2B-00B39B.svg)](https://github.com/topjohnwu/Magisk)
[![KernelSU](https://img.shields.io/badge/KernelSU-0.5.0%2B-orange.svg)](https://github.com/tiann/KernelSU)

## Screenshots

<p align="center">
  <img src="docs/screenshot_home.png" width="200" alt="Home"/>
  <img src="docs/screenshot_profiles.png" width="200" alt="Profiles"/>
  <img src="docs/screenshot_runtime.png" width="200" alt="Runtime"/>
  <img src="docs/screenshot_settings.png" width="200" alt="Settings"/>
</p>

## Features

- **Transparent TCP + UDP proxy** — all device traffic through one SSH connection. TCP uses TPROXY, UDP tunnels via BadVPN UDPGW.
- **DNS-through-tunnel** — queries proxied as TCP DNS through SSH, preventing leaks.
- **Fast reconnect** — dead-connection detection in 5–16s with auto-reconnect and exponential backoff.
- **SOCKS5 proxy** — local proxy at `127.0.0.1:1080`.
- **Hotspot sharing** — share the tunnel over Wi-Fi, USB, or Bluetooth tethering.
- **Web dashboard** — Material 3 UI at `http://127.0.0.1:9190`.
- **Lean engine** — single SSH connection with RFC 4254 multiplexing (~13 MB idle, ~30–40 MB under load).
- **Multiple transport modes** — direct SSH, HTTP proxy, TLS/SNI, payload injection.
- **Dropbear compatible** — vendored x/crypto with Dropbear patches.
- **KSU / KSU Next compatible** — stable module display across all root managers.

### UDP Proxy

UDP requires [BadVPN UDPGW](https://github.com/ambrop72/badvpn) running on your SSH server (default port 7300). Most server panels include it by default. If missing, SSHCustom logs once and silently skips UDP — TCP still works normally.

## Installation

1. Download the latest release ZIP from [Releases](https://github.com/GoodyOG/SSHCustom-Magisk/releases/latest).
2. Flash in **Magisk 24.0+** or **KernelSU 0.5.0+**.
3. Reboot.
4. Open the WebUI, add your SSH profile in the **Profiles** tab, and tap **Start Tunnel**.

## Accessing the WebUI

- **KernelSU / KSU Next** — open the module WebUI directly from the manager.
- **Magisk** — install [KsuWebUI Standalone](https://github.com/KOWX712/KsuWebUIStandalone/releases), grant root, open SSHCustom.
- **WebUI-X Portable** — install [WebUI-X Portable](https://github.com/MMRLApp/WebUI-X-Portable).
- **Browser** — navigate to `http://127.0.0.1:9190` on the device.

## Building

Requires Go 1.23+ and Python 3.8+.

```bash
./build.sh
```

Cross-compiles for ARM64 and ARMv7, packages a flashable Magisk ZIP into `dist/`.

Full REST + SSE API spec in `docs/openapi.yaml`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
