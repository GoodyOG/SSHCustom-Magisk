# SSHCustom-Magisk

Transparent SSH tunnel proxy for rooted Android. Routes all device TCP traffic through a single SSH connection — no per-app configuration, no VPN slot consumed.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Magisk](https://img.shields.io/badge/Magisk-24.0%2B-00B39B.svg)](https://github.com/topjohnwu/Magisk)
[![KernelSU](https://img.shields.io/badge/KernelSU-0.5.0%2B-orange.svg)](https://github.com/tiann/KernelSU)
[![Release](https://img.shields.io/github/v/release/GoodyOG/SSHCustom-Magisk?label=release)](https://github.com/GoodyOG/SSHCustom-Magisk/releases/latest)

## How It Works

```
App → iptables REDIRECT → sshcustomd → SSH direct-tcpip → Your Server → Internet
UDP → direct carrier (low latency, game encryption protects traffic)
DNS → iptables DNAT → DNS forwarder → SSH TCP DNS → 8.8.8.8
```

- **TCP**: All device TCP traffic is caught by iptables REDIRECT, forwarded through a single SSH connection via RFC 4254 `direct-tcpip` channels.
- **UDP**: Non-DNS/QUIC UDP goes direct to the carrier with minimal latency. Perfect for gaming (CODM, PUBG, etc.) — game encryption protects the traffic, and there's no SSH tunnel overhead.
- **DNS**: UDP port 53 is redirected to a local forwarder that proxies queries as TCP DNS through the SSH tunnel to 8.8.8.8. This fixes "no internet" warnings on restrictive networks.
- **QUIC** (UDP 443/80): Blocked to force Chrome/YouTube to fall back to TCP, which is then tunneled.

## Features

- **Transparent TCP proxy** — all device TCP traffic routed through SSH via iptables REDIRECT. No per-app setup.
- **UDP passthrough** — game/VoIP UDP bypasses the tunnel for low latency. Games like CODM work out of the box.
- **DNS-through-tunnel** — device DNS queries proxied as TCP DNS through SSH to 8.8.8.8. Eliminates DNS leaks and fixes "no internet" on restrictive networks.
- **SOCKS5 proxy** — local proxy at `127.0.0.1:1080` for apps that support proxy configuration.
- **Hotspot sharing** — share the tunnel over Wi-Fi, USB, or Bluetooth tethering.
- **Web dashboard** — Material 3 UI at `http://127.0.0.1:9190` with Home, Profiles, Runtime, and Settings tabs. Always available even without an active tunnel.
- **Lean engine** — single SSH connection with RFC 4254 multiplexing. ~13 MB idle, ~30–40 MB under load.
- **Auto-reconnect** — exponential backoff (2s–60s) on unexpected disconnect with graceful fail-closed routing.
- **Stream retry** — failed `direct-tcpip` channels auto-retry up to 2x for transient server-side errors.
- **TCP keepalives** — `TCP_USER_TIMEOUT`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT` on carrier socket for fast dead-link detection.
- **Captive portal bypass** — daemon serves HTTP 204 locally at `/generate_204`. No "no internet" warnings.
- **QUIC blocking** — UDP 443/80 dropped to force browser TCP fallback through the tunnel.
- **IPv6 disabled** — prevents leaks past the IPv4-only REDIRECT.
- **Multiple transport modes** — Direct SSH, HTTP CONNECT proxy, TLS/SNI, payload injection.
- **Dropbear compatible** — vendored `x/crypto` with compatibility patches for Dropbear SSH servers.
- **Configurable DNS** — Device, Google, Cloudflare, or custom DNS for SSH endpoint resolution.

## Installation

1. Download the latest release ZIP from the [Releases page](https://github.com/GoodyOG/SSHCustom-Magisk/releases/latest).
2. Flash in **Magisk 24.0+** or **KernelSU 0.5.0+**.
3. Reboot your device.
4. Open the WebUI, add your SSH server profile in the **Profiles** tab, and tap **Start Tunnel**.

## Accessing the WebUI

- **KernelSU / KSU-Next** — open the module WebUI directly from the manager.
- **WebUI-X Portable** — install [WebUI-X Portable](https://github.com/MMRLApp/WebUI-X-Portable). SSHCustom appears in the module list with full edge-to-edge support.
- **Magisk** — install [KsuWebUI Standalone](https://github.com/KOWX712/KsuWebUIStandalone/releases), grant root, then open SSHCustom from within it.
- **Browser** — navigate to `http://127.0.0.1:9190` on the device.

## Requirements

- Android 7.0+ (API 24+)
- Rooted with Magisk 24.0+ or KernelSU 0.5.0+
- An SSH server (Dropbear or OpenSSH, with or without TLS/SNI wrapping)
- ARM64 (arm64-v8a) or ARMv7 (armeabi-v7a) device

## Building from Source

Requires Go 1.23+ and Python 3.8+.

```bash
./build.sh
```

The script cross-compiles for ARM64 and ARMv7, then packages a flashable Magisk ZIP into `dist/`.

Read `docs/openapi.yaml` for the full REST + SSE API specification.

## License

Apache 2.0 — see [LICENSE](LICENSE).

**Disclaimer:** This tool is for educational and personal use. Users are responsible for complying with their ISP's terms of service and local laws.
