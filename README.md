# SSHCustom-Magisk

A transparent SSH tunnel proxy for rooted Android devices. Route all device traffic through an SSH tunnel with automatic DNS-through-tunnel, transparent TCP redirection, SOCKS5 proxy, and hotspot sharing.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Magisk](https://img.shields.io/badge/Magisk-24.0%2B-00B39B.svg)](https://github.com/topjohnwu/Magisk)
[![KernelSU](https://img.shields.io/badge/KernelSU-0.5.0%2B-orange.svg)](https://github.com/tiann/KernelSU)

## 📸 Screenshots

<p align="center">
  <img src="docs/screenshot_home.png" width="200" alt="Home"/>
  <img src="docs/screenshot_profiles.png" width="200" alt="Profiles"/>
  <img src="docs/screenshot_runtime.png" width="200" alt="Runtime"/>
  <img src="docs/screenshot_settings.png" width="200" alt="Settings"/>
</p>

## ✨ Key Features
- **Transparent TCP Proxy**: All TCP traffic routed automatically.
- **DNS-through-Tunnel**: Secure DNS queries without leaks.
- **Hotspot Sharing**: Share your tunneled connection via Wi-Fi or USB tethering.
- **Web Dashboard**: Modern browser UI accessible at `http://127.0.0.1:9190`.
- **Zero Configuration**: Works instantly via iptables routing, no complex manual setup needed.

## 🚀 Installation

1. Download the latest release from the [Releases page](https://github.com/GoodyOG/SSHCustom-Magisk/releases/latest).
2. Install the downloaded `.zip` via **Magisk** or **KernelSU**.
3. Reboot your device.
4. Open your web browser and navigate to `http://127.0.0.1:9190`.
5. Add your SSH server profile in the Profiles tab and tap **Start Tunnel**.

**Accessing the WebUI:**

- **KernelSU / KSU-Next** — open the module WebUI directly from the manager.
- **WebUI-X Portable** — install [WebUI-X Portable](https://github.com/MMRLApp/WebUI-X-Portable) (also available on [Google Play](https://play.google.com/store/apps/details?id=com.dergoogler.mmrl.wx)). SSHCustom-Magisk appears in its module list with full edge-to-edge support. You can also **add a home screen shortcut** for instant access from the app's module list.
- **Magisk** — install [KsuWebUI Standalone](https://github.com/KOWX712/KsuWebUIStandalone/releases), grant it root access, then open SSHCustom's WebUI from within it.
- **Browser** — navigate to `http://127.0.0.1:9190/` on the device.


## 🛠️ Building from Source
Ensure you have Go 1.21+ and Python 3.8+ installed.
```bash
./build.sh
```

## 📖 Documentation & Support
- API documentation is available on your device at `http://127.0.0.1:9190/api/v1/`
- Full version history is in [CHANGELOG.md](CHANGELOG.md).
- Need help? Check the [Discussions](https://github.com/GoodyOG/SSHCustom-Magisk/discussions) or open a [GitHub Issue](https://github.com/GoodyOG/SSHCustom-Magisk/issues).

---
**Disclaimer:** This tool is for educational use. Users are responsible for complying with their ISP's terms of service and local laws. 
