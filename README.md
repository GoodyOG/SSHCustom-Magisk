# SSHCustom-Magisk

SSH tunnel transparent proxy for rooted Android devices. Route all device traffic through an SSH tunnel with automatic DNS-through-tunnel, transparent TCP redirection, SOCKS5 proxy, and hotspot sharing.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android-green.svg)](https://www.android.com/)
[![Magisk](https://img.shields.io/badge/Magisk-24.0%2B-00B39B.svg)](https://github.com/topjohnwu/Magisk)
[![KernelSU](https://img.shields.io/badge/KernelSU-0.5.0%2B-orange.svg)](https://github.com/tiann/KernelSU)

## ✨ Features

- **Transparent TCP Proxy** - All TCP traffic automatically routed through SSH tunnel
- **DNS-through-Tunnel** - DNS queries proxied as TCP to prevent leaks and fix "no internet" tags
- **SOCKS5 Server** - Local SOCKS5 proxy for apps that support it
- **Hotspot Sharing** - Share your tunneled connection via Wi-Fi/USB tethering
- **Web Dashboard** - Modern browser-based UI at `http://127.0.0.1:9190`
- **Always-On Daemon** - WebUI accessible even when tunnel is stopped
- **Profile Management** - Save multiple SSH server configurations
- **Transport Modes** - Support for payload injection, TLS wrapping, HTTP proxy chains
- **Zero Configuration** - Works out of the box, no iptables knowledge required
- **Captive Portal Bypass** - Fixes "no internet" warnings on all carrier types
- **Leak Prevention** - QUIC block, IPv6 disable, fail-closed routing

## 📸 Screenshots

<p align="center">
  <img src="docs/screenshot_home.png" width="200" alt="Home"/>
  <img src="docs/screenshot_profiles.png" width="200" alt="Profiles"/>
  <img src="docs/screenshot_runtime.png" width="200" alt="Runtime"/>
  <img src="docs/screenshot_settings.png" width="200" alt="Settings"/>
</p>

## 🚀 Installation

### Requirements
- Rooted Android device (Magisk 24.0+ or KernelSU 0.5.0+)
- Android 11+
- SSH server with password/keyboard-interactive auth

### Steps
1. Download [`SSHCustom-Magisk-v2.5.0.zip`](https://github.com/GoodyOG/SSHCustom-Magisk/releases/latest)
2. Open Magisk Manager or KSU Manager
3. Go to **Modules** → **Install from storage**
4. Select the downloaded ZIP
5. Reboot device
6. Open browser to `http://127.0.0.1:9190`

### First Time Setup
1. Navigate to **Profiles** tab
2. Tap **Add Profile** or edit default profile
3. Enter your SSH server details:
   - Host: your SSH server IP/domain
   - Port: SSH port (default 22)
   - Username: SSH username
   - Password: SSH password
4. Tap **Save**
5. On **Home** tab, tap **Start Tunnel**

## 🎯 Use Cases

### Personal VPN
Route your mobile data through your home server or VPS to:
- Bypass geographic restrictions
- Secure traffic on public Wi-Fi
- Access home network resources remotely

### Bug-Host Networks
Bypass carrier HTTP injection and zero-rating systems:
- MTN Nigeria, Airtel, Glo bug hosts
- Carrier captive portals
- Zero-rating detection bypass

### Privacy & Security
- Encrypt all traffic through SSH tunnel
- Prevent ISP tracking and throttling
- Secure DNS queries (no DNS leaks)

### Hotspot Sharing
Share your tunneled connection with:
- Other devices (laptop, tablet, TV)
- Friends/family
- IoT devices

## 📋 Configuration

### Transparent Proxy (Recommended)
All TCP traffic automatically routed through tunnel. Enable in **Settings** → **Transparent Proxy**.

### SOCKS5 Proxy
For apps that support SOCKS5:
- **Host**: `127.0.0.1`
- **Port**: `1080` (default)

### DNS
Three modes available in **Settings** → **DNS**:
- **Device DNS** (default) - Uses carrier DNS for resolution
- **Google DNS** - 8.8.8.8, 8.8.4.4
- **Cloudflare DNS** - 1.1.1.1, 1.0.0.1
- **Custom** - Your own DNS servers

### Hotspot
Enable in **Settings** → **Hotspot** to share connection:
- Wi-Fi hotspot
- USB tethering
- Bluetooth tethering

## 🔧 Advanced Features

### Transport Modes
- **Direct** - Plain SSH connection
- **HTTP Proxy** - Chain through HTTP proxy
- **TLS** - Wrap SSH in TLS
- **Payload** - Custom HTTP payload injection

### Payload Templates
For bug-host bypass with SNI/Host tricks:
```
GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]
```

See docs for advanced payload templates.

## 🐛 Troubleshooting

### "No Internet" Tag in Chrome
Fixed in v2.5.0! If you still see it:
```bash
su
settings put global captive_portal_mode 0
settings put global captive_portal_server localhost
settings put global captive_portal_http_url "http://localhost/generate_204"
cmd connectivity reevaluate
```

### Apps Using Direct Connection
Some apps bypass system proxy. Solutions:
1. Enable **Transparent Proxy** (catches all TCP)
2. Use app-specific SOCKS5 settings if available
3. Check **UID Exemption** isn't blocking the app

### Slow Speeds
1. Check your SSH server upload bandwidth
2. Increase buffer size in **Settings** → **Performance**
3. Try different transport modes
4. Check if carrier throttling SSH

### Tunnel Disconnects
1. Check **keepalive_seconds** in settings (default 15s)
2. Verify SSH server isn't timing out connections
3. Check mobile data stability
4. Review logs in **Runtime** tab

## 📖 Architecture

### Components
- **Go Daemon** (`sshcustomd`) - Core engine, single SSH connection
- **iptables Rules** - REDIRECT for transparent TCP, DNAT for DNS
- **WebUI** - React-like vanilla JS dashboard (embedded in binary)
- **Shell Scripts** - Module lifecycle, watchdog, network cleanup

### How It Works
1. Daemon opens single SSH connection (multiplexed)
2. iptables REDIRECT catches TCP → daemon transparent listener
3. Daemon reads original destination via SO_ORIGINAL_DST
4. Opens SSH channel to original destination
5. Bidirectional data relay with configurable buffers

### DNS Flow
```
App DNS Query (UDP:53)
  ↓
iptables DNAT → 127.0.0.1:5353
  ↓
Daemon DNS Forwarder
  ↓
TCP DNS through SSH tunnel → 8.8.8.8
  ↓
Response back to app
```

## 🔐 Security Notes

- **Passwords in plaintext**: `profiles.json` stores passwords unencrypted (0600 permissions). Acceptable for personal use on encrypted device storage.
- **No authentication**: Dashboard has no auth (localhost-only). Don't expose port 9190 externally.
- **Root required**: Module runs as root, has full device access. Only install from trusted sources.

## 🛠️ Building from Source

### Prerequisites
```bash
# Install Go 1.21+
# Install Python 3.8+
```

### Build
```bash
./build.sh
```

Output: `dist/SSHCustom-Magisk-v2.5.0.zip`

### Manual Build Steps
```bash
# Build binaries
GOOS=linux GOARCH=arm64 go build -o src/module/bin/arm64/sshcustomd ./cmd/sshcustomd
GOOS=linux GOARCH=arm GOARM=7 go build -o src/module/bin/arm/sshcustomd ./cmd/sshcustomd

# Package module
python3 scripts/package_module.py src/module dist/SSHCustom-Magisk-v2.5.0.zip
```

## 📄 API Documentation

REST API available at `http://127.0.0.1:9190/api/v1/`

See [docs/openapi.yaml](docs/openapi.yaml) for full API spec.

### Quick Examples
```bash
# Get status
curl http://127.0.0.1:9190/api/v1/status

# Start tunnel
curl -X POST http://127.0.0.1:9190/api/v1/control -d '{"action":"start"}'

# Stop tunnel
curl -X POST http://127.0.0.1:9190/api/v1/control -d '{"action":"stop"}'
```

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📜 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 🙏 Credits

- Inspired by vpnchain SSH tunnel architecture
- Built with [x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh)
- Icons and design inspired by Material Design

## ⚠️ Disclaimer

This tool is for educational and personal use. Users are responsible for complying with their ISP's terms of service and local laws. The author is not responsible for misuse or any damages caused by this software.

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/GoodyOG/SSHCustom-Magisk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GoodyOG/SSHCustom-Magisk/discussions)
- **Dashboard**: `http://127.0.0.1:9190` (after installation)

---

**Made with ❤️ for the Android community**
