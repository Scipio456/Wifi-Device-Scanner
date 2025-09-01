# Network Device Scanner

A Python script to discover devices on your local network using ARP scans. For educational purposes only. Modification of this software is prohibited.

## Features
- **ARP Scan**: Maps IP addresses to MAC addresses for device discovery.
- **Dynamic IP Detection**: Auto-detects network range if not specified, ideal for Wi-Fi or hotspots.
- **Interface Specification**: Requires a network interface (e.g., `en0`, `wlan0`).
- **Improved Hostname Resolution**: Uses reverse DNS with increased timeout.
- **Robust Vendor Lookup**: Uses a local OUI database with API fallback to avoid rate limits.
- **Logging**: Saves detailed debug logs to `devices.log` without identifiable metadata.

## Usage

```bash
sudo python3 device_scanner.py <your-ip-range> --iface <your-interface>
```

Examples:
- Scan a specific range:
  ```bash
  sudo python3 device_scanner.py 192.168.1.0/24 --iface en0
  ```
- Scan a single IP:
  ```bash
  sudo python3 device_scanner.py 192.168.1.108 --iface en0
  ```
- Auto-detect network range:
  ```bash
  sudo python3 device_scanner.py --iface en0
  ```

## Requirements

Install dependencies:
```bash
pip3 install scapy requests netifaces certifi urllib3==1.26.18
```

- Requires Python 3.6+.
- Must run with `sudo` due to raw socket access for ARP scans.
- macOS/Linux only (Windows requires additional configuration).
- Optional: Download full OUI database from `https://standards.ieee.org/products-services/regauth/oui/` for offline vendor lookup.

## Finding Parameters

- **IP Range**: Run `ifconfig` (macOS) or `ip addr` (Linux) to find your subnet. Look for `inet` and `netmask`. Example: `192.168.1.0/24`.
- **Interface**: Run `ifconfig` or `ip link` to find your network interface (e.g., `en0` for Wi-Fi on macOS, `wlan0` for Linux).
- **Gateway**: Find your gateway with `netstat -rn | grep default` for router admin access.

## Warnings

- **Legal Notice**: Only use this script on networks you own or have explicit permission to scan. Unauthorized scanning may violate local laws and regulations.
- **No Modification**: This software may not be modified. See the `LICENSE` file for details.
- **Responsibility**: The authors are not responsible for any misuse of this script.

## Troubleshooting

If fewer devices are detected (e.g., 2 instead of 3) or hostnames/vendors are "Unknown":
- **Fewer Devices Detected**:
  - **Client Isolation**: Disable client/AP isolation in your router’s admin panel (e.g., `http://<gateway-ip>`). Common for hotspots.
  - **Interface**: Verify the correct interface with `ifconfig` or `ip link`. Ensure it matches `--iface` (e.g., `en0`).
  - **IP Range**: Confirm the IP range covers all devices. Check device IPs with `arp -a` or `ip neigh`.
  - **Permissions**: Run with `sudo`. Check `/dev/bpf*` usage: `sudo lsof /dev/bpf*`.
  - **Firewalls**: Ensure devices allow ARP responses. Test with `ping <device-ip>` or `nmap -sn <device-ip>`.
  - **Compare with Nmap**: Run `sudo nmap -sn <your-ip-range>` or `sudo nmap -PR -sn <your-ip-range>` to cross-check.
  - **Wireshark**: Capture traffic with `sudo wireshark -i <your-interface> -k` and filter for `arp`.
- **Hostname Issues**:
  - Enable router DNS or mDNS in the admin panel (e.g., `http://<gateway-ip>`).
  - Test with `dig -x <device-ip>` or `nslookup <device-ip>`.
  - Check `devices.log` for `socket.herror` errors.
- **Vendor Issues**:
  - Test API: `curl https://api.macvendors.com/00:14:22:01:23:45`. If it fails, check internet or rate limits.
  - Expand local OUI database with `oui.txt` from `https://standards.ieee.org/products-services/regauth/oui/`.
- **macOS LibreSSL Warning**: If you see a `NotOpenSSLWarning`, ensure `urllib3==1.26.18` is installed.
- **Logs**: Review `devices.log` for detailed errors (set to DEBUG level).
- **Hotspot Issues**: Some hotspots isolate clients. Test with a different network or disable isolation.

## License

This project is licensed under the Educational Use Only, No Modification License. See the `LICENSE` file for details.