# Network Device Scanner

A Python script to discover devices on your local network using ARP, ICMP, and TCP scans. For educational purposes only. Modification of this software is prohibited.

## Features
- **ARP Scan**: Maps IP addresses to MAC addresses for device discovery.
- **ICMP Scan**: Uses ping to detect devices not responding to ARP.
- **TCP Scan**: Checks common ports (e.g., SSH, HTTP, HTTPS) for active services.
- **Dynamic IP Detection**: Auto-detects network range if not specified, ideal for Wi-Fi or hotspots.
- **Interface Specification**: Requires a network interface (e.g., `en0`, `wlan0`).
- **Logging**: Saves results to `devices.log` without identifiable metadata.

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
pip3 install scapy requests netifaces
```

- Requires Python 3.6+.
- Must run with `sudo` due to raw socket access for ARP and TCP scans.
- macOS/Linux only (Windows requires additional configuration).

## Finding Parameters

- **IP Range**: Run `ifconfig` (macOS) or `ip addr` (Linux) to find your subnet. Look for `inet` and `netmask`. Example: `192.168.1.0/24`.
- **Interface**: Run `ifconfig` or `ip link` to find your network interface (e.g., `en0` for Wi-Fi on macOS, `wlan0` for Linux).
- **Gateway**: Find your gateway with `netstat -rn | grep default` for router admin access.

## Warnings

- **Legal Notice**: Only use this script on networks you own or have explicit permission to scan. Unauthorized scanning may violate local laws and regulations.
- **No Modification**: This software may not be modified. See the `LICENSE` file for details.
- **Responsibility**: The authors are not responsible for any misuse of this script.

## Troubleshooting

If fewer devices are detected than expected:
- **Check Router Settings**: Disable client/AP isolation in your router’s admin panel (e.g., `http://<gateway-ip>`).
- **Device Firewalls**: Ensure devices allow ICMP (ping) or TCP responses. Test with `ping <device-ip>`.
- **Correct Parameters**: Verify IP range and interface match your network. Use `ifconfig` or `ip addr`.
- **Compare with Nmap**: Run `sudo nmap -sn <your-ip-range>` or `sudo nmap -PR -sn <your-ip-range>` to cross-check.
- **Debug with Wireshark**: Capture traffic with `sudo wireshark -i <your-interface> -k` and filter for `arp or icmp or tcp.port in {22 80 443 3389 8080}`.
- **Check Logs**: Review `devices.log` for errors or raw packet data.
- **Hotspot Issues**: Some hotspots isolate clients. Test with a different network or disable isolation.

## License

This project is licensed under the Educational Use Only, No Modification License. See the `LICENSE` file for details.