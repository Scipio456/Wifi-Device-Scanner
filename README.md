# Network Device Scanner

A Python script to discover devices on your local network using ARP, ICMP, and TCP scans. For educational purposes only. Modification of this software is prohibited.

## Usage

```bash
sudo python3 device_scanner.py <your-ip-range> --iface <your-interface>
```

## Requirements

Install dependencies:

```bash
pip3 install scapy requests
```

- Requires Python 3.6+.
- Must run with `sudo` due to raw socket access for network scanning.

## Finding Parameters

- **IP Range**: Run `ifconfig` (macOS) or `ip addr` (Linux) to find your subnet. Look for `inet` and `netmask`.
- **Interface**: Run `ifconfig` or `ip link` to find your network interface.

## Warnings

- **Legal Notice**: Only use this script on networks you own or have explicit permission to scan. Unauthorized scanning may violate local laws and regulations.
- **No Modification**: This software may not be modified. See the LICENSE file for details.
- **Responsibility**: The authors are not responsible for any misuse of this script.

## Troubleshooting

If fewer devices are detected than expected:

- **Check Router Settings**: Disable client/AP isolation in your router’s admin panel (e.g., `http://<gateway-ip>`). Find your gateway with `netstat -rn | grep default`.
- **Device Firewalls**: Ensure devices allow ICMP (ping) or TCP responses. Test with `ping <device-ip>`.
- **Correct Parameters**: Verify IP range and interface match your network.
- **Compare with Nmap**: Run `sudo nmap -sn <your-ip-range>` or `sudo nmap -PR -sn <your-ip-range>` to cross-check.
- **Debug with Wireshark**: Capture traffic with `sudo wireshark -i <your-interface> -k` and filter for `arp or icmp or tcp.port in {22 80 443 3389 8080}`.
- **Check Logs**: Review `devices.log` for errors or raw packet data.

## License

This project is licensed under the Educational Use Only, No Modification License. See the `LICENSE` file for details.