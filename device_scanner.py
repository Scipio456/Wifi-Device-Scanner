"""
Network Device Scanner
Discovers devices on a local network using ARP requests.
For educational use only on networks you own. Modification prohibited.

Features:
- ARP scan to map IP to MAC addresses.
- Auto-detects network range and interface if not provided.
- Optional interface specification for manual override.
- Improved hostname resolution with increased timeout.
- Local OUI database for vendor lookup to avoid API rate limits.
- Logs results to 'devices.log' without identifiable metadata.
"""

import scapy.all as scapy
import argparse
import logging
import socket
import time
import netifaces
import requests
from typing import List, Dict

# Configure logging (generic, no identifiable info)
logging.basicConfig(
    filename='devices.log',
    level=logging.DEBUG,  # Increased to DEBUG for troubleshooting
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Static OUI database (subset; expand with full OUI list)
OUI_DATABASE = {
    "00:14:22": "Apple, Inc.",
    "00:16:17": "Samsung Electronics",
    "00:50:56": "VMware, Inc.",
    # Add more from https://standards.ieee.org/products-services/regauth/oui/
}

def get_default_interface() -> str:
    """
    Detect the network interface connected to the default gateway.
    Returns: Interface name or None if detection fails.
    """
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_ip, iface = gateways['default'][netifaces.AF_INET]
            logging.debug(f"Detected default gateway {gateway_ip} on interface {iface}")
            print(f"Detected interface: {iface} (gateway: {gateway_ip})")
            return iface
        else:
            # Fallback: Check common interfaces
            for iface in netifaces.interfaces():
                if iface.startswith(('en', 'wlan', 'eth', 'hotspot')):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        logging.debug(f"Fallback: Using interface {iface} with IPv4 address")
                        print(f"Fallback: Using interface {iface}")
                        return iface
        logging.warning("No default gateway or IPv4 interface found")
        print("No default gateway or IPv4 interface found")
        return None
    except Exception as e:
        logging.error(f"Failed to detect default interface: {e}")
        print(f"Error detecting default interface: {e}")
        return None

def get_network_range(iface: str) -> str:
    """
    Detect the network range for the given interface.
    Args:
        iface: Network interface.
    Returns: CIDR notation or None if detection fails.
    """
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            ip_parts = ip.split('.')
            mask_parts = netmask.split('.')
            network = '.'.join(str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4))
            prefix = sum(bin(int(x)).count('1') for x in mask_parts)
            logging.debug(f"Detected IP: {ip}, Netmask: {netmask}, Network: {network}/{prefix}")
            print(f"Detected network range: {network}/{prefix} on interface {iface}")
            return f"{network}/{prefix}"
        logging.warning(f"No IPv4 address found for interface {iface}")
        print(f"No IPv4 address found for interface {iface}")
        return None
    except Exception as e:
        logging.error(f"Failed to detect network range for {iface}: {e}")
        print(f"Error detecting network range for {iface}: {e}")
        return None

def get_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for target IP/range and optional interface.
    Returns: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Network Device Scanner for educational use only. Modification prohibited."
    )
    parser.add_argument(
        "target",
        nargs='?',
        default=None,
        help="Target IP or range (e.g., 192.168.1.0/24 or 192.168.1.108). If omitted, auto-detects network range."
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface (e.g., en0, wlan0). If omitted, auto-detects interface. Use 'ifconfig' or 'ip link' to find."
    )
    return parser.parse_args()

def get_vendor(mac: str) -> str:
    """
    Fetch vendor name for a MAC address using local OUI database and online API as fallback.
    Args:
        mac: MAC address.
    Returns: Vendor name or 'Unknown' if lookup fails.
    """
    mac_prefix = mac.upper()[:8].replace(':', '')
    # Try local OUI database first
    if mac_prefix in OUI_DATABASE:
        logging.debug(f"Vendor found in local OUI database for {mac}: {OUI_DATABASE[mac_prefix]}")
        return OUI_DATABASE[mac_prefix]
    
    # Fallback to API
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            vendor = response.text.strip()
            OUI_DATABASE[mac_prefix] = vendor  # Cache in-memory
            logging.debug(f"Vendor found via API for {mac}: {vendor}")
            return vendor
        logging.warning(f"API returned status {response.status_code} for {mac}")
        return "Unknown"
    except requests.exceptions.RequestException as e:
        logging.warning(f"Vendor lookup failed for {mac}: {e}")
        return "Unknown"

def get_hostname(ip: str) -> str:
    """
    Resolve hostname for an IP address.
    Args:
        ip: IP address.
    Returns: Hostname or 'Unknown' if resolution fails.
    """
    try:
        socket.setdefaulttimeout(5)  # Increased to 5 seconds
        hostname = socket.gethostbyaddr(ip)[0]
        logging.debug(f"Hostname resolved for {ip}: {hostname}")
        return hostname
    except socket.herror as e:
        logging.warning(f"Hostname resolution failed for {ip}: {e}")
        return "Unknown"

def scan_network(ip_range: str, iface: str) -> List[Dict]:
    """
    Scan the network for devices using ARP requests.
    Args:
        ip_range: IP address or range.
        iface: Network interface.
    Returns: List of device dictionaries.
    """
    print(f"Scanning {ip_range} on interface {iface}...")
    logging.info(f"Starting scan for {ip_range} on {iface}")
    
    devices = []
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, iface=iface, verbose=False, retry=3)[0]
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
            print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
            logging.info(f"Device found - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
        
        if not devices and "/" not in ip_range:
            print(f"No response from {ip_range}, retrying with longer timeout...")
            logging.info(f"Retrying single IP {ip_range}")
            answered_list = scapy.srp(arp_request_broadcast, timeout=10, iface=iface, verbose=False, retry=5)[0]
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                hostname = get_hostname(ip)
                vendor = get_vendor(mac)
                devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
                print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
                logging.info(f"Device found - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
        
        if not devices:
            print(f"No devices found at {ip_range}. Check network settings and try again.")
            logging.info(f"No devices found at {ip_range}")
    
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Scan failed for {ip_range}: {e}")
    
    return devices

def main():
    """Main function to orchestrate the network scan."""
    print("Network Device Scanner - Educational Use Only")
    print("Ensure you have permission to scan the target network!")
    print("Modification of this software is prohibited.")
    
    args = get_arguments()
    start_time = time.time()
    
    # Use provided interface or auto-detect
    iface = args.iface if args.iface else get_default_interface()
    if not iface:
        print("Error: Could not determine network interface. Please specify --iface or check network connection.")
        logging.error("Could not determine network interface")
        return
    
    # Debug: List available interfaces
    print("Available network interfaces:", netifaces.interfaces())
    logging.debug(f"Available interfaces: {netifaces.interfaces()}")
    
    # Use provided target or auto-detect network range
    target = args.target if args.target else get_network_range(iface)
    if not target:
        print(f"Error: Could not determine network range for interface {iface}. Please specify a target IP or range.")
        logging.error(f"Could not determine network range for {iface}")
        return
    
    try:
        # Validate IP or range
        if "/" not in target:
            socket.inet_aton(target)  # Validate single IP
        devices = scan_network(target, iface)
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
        print(f"Found {len(devices)} devices:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, Vendor: {device['vendor']}")
        logging.info(f"Scan completed - Found {len(devices)} devices")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        logging.info("Scan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Main function error: {e}")

if __name__ == "__main__":
    main()