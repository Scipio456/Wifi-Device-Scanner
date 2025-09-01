import scapy.all as scapy
import argparse
import logging
import socket
import time
import netifaces
import requests
import json
import urllib3

# Suppress urllib3 warnings (temporary for testing, see note below)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(filename='devices.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

def get_network_range():
    """Detect the local network's IP range"""
    try:
        # Get the default interface (e.g., Wi-Fi or hotspot interface)
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith(('en', 'wlan', 'eth', 'hotspot')):  # Common Wi-Fi interfaces
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    netmask = ip_info['netmask']
                    # Calculate CIDR notation
                    ip_parts = ip.split('.')
                    mask_parts = netmask.split('.')
                    network = '.'.join(str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4))
                    # Convert netmask to CIDR prefix
                    prefix = sum(bin(int(x)).count('1') for x in mask_parts)
                    return f"{network}/{prefix}"
        return None
    except Exception as e:
        print(f"Error detecting network range: {e}")
        logging.error(f"Error detecting network range: {e}")
        return None

def get_arguments():
    """Parse command-line arguments, with optional IP range"""
    parser = argparse.ArgumentParser(description="Network Device Scanner for educational use")
    parser.add_argument("target", nargs='?', default=None, 
                        help="Target IP or range If omitted, auto-detects network range.")
    return parser.parse_args()

def get_vendor(mac):
    """Attempt to get vendor name from MAC address using an online API"""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5, verify=False)  # Disable SSL verification for testing
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except requests.exceptions.RequestException as e:
        print(f"Vendor lookup failed for {mac}: {e}")
        return "Unknown"

def scan_network(ip_range):
    """Scan the network for devices using ARP requests"""
    print(f"Scanning {ip_range}...")
    logging.info(f"Starting scan for {ip_range}")
    
    # Create ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet and capture responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        vendor = get_vendor(mac)
        devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
        print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
        logging.info(f"Device found - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
    
    # Retry for single IP if no response
    if not devices and not "/" in ip_range:
        print(f"No response from {ip_range}, retrying with longer timeout...")
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, retry=2)[0]
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            vendor = get_vendor(mac)
            devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
            print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
            logging.info(f"Device found - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
    
    if not devices:
        print(f"No devices found at {ip_range}")
        logging.info(f"No devices found at {ip_range}")
    
    return devices

def main():
    args = get_arguments()
    start_time = time.time()
    
    # Use provided IP/range or auto-detect network range
    target = args.target if args.target else get_network_range()
    if not target:
        print("Error: Could not determine network range. Please specify a target IP or range.")
        logging.error("Could not determine network range")
        return
    
    try:
        devices = scan_network(target)
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
        print(f"Found {len(devices)} devices:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['ip']}, Hostname: {device['hostname']}, Vendor: {device['vendor']}")
        logging.info(f"Scan completed - Found {len(devices)} devices")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Scan failed: {e}")

if __name__ == "__main__":
    print("Network Device Scanner - Educational Use Only")
    print("Ensure you have permission to scan the target network!")
    main()

