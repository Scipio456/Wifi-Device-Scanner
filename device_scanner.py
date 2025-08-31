import scapy.all as scapy
import argparse
import logging
import socket
import time
from datetime import datetime
import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor

# WARNING: This script is for educational use only. Only scan networks you own or have explicit permission to scan.
# Unauthorized network scanning may violate local laws and regulations. The authors are not responsible for misuse.

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(filename='devices.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_arguments():
    """Parse command-line arguments for the network scanner"""
    parser = argparse.ArgumentParser(
        description="Network Device Scanner for educational use. Scans your local network only. Ensure you have permission to scan the target network. Unauthorized scanning may be illegal."
    )
    parser.add_argument(
        "target",
        help="Target IP range to scan (e.g., <your-ip-range>). Use your local network's IP range. Run 'ifconfig' (macOS) or 'ip addr' (Linux) to find it."
    )
    parser.add_argument(
        "--iface",
        required=True,
        help="Network interface to use (e.g., <your-interface>, such as eth0 for Linux, wlan0 for Wi-Fi, en0 for macOS). Run 'ifconfig' or 'ip link' to find it."
    )
    return parser.parse_args()

def get_vendor(mac):
    """Attempt to get vendor name from MAC address using an online API"""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except requests.exceptions.RequestException as e:
        logging.error(f"Vendor lookup failed for {mac}: {e}")
        return "Unknown"

def scan_ip(ip, iface):
    """Scan a single IP using ARP"""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False, iface=iface)[0]
        if answered_list:
            ip = answered_list[0][1].psrc
            mac = answered_list[0][1].hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            vendor = get_vendor(mac)
            logging.debug(f"Raw ARP response for {ip}: {answered_list.summary()}")
            return {"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor}
    except Exception as e:
        logging.error(f"Error scanning IP {ip}: {e}")
    return None

def scan_network(ip_range, iface):
    """Scan the network for devices using ARP requests"""
    print(f"Scanning {ip_range} on interface {iface}...")
    logging.info(f"Starting ARP scan for {ip_range} on {iface}")
    
    scapy.conf.iface = iface
    devices = []
    
    # Generate list of IPs to scan
    try:
        ip_list = [str(ip) for ip in scapy.IP(dst=ip_range).dst]
    except:
        logging.error(f"Invalid IP range: {ip_range}")
        print(f"Invalid IP range: {ip_range}")
        return devices
    
    # Scan IPs concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda ip: scan_ip(ip, iface), ip_list)
        for result in results:
            if result and result['ip'] not in [d['ip'] for d in devices]:
                devices.append(result)
                print(f"IP: {result['ip']}, MAC: {result['mac']}, Hostname: {result['hostname']}, Vendor: {result['vendor']}")
                logging.info(f"Device found - IP: {result['ip']}, MAC: {result['mac']}, Hostname: {result['hostname']}, Vendor: {result['vendor']}")
    
    if not devices:
        print(f"No devices found with ARP on {ip_range}. Trying ICMP scan...")
        logging.info(f"No devices found with ARP on {ip_range}")
    
    return devices

def ping_scan(ip_range, iface):
    """Perform an ICMP ping scan as a fallback"""
    print(f"Performing ICMP ping scan on {ip_range}...")
    logging.info(f"Starting ICMP ping scan for {ip_range} on {iface}")
    devices = []
    try:
        scapy.conf.iface = iface
        answered, _ = scapy.sr(scapy.IP(dst=ip_range)/scapy.ICMP(), timeout=6, verbose=False, retry=5)
        for pkt in answered:
            ip = pkt[1].src
            mac = pkt[1].hwsrc if pkt[1].hwsrc else "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            vendor = get_vendor(mac) if mac != "Unknown" else "Unknown"
            if ip not in [d['ip'] for d in devices]:
                devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
                print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
                logging.info(f"Device found (ICMP) - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
                logging.debug(f"Raw ICMP response for {ip}: {pkt.summary()}")
    except Exception as e:
        print(f"ICMP scan error: {e}")
        logging.error(f"ICMP scan failed: {e}")
    return devices

def tcp_scan(ip_range, iface):
    """Perform a TCP SYN scan as a fallback"""
    print(f"Performing TCP SYN scan on {ip_range}...")
    logging.info(f"Starting TCP SYN scan for {ip_range} on {iface}")
    devices = []
    try:
        scapy.conf.iface = iface
        # Scan common ports for faster results
        answered, _ = scapy.sr(scapy.IP(dst=ip_range)/scapy.TCP(dport=[22, 80, 443, 3389, 8080], flags="S"), timeout=6, verbose=False, retry=5)
        for pkt in answered:
            ip = pkt[1].src
            mac = pkt[1].hwsrc if pkt[1].hwsrc else "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            vendor = get_vendor(mac) if mac != "Unknown" else "Unknown"
            if ip not in [d['ip'] for d in devices]:
                devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
                print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
                logging.info(f"Device found (TCP) - IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}")
                logging.debug(f"Raw TCP response for {ip}: {pkt.summary()}")
    except Exception as e:
        print(f"TCP scan error: {e}")
        logging.error(f"TCP scan failed: {e}")
    return devices

def main():
    """Main function to run the network scanner"""
    args = get_arguments()
    start_time = time.time()
    
    try:
        devices = scan_network(args.target, args.iface)
        if len(devices) < 3:  # Try ICMP if fewer than expected devices
            devices.extend(ping_scan(args.target, args.iface))
        if len(devices) < 3:  # Try TCP if still fewer than expected
            devices.extend(tcp_scan(args.target, args.iface))
        if not devices:
            print(f"No devices found on {args.target}. Check network settings, client isolation, or device firewalls.")
            logging.warning(f"No devices found on {args.target}")
        else:
            # Remove duplicates by IP
            seen_ips = set()
            unique_devices = []
            for device in devices:
                if device['ip'] not in seen_ips:
                    unique_devices.append(device)
                    seen_ips.add(device['ip'])
            devices = unique_devices
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
        print(f"Found {len(devices)} devices:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, Vendor: {device['vendor']}")
        logging.info(f"Scan completed - Found {len(devices)} devices")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Scan failed: {e}")

if __name__ == "__main__":
    print("Network Device Scanner - Educational Use Only")
    print("WARNING: Only scan networks you own or have explicit permission to scan.")
    print("Unauthorized scanning may violate local laws and regulations.")
    print("Usage: sudo python3 device_scanner.py <your-ip-range> --iface <your-interface>")
    print("Find your IP range with 'ifconfig' or 'ip addr' and interface with 'ifconfig' or 'ip link'.")
    main()