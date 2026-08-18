#!/usr/bin/env python3
"""
NetSentinel – Advanced Network Device Scanner with mDNS/SSDP, whitelist,
ARP spoofing detection, and optional port scanning.
"""

import argparse
import datetime
import ipaddress
import os
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
from collections import defaultdict

try:
    from scapy.all import arping, ARP, IP, TCP, sr1
except ImportError:
    print("Scapy is required. Install with: pip install scapy")
    sys.exit(1)

try:
    from manuf import manuf
except ImportError:
    manuf = None

try:
    import netifaces
except ImportError:
    netifaces = None

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Colorama is required. Install with: pip install colorama")
    sys.exit(1)

try:
    from zeroconf import ServiceBrowser, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

DEFAULT_DB = "network_devices.db"
DEFAULT_IP_FILE = "discovered_ips.txt"
DEFAULT_WHITELIST = "whitelist.txt"
DEFAULT_BLACKLIST = "blacklist.txt"
DEFAULT_INTERVAL = 40  # seconds
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]


def get_local_network():
    """Try to auto-detect local IPv4 network; otherwise ask user."""
    if netifaces:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get("addr")
                    netmask = addr.get("netmask")
                    if not ip or not netmask or ip.startswith("127."):
                        continue
                    try:
                        prefix = sum(
                            bin(int(x)).count("1") for x in netmask.split(".")
                        )
                        network = ipaddress.IPv4Network(
                            f"{ip}/{prefix}", strict=False
                        )
                        if network.is_link_local:
                            continue
                        return str(network)
                    except Exception:
                        continue

    return input("Enter network CIDR (e.g. 192.168.1.0/24): ")


def arp_scan(network):
    """
    Perform an ARP scan on the given network.
    Returns a list of dicts with 'ip' and 'mac'.
    """
    print(f"{Fore.CYAN}ARP scanning {network} ...{Style.RESET_ALL}")
    try:
        ans, _ = arping(str(network), timeout=2, verbose=False)
    except Exception as e:
        print(f"{Fore.RED}ARP scan failed: {e}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}Make sure you have the required permissions "
            "(root/admin) and Scapy/Npcap installed.{Style.RESET_ALL}"
        )
        return []

    devices = []
    for sent, received in ans:
        try:
            ip = received[ARP].psrc
            mac = received.src.lower()
            if mac and ip:
                devices.append({"ip": ip, "mac": mac})
        except Exception:
            continue
    return devices


def get_vendor(mac, parser):
    """Look up MAC vendor/manufacturer using the manuf library."""
    if parser:
        try:
            return parser.get_manuf(mac)
        except Exception:
            return None
    return None


def get_hostname(ip, timeout=1.0):
    """Reverse DNS lookup with a timeout to avoid blocking."""
    result = [None]

    def lookup():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=lookup)
    t.daemon = True
    t.start()
    t.join(timeout)
    return result[0]


class MyListener:
    """Zeroconf service listener."""
    def __init__(self):
        self.services = []

    def remove_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            self.services.append(info)


def discover_friendly_names(timeout=3):
    """
    Discover mDNS and SSDP friendly names on the local network.
    Returns a dictionary mapping IP -> friendly name.
    """
    friendly = {}
    threads = []

    # --- mDNS (Bonjour) ---
    if ZEROCONF_AVAILABLE:
        def mdns_worker():
            zc = Zeroconf()
            listener = MyListener()
            browser = ServiceBrowser(zc, "_services._dns-sd._udp.local.", listener)
            time.sleep(timeout)
            browser.cancel()
            zc.close()
            for info in listener.services:
                try:
                    ip = socket.inet_ntoa(info.address)
                    friendly[ip] = info.name
                except Exception:
                    pass

        t = threading.Thread(target=mdns_worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # --- SSDP (UPnP) ---
    def ssdp_worker():
        ssdp_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(ssdp_msg.encode(), ("239.255.255.250", 1900))
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(65507)
                    response = data.decode(errors="ignore")
                    if "LOCATION:" in response:
                        location = re.search(r"LOCATION:\s*(.+)", response, re.IGNORECASE)
                        if location:
                            url = location.group(1).strip()
                            # Extract IP from URL
                            try:
                                ip = socket.gethostbyname(url.split("/")[2])
                            except Exception:
                                continue
                            # For simplicity, we don't fetch XML; if no name,
                            # we still note the IP as discovered (value None)
                            if ip not in friendly:
                                friendly[ip] = None
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

    t = threading.Thread(target=ssdp_worker)
    t.daemon = True
    t.start()
    threads.append(t)

    for t in threads:
        t.join()
    return friendly


def port_scan(ip, ports, timeout=0.5):
    """
    Scan a single IP for open TCP ports using Scapy SYN scan.
    Returns list of open ports.
    """
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
            open_ports.append(port)
            # Send RST to close
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
    return open_ports


def match_mac(mac, pattern):
    """
    Check if a MAC address matches a pattern.
    Pattern can be:
    - Exact MAC (e.g., AA:BB:CC:DD:EE:FF)
    - Wildcard using * (e.g., AA:BB:CC:*)
    - Case-insensitive, colon or dash separators accepted.
    """
    mac = mac.lower().replace('-', ':')
    pattern = pattern.lower().replace('-', ':')
    regex = re.escape(pattern).replace(r'\*', '.*')
    return re.fullmatch(regex, mac) is not None


def check_whitelist_blacklist(mac, whitelist, blacklist):
    """
    Returns (is_known, is_blacklisted)
    is_known: True if whitelist is empty or MAC matches a whitelist pattern.
    is_blacklisted: True if MAC matches a blacklist pattern.
    """
    is_blacklisted = False
    is_known = True  # default if no whitelist

    if blacklist:
        for pattern in blacklist:
            if match_mac(mac, pattern):
                is_blacklisted = True
                break

    if whitelist:
        is_known = False
        for pattern in whitelist:
            if match_mac(mac, pattern):
                is_known = True
                break

    return is_known, is_blacklisted


def detect_arp_spoofing(found_devices):
    """
    Detect possible ARP spoofing within the current scan:
    - Same MAC with multiple different IPs
    - Same IP with multiple different MACs
    Returns list of alert messages.
    """
    ip_to_mac = defaultdict(set)
    mac_to_ip = defaultdict(set)
    for dev in found_devices:
        ip_to_mac[dev['ip']].add(dev['mac'])
        mac_to_ip[dev['mac']].add(dev['ip'])

    alerts = []
    for mac, ips in mac_to_ip.items():
        if len(ips) > 1:
            alerts.append(f"MAC {mac} has multiple IPs: {', '.join(sorted(ips))}")
    for ip, macs in ip_to_mac.items():
        if len(macs) > 1:
            alerts.append(f"IP {ip} has multiple MACs: {', '.join(sorted(macs))}")
    return alerts


def init_db(db_file):
    """
    Initialize SQLite database and migrate old databases if needed.
    """
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            vendor TEXT,
            hostname TEXT,
            friendly_name TEXT,
            ports TEXT,
            first_seen TEXT,
            last_seen TEXT,
            online INTEGER DEFAULT 0,
            arp_anomaly INTEGER DEFAULT 0
        )
        """
    )
    # Check existing columns and add missing ones (for old databases)
    c.execute("PRAGMA table_info(devices)")
    existing_columns = [row[1] for row in c.fetchall()]
    new_columns = {
        'friendly_name': 'TEXT',
        'ports': 'TEXT',
        'arp_anomaly': 'INTEGER DEFAULT 0'
    }
    for col, col_type in new_columns.items():
        if col not in existing_columns:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} {col_type}")
    conn.commit()
    return conn


def update_devices(conn, found_devices, port_scan_results=None):
    """
    Update the database with scan results.
    found_devices: list of dicts with ip, mac, vendor, hostname, friendly_name
    port_scan_results: dict mapping ip -> list of open ports
    Returns a dict with lists of new, online, offline devices, and unknown devices.
    """
    now = datetime.datetime.now().isoformat()
    c = conn.cursor()

    # Previous online/offline states
    c.execute("SELECT mac, online FROM devices")
    prev_states = {row[0]: row[1] for row in c.fetchall()}

    # Mark all devices offline first; we will set found ones online
    c.execute("UPDATE devices SET online = 0, arp_anomaly = 0")

    new_devices = []
    online_devices = []  # devices that were offline/unknown and are now online
    unknown_devices = []

    for dev in found_devices:
        mac = dev["mac"]
        ip = dev["ip"]
        vendor = dev.get("vendor")
        hostname = dev.get("hostname")
        friendly_name = dev.get("friendly_name")
        ports = ""
        if port_scan_results and ip in port_scan_results:
            ports = ",".join(map(str, port_scan_results[ip]))

        c.execute(
            "SELECT first_seen, vendor, hostname, friendly_name FROM devices WHERE mac=?",
            (mac,),
        )
        row = c.fetchone()

        if row:
            first_seen = row[0]
            existing_vendor = row[1]
            existing_hostname = row[2]
            existing_friendly = row[3]

            vendor = vendor if vendor else existing_vendor
            hostname = hostname if hostname else existing_hostname
            friendly_name = friendly_name if friendly_name else existing_friendly

            c.execute(
                """
                UPDATE devices
                SET ip=?, vendor=?, hostname=?, friendly_name=?, ports=?,
                    last_seen=?, online=1
                WHERE mac=?
                """,
                (ip, vendor, hostname, friendly_name, ports, now, mac),
            )
        else:
            c.execute(
                """
                INSERT INTO devices
                (mac, ip, vendor, hostname, friendly_name, ports,
                 first_seen, last_seen, online, arp_anomaly)
                VALUES (?,?,?,?,?,?,?,?,1,0)
                """,
                (mac, ip, vendor, hostname, friendly_name, ports, now, now),
            )
            new_devices.append(dev)

        if prev_states.get(mac, 0) == 0:
            online_devices.append(dev)

    conn.commit()

    # Determine offline devices
    found_macs = {d["mac"] for d in found_devices}
    offline_devices = [
        mac for mac, online in prev_states.items() if online and mac not in found_macs
    ]

    return {
        "new": new_devices,
        "online": online_devices,
        "offline": offline_devices,
        "found_count": len(found_devices),
    }


def save_ips_to_file(ip_file, found_ips):
    """
    Merge found IPs with existing ones and write unique IPs to file.
    """
    existing_ips = set()
    if os.path.exists(ip_file):
        with open(ip_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    existing_ips.add(line)
    all_ips = existing_ips.union(set(found_ips))
    with open(ip_file, "w") as f:
        for ip in sorted(all_ips, key=lambda x: ipaddress.ip_address(x)):
            f.write(ip + "\n")
    return all_ips


def print_summary(found_devices, changes, ip_file, port_scan_results, unknown_devices, arp_alerts):
    print(f"{Fore.CYAN}Found {changes['found_count']} device(s) online.{Style.RESET_ALL}")

    if changes["new"]:
        print(f"\n{Fore.GREEN}New devices:{Style.RESET_ALL}")
        for d in changes["new"]:
            friendly = f" ({d.get('friendly_name')})" if d.get('friendly_name') else ""
            print(
                f"  {Fore.GREEN}{d['ip']:15s}{Style.RESET_ALL} "
                f"{d['mac']:17s} "
                f"{d.get('vendor') or 'Unknown':20s} "
                f"{d.get('hostname') or ''}{friendly}"
            )

    if changes["online"]:
        print(f"\n{Fore.GREEN}Came online:{Style.RESET_ALL}")
        for d in changes["online"]:
            friendly = f" ({d.get('friendly_name')})" if d.get('friendly_name') else ""
            print(
                f"  {Fore.GREEN}{d['ip']:15s}{Style.RESET_ALL} "
                f"{d['mac']:17s} "
                f"{d.get('vendor') or 'Unknown':20s} "
                f"{d.get('hostname') or ''}{friendly}"
            )

    if changes["offline"]:
        print(f"\n{Fore.RED}Went offline:{Style.RESET_ALL}")
        for mac in changes["offline"]:
            print(f"  {Fore.RED}{mac}{Style.RESET_ALL}")

    if unknown_devices:
        print(f"\n{Fore.YELLOW}Unknown devices (not in whitelist):{Style.RESET_ALL}")
        for d in unknown_devices:
            print(f"  {Fore.YELLOW}{d['ip']:15s} {d['mac']:17s} {d.get('vendor') or ''}{Style.RESET_ALL}")

    if arp_alerts:
        print(f"\n{Fore.RED}⚠ ARP Spoofing Alerts:{Style.RESET_ALL}")
        for alert in arp_alerts:
            print(f"  {Fore.RED}{alert}{Style.RESET_ALL}")

    if port_scan_results:
        print(f"\n{Fore.MAGENTA}Open ports:{Style.RESET_ALL}")
        for ip, ports in port_scan_results.items():
            if ports:
                print(f"  {ip:15s} -> {', '.join(map(str, ports))}")

    all_ips = save_ips_to_file(ip_file, [d["ip"] for d in found_devices])
    print(f"{Fore.YELLOW}IPs saved to {ip_file} ({len(all_ips)} unique).{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'-' * 60}{Style.RESET_ALL}")


def list_devices(conn):
    """Print all devices currently stored in the database."""
    c = conn.cursor()
    c.execute(
        """
        SELECT mac, ip, vendor, hostname, friendly_name, ports,
               first_seen, last_seen, online, arp_anomaly
        FROM devices
        ORDER BY online DESC, last_seen DESC
        """
    )
    rows = c.fetchall()

    header = (
        f"{'MAC':17s} {'IP':15s} {'Vendor':20s} {'Hostname':20s} {'Friendly':20s} "
        f"{'Ports':15s} {'First Seen':19s} {'Last Seen':19s} {'Online':6s} {'Anomaly':7s}"
    )
    print(f"{Fore.CYAN}{header}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * len(header)}{Style.RESET_ALL}")
    for row in rows:
        online_str = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if row[8] else f"{Fore.RED}No{Style.RESET_ALL}"
        anomaly_str = f"{Fore.RED}Yes{Style.RESET_ALL}" if row[9] else "No"
        print(
            f"{row[0]:17s} {row[1]:15s} {(row[2] or 'Unknown'):20s} "
            f"{(row[3] or ''):20s} {(row[4] or ''):20s} "
            f"{(row[5] or ''):15s} {row[6]:19s} {row[7]:19s} "
            f"{online_str:6s} {anomaly_str:7s}"
        )


def main():
    parser = argparse.ArgumentParser(description="NetSentinel – Advanced Network Scanner")
    parser.add_argument("--network", help="CIDR to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Scan interval in seconds")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database file")
    parser.add_argument("--ip-file", default=DEFAULT_IP_FILE, help="File to store discovered IPs")
    parser.add_argument("--whitelist", default=DEFAULT_WHITELIST, help="Whitelist file (MACs allowed)")
    parser.add_argument("--blacklist", default=DEFAULT_BLACKLIST, help="Blacklist file (MACs to alert)")
    parser.add_argument("--portscan", action="store_true", help="Enable port scanning (requires root)")
    parser.add_argument("--ports", type=str, help="Comma-separated list of ports to scan (overrides default)")
    parser.add_argument("--once", action="store_true", help="Run a single scan and exit")
    parser.add_argument("--list", action="store_true", help="List stored devices and exit")
    args = parser.parse_args()

    # Banner
    BANNER = r"""
::::    ::: :::::::::: ::::::::::: :::::::::  :::    ::: :::        ::::::::  :::::::::: 
:+:+:   :+: :+:            :+:     :+:    :+: :+:    :+: :+:       :+:    :+: :+:        
:+:+:+  +:+ +:+            +:+     +:+    +:+ +:+    +:+ +:+       +:+        +:+        
+#+ +:+ +#+ +#++:++#       +#+     +#++:++#+  +#+    +:+ +#+       +#++:++#++ +#++:++#   
+#+  +#+#+# +#+            +#+     +#+        +#+    +#+ +#+              +#+ +#+        
#+#   #+#+# #+#            #+#     #+#        #+#    #+# #+#       #+#    #+# #+#        
###    #### ##########     ###     ###         ########  ########## ########  ##########
"""
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(f"{Fore.YELLOW}WARNING: Only scan networks you own or are authorised to scan.{Style.RESET_ALL}\n")

    if args.list:
        conn = init_db(args.db)
        list_devices(conn)
        conn.close()
        return

    # Load whitelist/blacklist
    whitelist = []
    blacklist = []
    if os.path.exists(args.whitelist):
        with open(args.whitelist) as f:
            whitelist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"{Fore.CYAN}Loaded whitelist: {len(whitelist)} pattern(s){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No whitelist file found. All devices will be considered known.{Style.RESET_ALL}")
    if os.path.exists(args.blacklist):
        with open(args.blacklist) as f:
            blacklist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"{Fore.CYAN}Loaded blacklist: {len(blacklist)} pattern(s){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No blacklist file found.{Style.RESET_ALL}")

    network_str = args.network or get_local_network()
    try:
        network = ipaddress.ip_network(network_str, strict=False)
    except ValueError as e:
        print(f"{Fore.RED}Invalid network: {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.CYAN}Network: {network}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scan interval: {args.interval}s{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Database: {args.db}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}IP file: {args.ip_file}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Port scanning: {'Enabled' if args.portscan else 'Disabled'}{Style.RESET_ALL}\n")

    # Initialize MAC vendor parser
    vendor_parser = None
    if manuf:
        try:
            vendor_parser = manuf.MacParser()
        except Exception as e:
            print(f"{Fore.YELLOW}Could not initialize MAC vendor lookup: {e}{Style.RESET_ALL}")
            vendor_parser = None

    # Determine ports to scan
    ports_to_scan = COMMON_PORTS
    if args.ports:
        try:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print(f"{Fore.RED}Invalid port list. Using defaults.{Style.RESET_ALL}")

    conn = init_db(args.db)

    try:
        while True:
            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{Fore.MAGENTA}[Scan at {scan_time}]{Style.RESET_ALL}")

            # ARP scan
            found = arp_scan(network)

            # Friendly name discovery (mDNS/SSDP) in parallel
            print(f"{Fore.CYAN}Discovering mDNS/SSDP names...{Style.RESET_ALL}")
            friendly_map = discover_friendly_names(timeout=2)  # short timeout
            for dev in found:
                dev["friendly_name"] = friendly_map.get(dev["ip"])

            # Vendor and hostname lookup
            for dev in found:
                dev["vendor"] = get_vendor(dev["mac"], vendor_parser)
                dev["hostname"] = get_hostname(dev["ip"])

            # Port scanning (optional)
            port_scan_results = {}
            if args.portscan:
                print(f"{Fore.CYAN}Port scanning online devices...{Style.RESET_ALL}")
                for dev in found:
                    ip = dev["ip"]
                    try:
                        open_ports = port_scan(ip, ports_to_scan)
                        if open_ports:
                            port_scan_results[ip] = open_ports
                    except Exception as e:
                        print(f"{Fore.RED}Port scan failed for {ip}: {e}{Style.RESET_ALL}")

            # ARP spoofing detection (within scan)
            arp_alerts = detect_arp_spoofing(found)

            # Check whitelist/blacklist for each device
            unknown_devices = []
            for dev in found:
                is_known, is_blacklisted = check_whitelist_blacklist(dev["mac"], whitelist, blacklist)
                dev["is_known"] = is_known
                dev["is_blacklisted"] = is_blacklisted
                if not is_known:
                    unknown_devices.append(dev)
                if is_blacklisted:
                    print(f"{Fore.RED}⚠ BLACKLISTED DEVICE DETECTED: {dev['ip']} {dev['mac']}{Style.RESET_ALL}")

            # Update database
            changes = update_devices(conn, found, port_scan_results)

            # Mark devices with ARP anomaly in DB (if any)
            if arp_alerts:
                for alert in arp_alerts:
                    # Mark all involved MACs as anomalous (simplistic)
                    for dev in found:
                        if dev['mac'] in alert or dev['ip'] in alert:
                            c = conn.cursor()
                            c.execute("UPDATE devices SET arp_anomaly = 1 WHERE mac=?", (dev['mac'],))
                            conn.commit()

            print_summary(found, changes, args.ip_file, port_scan_results, unknown_devices, arp_alerts)

            if args.once:
                break

            print(f"{Fore.YELLOW}Sleeping {args.interval}s... Press Ctrl+C to stop.{Style.RESET_ALL}")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopping scanner.{Style.RESET_ALL}")
    finally:
        conn.close()
        print(f"{Fore.YELLOW}Database closed.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()