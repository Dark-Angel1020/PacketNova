import nmap
import netifaces
import ipaddress
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, srp

def NetworkScanner():
    def get_local_network():

        try:
            default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            iface_data = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
            ip_addr = iface_data['addr']
            netmask = iface_data['netmask']
            network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
            return str(network)
        except KeyError as e:
            raise RuntimeError("Unable to detect the local network. Check your network configuration.") from e

    def scan_network_with_nmap(network_range):

        try:
            scanner = nmap.PortScanner()
            print(f"[+] Scanning network: {network_range} with Nmap (this may take a while)...")
            scanner.scan(hosts=network_range, arguments='-O -sV --version-light')

            mac_lookup = MacLookup()
            try:
                mac_lookup.update_vendors()
            except Exception:
                print("[-] Vendor DB already updated or offline mode.")

            devices = []
            for host in scanner.all_hosts():
                addr = scanner[host]['addresses']
                mac = addr.get('mac')
                ip = addr.get('ipv4')
                hostname = scanner[host].hostname()
                os_info = "Unknown"
                if 'osclass' in scanner[host]:
                    os_classes = scanner[host]['osclass']
                    if os_classes:
                        os_info = f"{os_classes[0]['osfamily']} {os_classes[0].get('osgen', '')}".strip()
                        if 'type' in os_classes[0]:
                            os_info += f" ({os_classes[0]['type']})"
                device_type = "Unknown"
                if 'osmatch' in scanner[host]:
                    osmatch = scanner[host]['osmatch']
                    if osmatch:
                        device_type = osmatch[0].get('name', 'Unknown')
                vendor = "Unknown"
                if mac:
                    try:
                        vendor = mac_lookup.lookup(mac)
                    except Exception:
                        pass
                services = []
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        services.append(f"{port}/{proto} ({service['name']} {service.get('product', '')} {service.get('version', '')})".strip())
                
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': hostname,
                    'os': os_info,
                    'device_type': device_type,
                    'services': ', '.join(services) if services else 'None'
                })
            return devices
        except Exception as e:
            print(f"❌ Nmap scan failed: {e}")
            return []

    def arp_scan(network_range):
        try:
            print(f"[+] Performing ARP scan on {network_range} ...")
            devices = []
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=2, verbose=0)[0]

            mac_lookup = MacLookup()

            for sent, received in result:
                mac = received.hwsrc
                ip = received.psrc
                try:
                    vendor = mac_lookup.lookup(mac)
                except Exception:
                    vendor = "Unknown"

                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': "-",
                    'os': "Unknown (ARP scan)",
                    'device_type': "Unknown (ARP scan)",
                    'services': "None"
                })

            return devices
        except Exception as e:
            print(f"❌ ARP scan failed: {e}")
            return []

    def print_device_list(devices):

        if not devices:
            print("\n📋 No devices detected.")
            return

        print("\n📋 Network Devices:")
        print("{:<16} {:<20} {:<25} {:<30} {:<30}".format(
            "IP", "MAC", "Vendor", "Model", "Services"))
        print("-" * 120)
        for d in devices:
            print("{:<16} {:<20} {:<25} {:<30} {:<30}".format(
                d['ip'] or "-",
                d['mac'] or "-",
                (d['vendor'][:22] + '...') if d['vendor'] and len(d['vendor']) > 25 else d['vendor'] or "-",
                (d['device_type'][:27] + '...') if d['device_type'] and len(d['device_type']) > 30 else d['device_type'] or "-",
                (d['services'][:27] + '...') if d['services'] and len(d['services']) > 30 else d['services'] or "-"
            ))


    try:
        network = get_local_network()

        print("\n=== NMAP SCAN (Detailed) ===")
        nmap_devices = scan_network_with_nmap(network)

        print("\n=== ARP SCAN ===")
        arp_devices = arp_scan(network)
        all_devices = {d['ip']: d for d in nmap_devices if d['ip']}
        for d in arp_devices:
            if d['ip']:
                all_devices[d['ip']] = d

        print_device_list(list(all_devices.values()))
        return list(all_devices.values())
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

if __name__ == "__main__":
    NetworkScanner()