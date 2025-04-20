from networkscanner import NetworkScanner
import netifaces
import socket
import ipaddress
import nmap
from fileanalyzer import (
    select_pcap_file,
    analyze_pcap,
    display_analysis_results,
    generate_plots,
    generate_report
)
import os
import sys

def display_menu():
    print("\n" + "="*50)
    print("Network Scanner and Analysis Tool".center(50))
    print("="*50)
    print("1. Get IP Addresses of All Network Devices")
    print("2. Complete Network Scan")
    print("3. Analyze Old Capture Files (Log Files)")
    print("4. Generate Consolidated Report")
    print("5. Graphical Analysis")
    print("6. Exit")
    print("="*50)

def get_ip_addresses():
    try:
        print("\n[+] Detecting active network interface...")
        gws = netifaces.gateways()
        default_gateway = gws.get('default', {}).get(netifaces.AF_INET)

        if not default_gateway:
            print("[-] Could not find default gateway. Are you connected?")
            return

        _, iface = default_gateway
        addrs = netifaces.ifaddresses(iface)
        ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        subnet = str(network)
        print(f"[i] Interface: {iface}")
        print(f"[i] Scanning subnet: {subnet}")
        nm = nmap.PortScanner()

        # ping scan (-sn)
        print("[+] Running Nmap scan...")
        nm.scan(hosts=subnet, arguments='-sn')

        live_hosts = nm.all_hosts()

        if not live_hosts:
            print("[-] No live hosts found.")
            return

        print("\n" + "="*60)
        print("Live Hosts on Network:".center(60))
        print("="*60)

        for host in live_hosts:
            mac = nm[host]['addresses'].get('mac', 'N/A')
            print(f"{host:15} | MAC: {mac:17}")

        print(f"\nTotal live hosts found: {len(live_hosts)}")

    except Exception as e:
        print(f"\n❌ Error: {e}")

def complete_network_scan():
    try:
        print("\n[+] Starting complete network scan...")
        devices = NetworkScanner()
        return devices
    except Exception as e:
        print(f"\n❌ Error during network scan: {e}")
        return None

def analyze_capture_files():
    try:
        file_path = select_pcap_file()
        if not file_path:
            print("[-] No file selected. Returning to menu.")
            return
        
        print(f"[+] Analyzing file: {os.path.basename(file_path)}")
        stats = analyze_pcap(file_path)
        display_analysis_results(stats)
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")

def generate_consolidated_report():
    print("\n[+] Report Generation Selected")
    try:
        file_path = select_pcap_file()
        if not file_path:
            print("[-] No file selected. Returning to menu.")
            return
        
        print(f"[+] Analyzing file for report: {os.path.basename(file_path)}")
        stats = analyze_pcap(file_path)
        report_path = generate_report(stats)
        print(f"[+] Report successfully generated at: {report_path}")
        
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")

def show_graphical_analysis():
    print("\n[+] Graphical Analysis Selected")
    try:
        file_path = select_pcap_file()
        if not file_path:
            print("[-] No file selected. Returning to menu.")
            return
        
        print(f"[+] Analyzing file for visualization: {os.path.basename(file_path)}")
        stats = analyze_pcap(file_path)
        generate_plots(stats)
        
    except Exception as e:
        print(f"\n❌ Error during graphical analysis: {e}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    while True:
        clear_screen()
        display_menu()
        try:
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                clear_screen()
                get_ip_addresses()
            elif choice == '2':
                clear_screen()
                complete_network_scan()
            elif choice == '3':
                clear_screen()
                analyze_capture_files()
            elif choice == '4':
                clear_screen()
                generate_consolidated_report()
            elif choice == '5':
                clear_screen()
                show_graphical_analysis()
            elif choice == '6':
                print("\n[+] Exiting the program. Goodbye!")
                sys.exit(0)
            else:
                print("\n[!] Invalid choice. Please enter a number between 1-6.")
                
            input("\nPress Enter to return to menu...")
            
        except KeyboardInterrupt:
            print("\n[+] Exiting the program. Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ An unexpected error occurred: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        if os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Warning: Some features may require administrator privileges.")
        else:
            if os.geteuid() != 0:
                print("[!] Warning: Some features may require root privileges.")
        
        main()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)