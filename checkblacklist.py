import requests
from datetime import datetime
import time
from colorama import init, Fore, Style
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv('API_KEY')
API_URL = os.getenv('API_URL')

def print_banner():
    print(Fore.YELLOW + " " * 20 + "\n IP Reputation Checker \n")
    print(Fore.WHITE + "=" * 60)

def get_ip_report(ip):
    url = f'{API_URL}{ip}'
    headers = {'x-apikey': API_KEY}
    
    try:
        print(Fore.GREEN + f"\n[+] Checking IP: {ip}...")
        print(Fore.YELLOW + "[~] Querying VirusTotal API...", end='')
        spinner = ['|', '/', '-', '\\']
        for i in range(4):
            time.sleep(0.1)
            print(Fore.YELLOW + f"\b{spinner[i % 4]}", end='', flush=True)
        
        response = requests.get(url, headers=headers)
        print("\b" + Fore.GREEN + " ✓ Done!")

        if response.status_code == 200:
            data = response.json()
            

            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            

            last_analysis_timestamp = attributes.get('last_analysis_date')
            if last_analysis_timestamp:
                last_analysis_date = datetime.fromtimestamp(last_analysis_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            else:
                last_analysis_date = "Not available"
            
            print(Fore.CYAN + "\n" + "=" * 60)
            print(Fore.MAGENTA + f"VirusTotal Report for {ip}")
            print(Fore.CYAN + "=" * 60)            
            print(Fore.WHITE + f"\n{Fore.YELLOW}Reputation Scores:")
            print(f"  {Fore.GREEN}Harmless: {Fore.WHITE}{last_analysis_stats.get('harmless', 0)}")
            
            malicious_count = last_analysis_stats.get('malicious', 0)
            if malicious_count > 0:
                print(f"  {Fore.RED}Malicious: {Fore.WHITE}{malicious_count} {Fore.RED}⚠️ WARNING!")
            else:
                print(f"  {Fore.GREEN}Malicious: {Fore.WHITE}{malicious_count}")
                
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            if suspicious_count > 0:
                print(f"  {Fore.YELLOW}Suspicious: {Fore.WHITE}{suspicious_count} {Fore.YELLOW}⚠️ Caution")
            else:
                print(f"  {Fore.GREEN}Suspicious: {Fore.WHITE}{suspicious_count}")
                
            print(f"  {Fore.CYAN}Undetected: {Fore.WHITE}{last_analysis_stats.get('undetected', 0)}")
            
            print(Fore.CYAN + "\n" + "=" * 60)
            risk_score = malicious_count + (suspicious_count * 0.5)
            print(Fore.WHITE + f"\n{Fore.YELLOW}Risk Assessment:")
            if risk_score == 0:
                print(Fore.GREEN + "  ✅ This IP appears to be safe")
            elif risk_score < 3:
                print(Fore.YELLOW + "  ⚠️ Low risk detected")
            elif risk_score < 10:
                print(Fore.LIGHTRED_EX + "  ⚠️⚠️ Medium risk detected")
            else:
                print(Fore.RED + "  ❌❌ HIGH RISK DETECTED!")
            
            print(Fore.CYAN + "=" * 60)
            
        else:
            print(Fore.RED + f"\nError: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(Fore.RED + f"\n❌ An unexpected error occurred: {str(e)}")

def blacklist_main():
    init(autoreset=True)
    print_banner()

    while True:
        print(Fore.WHITE + "\nOptions:")
        print(Fore.CYAN + "1. Check an IP address")
        print(Fore.CYAN + "2. Exit")
        
        choice = input(Fore.YELLOW + "\nEnter your choice (1/2): ").strip()
        
        if choice == '1':
            ip = input(Fore.WHITE + "\nEnter IP address to check: ").strip()
            if ip:
                get_ip_report(ip)
            else:
                print(Fore.RED + "Please enter a valid IP address")
        elif choice == '2':
            try:
                from maiin import display_menu
                display_menu()
            except ImportError:
                print(Fore.YELLOW + "Returning to main menu...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    blacklist_main()