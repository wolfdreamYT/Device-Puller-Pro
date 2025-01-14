import socket
import subprocess
import platform
import time
import requests
from ipaddress import ip_network
import os
import sys
import termios
import tty
import nmap

def is_device_reachable(ip_address):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        response = subprocess.run(
            ['ping', param, '1', ip_address],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return response.returncode == 0
    except Exception as e:
        print(f"Error pinging {ip_address}: {e}")
        return False

def fetch_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"

def scan_os(ip_address):
    nm = nmap.PortScanner()
    try:
        scan_result = nm.scan(hosts=ip_address, arguments='-O')
        os_matches = scan_result['scan'][ip_address].get('osmatch', [])

        if os_matches:
            os_info = os_matches[0]['name']
            accuracy = os_matches[0]['accuracy']
            return f"Detected OS: {os_info} (Accuracy: {accuracy}%)"
        else:
            return "Unable to detect OS. Try using administrative privileges or check the IP."
    except Exception as e:
        return f"Error scanning for OS: {e}"

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        start_time = time.time()
        scan_result = nm.scan(hosts=ip_address, arguments='-p 1-65535 --host-timeout 2m')
        open_ports = []

        for protocol in scan_result['scan'][ip_address].all_protocols():
            ports = scan_result['scan'][ip_address][protocol].keys()
            open_ports.extend(ports)

        open_ports = sorted(open_ports)[:5]

        if open_ports:
            return f"Open Ports: {', '.join(map(str, open_ports))}"
        else:
            return "No open ports found."
    except Exception as e:
        return f"Error scanning ports: {e}"

def get_local_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def get_geoip_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "City": data.get("city", "Unknown"),
                    "Region": data.get("regionName", "Unknown"),
                    "Country": data.get("country", "Unknown"),
                    "Latitude": data.get("lat", "Unknown"),
                    "Longitude": data.get("lon", "Unknown"),
                    "Organization": data.get("org", "Unknown")
                }
        return {
            "City": "Unknown",
            "Region": "Unknown",
            "Country": "Unknown",
            "Latitude": "Unknown",
            "Longitude": "Unknown",
            "Organization": "Unknown"
        }
    except Exception as e:
        print(f"Error fetching GeoIP data for {ip_address}: {e}")
        return {
            "City": "Unknown",
            "Region": "Unknown",
            "Country": "Unknown",
            "Latitude": "Unknown",
            "Longitude": "Unknown",
            "Organization": "Unknown"
        }

def fetch_device_info(ip_address):
    try:
        hostname = fetch_hostname(ip_address)
        os_info = scan_os(ip_address)
        port_info = scan_ports(ip_address)
        local_time = get_local_time()
        geoip_info = get_geoip_location(ip_address)

        device_info = {
            "Hostname": hostname,
            "IP Address": ip_address,
            "OS Info": os_info,
            "Port Info": port_info,
            "Local Time": local_time,
            "GeoIP Info": geoip_info,
        }
        return device_info
    except Exception as e:
        print(f"Error fetching device info for {ip_address}: {e}")
        return None

def get_key():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def display_menu(selected):
    os.system('clear')
    print("\033[1;32;40m") 
    print("**********************************************")
    print("*               Network Scanner              *")
    print("**********************************************")

    print("""
    +===========================================================================+
    | ____  _______     _____ ____ _____   ____  _   _ _     _     _____ ____   |
    ||  _ \| ____\ \   / /_ _/ ___| ____| |  _ \| | | | |   | |   | ____|  _ \  |
    || | | |  _|  \ \ / / | | |   |  _|   | |_) | | | | |   | |   |  _| | |_) | |
    || |_| | |___  \ V /  | | |___| |___  |  __/| |_| | |___| |___| |___|  _ <  |
    ||____/|_____|  \_/  |___\____|_____| |_|    \___/|_____|_____|_____|_| \_\ |
    +===========================================================================+
    """)
    print("Version 2.0.1 | Created on Jan 14, 2025 at 5:32PM EST")
    print("Please choose an option:")
    options = ["Start", "Cancel"]
    for i, option in enumerate(options):
        if i == selected:
            print(f"> {option} <")
        else:
            print(f"  {option}")
    print("\033[0m")

def main():
    selected = 0
    while True:
        display_menu(selected)
        key = get_key()
        if key == "\x1b": 
            key = sys.stdin.read(2)
            if key == "[A":  
                selected = (selected - 1) % 2
            elif key == "[B": 
                selected = (selected + 1) % 2
        elif key == "\r": 
            if selected == 0:
                os.system('clear')
                ip = input("Enter IP address to scan: ").strip()
                if is_device_reachable(ip):
                    print(f"\n{ip} is reachable.")
                    info = fetch_device_info(ip)
                    if info:
                        print("\nDevice Info:")
                        for key, value in info.items():
                            if isinstance(value, dict):
                                print(f"{key}:")
                                for sub_key, sub_value in value.items():
                                    print(f"  {sub_key}: {sub_value}")
                            else:
                                print(f"{key}: {value}")
                else:
                    print(f"\n{ip} is not reachable.")
                input("\nPress Enter to return to the menu.")
            elif selected == 1:
                os.system('clear')
                print("Exiting program...")
                break

if __name__ == "__main__":
    main()
