import socket
import subprocess
import platform
import time
import ipinfo

# Remember not to mess with any of the code EXCEPT the ACCESS_TOKEN = '1234567890' 
# Dont use this for unethical hacking, this is for educational purposes only, so please dont do any naughty things!

# remember to replace this token with your own, you can get it at https://ipinfo.io/ since this is just a fake example
ACCESS_TOKEN = '1234567890'
handler = ipinfo.getHandler(ACCESS_TOKEN)

def is_device_reachable(ip_address):
    """Check if the device is reachable via ping."""
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
    """Resolve hostname from IP address."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"

def get_os_info():
    """Get operating system information."""
    return f"{platform.system()} {platform.release()}"

def check_if_online():
    """Check if the computer is online by pinging a common server (e.g., Google DNS)."""
    try:
        online = is_device_reachable("8.8.8.8")
        return "Online" if online else "Offline"
    except Exception as e:
        print(f"Error checking online status: {e}")
        return "Unknown"

def get_local_time():
    """Get the current local time."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def get_geoip_location(ip_address):
    """Fetch geolocation data for the IP address using IPinfo."""
    try:
        details = handler.getDetails(ip_address)
        return {
            "IP": details.ip,
            "Hostname": details.hostname,
            "City": details.city,
            "Region": details.region,
            "Country": details.country_name,
            "Location": details.loc, 
            "Organization": details.org,
            "Postal": details.postal,
            "Timezone": details.timezone
        }
    except Exception as e:
        print(f"Error fetching GeoIP data for {ip_address}: {e}")
        return {
            "IP": ip_address,
            "Hostname": "Unknown",
            "City": "Unknown",
            "Region": "Unknown",
            "Country": "Unknown",
            "Location": "Unknown",
            "Organization": "Unknown",
            "Postal": "Unknown",
            "Timezone": "Unknown"
        }

def fetch_device_info(ip_address):
    """Fetch detailed information about the device."""
    try:
        hostname = fetch_hostname(ip_address)
        os_info = get_os_info()
        online_status = check_if_online()
        local_time = get_local_time()
        geoip_info = get_geoip_location(ip_address)

        device_info = {
            "Hostname": hostname,
            "IP Address": ip_address,
            "OS Info": os_info,
            "Online Status": online_status,
            "Local Time": local_time,
            "GeoIP Info": geoip_info,
        }
        return device_info
    except Exception as e:
        print(f"Error fetching device info for {ip_address}: {e}")
        return None

def main():
    """Main function to check device connectivity and fetch details."""
    ip = input("Enter IP address: ").strip()

    if is_device_reachable(ip):
        print(f"{ip} is reachable.")
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
        print(f"{ip} is not reachable.")

if __name__ == "__main__":
    main()
