import json
import urllib.request
from ipaddress import ip_address

def get_ip_geolocation(ip: str) -> dict:
    """
    Looks up the physical geolocation of an IP address.
    Skips private/local IP addresses.
    """
    try:
        # Check if the IP is a local/private network IP
        if ip_address(ip).is_private:
            return {"ip": ip, "status": "private", "message": "Private/Local IP Address"}
            
        # Call a free IP Geolocation API (ip-api.com)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            
        if data.get("status") == "success":
            return {
                "ip": ip,
                "status": "success",
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "organization": data.get("org")
            }
        else:
            return {"ip": ip, "status": "failed", "message": data.get("message", "Unknown error")}
            
    except ValueError:
        return {"ip": ip, "status": "invalid", "message": "Invalid IP format"}
    except Exception as e:
        return {"ip": ip, "status": "error", "message": str(e)}

def trace_ip_route(ip_list: list) -> list:
    """
    Takes a list of IPs extracted from email headers and returns their geolocations.
    """
    geolocations = []
    for ip in ip_list:
        geo_data = get_ip_geolocation(ip)
        geolocations.append(geo_data)
    return geolocations
