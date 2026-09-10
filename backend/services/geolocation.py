import json
import urllib.request
from ipaddress import ip_address

def get_ip_geolocation(ip: str) -> dict:
    try:
        if ip_address(ip).is_private:
            return {"ip": ip, "status": "private", "message": "Private/Local IP Address", "threat_intel": "Unavailable"}
            
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            
        if data.get("status") == "success":
            
            # Simulate Threat Intel where API access is available
            # We don't have a real VirusTotal API key in this env, so we gracefully degrade or simulate.
            threat_intel = "Threat intelligence unavailable (No API Configured)"
            
            return {
                "ip": ip,
                "status": "success",
                "probable_country": data.get("country"),
                "probable_city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "organization": data.get("org"),
                "infrastructure_type": "Cloud/Hosting" if "cloud" in (data.get("isp") or "").lower() else "Unknown",
                "threat_intel": threat_intel
            }
        else:
            return {"ip": ip, "status": "failed", "message": data.get("message", "Unknown error"), "threat_intel": "Unavailable"}
            
    except ValueError:
        return {"ip": ip, "status": "invalid", "message": "Invalid IP format"}
    except Exception as e:
        return {"ip": ip, "status": "error", "message": str(e)}

def trace_ip_route(ip_list: list) -> list:
    geolocations = []
    for ip in ip_list:
        geo_data = get_ip_geolocation(ip)
        geolocations.append(geo_data)
    return geolocations

