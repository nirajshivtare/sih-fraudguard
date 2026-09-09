import json
from services.geolocation import trace_ip_route

def test_geolocation():
    # We mix private IPs (like internal routers) with real public IPs
    # 176.113.115.150 is a random IP in Russia (often used in cyber examples)
    # 45.33.32.156 is a random IP in the US
    suspicious_ips = ["192.168.1.100", "10.0.0.5", "176.113.115.150", "45.33.32.156"]
    
    print("--- Tracing IP Geolocation ---")
    results = trace_ip_route(suspicious_ips)
    
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    test_geolocation()
