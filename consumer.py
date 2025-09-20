import asyncio
import pandas as pd
from collections import Counter
from src.ingestion.base_ingestor import BaseIngestor
from src.db import threat_db
from rich.console import Console
from src.utils.logging import setup_logging

logger = setup_logging()
console = Console()

class ThreatConsumer:
    def __init__(self, ingestor: BaseIngestor, batch_size: int = 10):
        self.ingestor = ingestor
        self.batch_size = batch_size
        self.db = threat_db# FIX 3: Add database reference

    async def consume_and_analyze(self):
        """Continuously consume events in batches"""
        batch = []
        
        while True:
            try:
                event = await asyncio.wait_for(self.ingestor.queue.get(), timeout=1.0)
                console.print(f"New event: {event.ip}", style="green")
                batch.append(event)
                
                if len(batch) >= self.batch_size:
                    await self._analyze_batch(batch)
                    batch.clear()
                    
            except asyncio.TimeoutError:
                if batch:
                    await self._analyze_batch(batch)
                    batch.clear()
                continue
            except Exception as e:
                logger.error(f"Consumer error: {e}")

    async def _analyze_batch(self, batch):  # FIX 4: Fixed method name (was *analyze*batch)
        """Analyze batch of events with pandas and database queries"""
        if not batch:
            return
            
        console.print(f"\n=== Batch Analysis ({len(batch)} events) ===", style="bold cyan")
        
        # Convert events to DataFrame
        data = []
        for event in batch:
            data.append({
                "ip": event.ip,
                "severity": event.severity,
                "score": event.score,
                "threats": event.threat,
                "seen_before": event.seen_before,
                "mitre": getattr(event, "mitre", []),  # FIX 5: Default to empty list
                "source_type": getattr(event, "source_type", "unknown")
            })
        
        df = pd.DataFrame(data)
        
        # IP analysis
        console.print("IP per Event:")
        ip_counts = df["ip"].value_counts()
        console.print(ip_counts)
        
        # Severity distribution
        console.print("\nSeverity Distribution:")
        severity_counts = df["severity"].value_counts()
        console.print(severity_counts)
        
        # Threat analysis
        all_threats = []
        for threats in df["threats"]:
            if threats:  # FIX 6: Check if threats exist
                all_threats.extend(threats)
                
        if all_threats:
            console.print("\nTop Threats:")
            threat_counter = Counter(all_threats)
            for threat, count in threat_counter.most_common(10):
                console.print(f" {threat:<30} {count}")
        
        # MITRE technique analysis
        all_mitre = []
        for mitre_list in df["mitre"]:
            if mitre_list:
                all_mitre.extend(mitre_list)
                
        if all_mitre:
            console.print("\nTop MITRE Techniques:")
            mitre_counter = Counter(all_mitre)
            for technique, count in mitre_counter.most_common(5):
                console.print(f" {technique:<40} {count}")
        
        # Source type analysis
        console.print("\nSource Types:")
        source_counts = df["source_type"].value_counts()
        console.print(source_counts)
        
        # High-risk IP analysis
        high_risk = df[df["score"] >= 10]
        if not high_risk.empty:
            console.print(f"\n🚨 High Risk IPs ({len(high_risk)}):", style="bold red")
            for _, row in high_risk.iterrows():  # FIX 7: Fixed iterator syntax
                console.print(
                    f" {row['ip']} - Score: {row['score']} - {row['severity'].upper()}"
                )
        
        # Database trending analysis
        try:
            trending = await self.db.get_trending_ips(24, 10)  # FIX 8: Use self.db
            if trending:
                console.print("\n📈 Trending IPs (24h):", style="bold yellow")
                for row in trending:  # FIX 9: Fixed variable name (was 'rows')
                    console.print(
                        f" {row['ip']} - Avg Score: {row['avg_score']:.1f}, "
                        f"Events: {row['event_count']}, Severity: {row['max_severity']}"
                    )
        except Exception as e:
            logger.error(f"Failed to get trending IPs: {e}")
            console.print("⚠️ Trending analysis unavailable", style="yellow")
        
        # Database statistics
        try:
            stats = await self.db.get_threat_stats()
            if stats:
                console.print("\n📊 Database Statistics:", style="bold blue")
                console.print(f" Total Events: {stats.get('total_events', 0)}")
                console.print(f" Unique IPs: {stats.get('unique_ips', 0)}")
                console.print(f" Critical: {stats.get('critical_count', 0)}")
                console.print(f" High: {stats.get('high_count', 0)}")
                console.print(f" Average Score: {stats.get('avg_score', 0):.1f}")
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")

async def main():
    """Main function with proper ingestor setup"""
    # FIX 10: Use BaseIngestor with proper configuration
    config = {
        'batch_size': 25,
        'queue_size': 1000
    }
    ingestor = BaseIngestor("threat_ingestor", config)
    consumer = ThreatConsumer(ingestor, batch_size=10)
    
    # Initialize database connection
    try:
        await threat_db.init_pool()
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return
    
    # Start ingestor
    await ingestor.start()
    
    # Start consumer in background
    consumer_task = asyncio.create_task(consumer.consume_and_analyze())
    
    # Process test files
    test_files = [
        "tests/sample_log.jsonl",
        "tests/sample.pcap"
    ]
    
    for filepath in test_files:
        try:
            logger.info(f"Processing {filepath}")
            console.print(f"📁 Processing: {filepath}", style="bold")
            
            async for event in ingestor.ingest_file(filepath):
                console.print(f"Ingested event: {event.ip} - {event.severity}")
                
        except FileNotFoundError:
            logger.warning(f"File not found: {filepath}")
            console.print(f"⚠️ File not found: {filepath}", style="yellow")
        except Exception as e:
            logger.error(f"Error processing {filepath}: {e}")
            console.print(f"❌ Error processing {filepath}: {e}", style="red")
    
    # Allow consumer time to process remaining events
    console.print("\n⏳ Waiting for final batch processing...", style="blue")
    await asyncio.sleep(3)
    
    # Clean shutdown
    consumer_task.cancel()
    await ingestor.stop()
    console.print("🏁 Processing complete!", style="bold green")

if __name__ == "__main__":
    asyncio.run(main())
    
 


		
