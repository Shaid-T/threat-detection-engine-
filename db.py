import asyncpg
import json
import asyncio  # ADD THIS LINE
from typing import List
from datetime import datetime, timedelta

class ThreatDB:
    def __init__(self):
        self.pool = None
        
    async def init_pool(self):
        """Initialize PostgreSQL connection pool"""
        self.pool = await asyncpg.create_pool(
            host="localhost",
            user="postgres",       
            password="pass",
            database="security_db",
            min_size=2,
            max_size=10
        )
        await self.create_table()
    
    # ... rest of your code
        
    async def create_table(self):
        """Ensure events table exists"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    ip INET NOT NULL,
                    threat JSONB,
                    severity TEXT,
                    score INT,
                    geo JSONB,
                    mitre JSONB,
                    seen_before BOOLEAN,
                    raw_data TEXT,
                    source_type TEXT,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            
    async def is_ip_seen(self, ip: str) -> bool:
        """Check if IP exists in events table"""
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM events WHERE ip = $1)", ip
            )
            
    async def get_ip_cumulative_score(self, ip: str) -> int:
        """Sum threat scores for an IP"""
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COALESCE(SUM(score), 0) FROM events WHERE ip = $1", ip
            ) or 0
            
    async def batch_insert(self, events: List["Event"]):
        """Batch insert events"""
        if not events:
            return
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany("""
                    INSERT INTO events 
                        (ip, threat, severity, score, geo, mitre, seen_before, raw_data, source_type) 
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, [
                    (
                        e.ip,
                        json.dumps(e.threat) if e.threat else None,
                        e.severity,
                        e.score,
                        json.dumps(e.geo) if e.geo else None,
                        json.dumps(e.mitre) if getattr(e, "mitre", None) else None,
                        e.seen_before,
                        e.raw[:1000] if getattr(e, "raw", None) else None,
                        getattr(e, "source_type", "unknown")
                    )
                    for e in events
                ])
                
    async def get_trending_ips(self, hours: int = 24, limit: int = 10):
        """Return trending IPs in the last X hours"""
        async with self.pool.acquire() as conn:
            return await conn.fetch("""
                SELECT ip,
                       AVG(score) AS avg_score,
                       COUNT(*) AS event_count,
                       MAX(severity) AS max_severity
                FROM events
                WHERE timestamp > NOW() - ($1::interval)
                GROUP BY ip
                ORDER BY avg_score DESC, event_count DESC
                LIMIT $2
            """, f"{hours} hours", limit)
            
    async def get_threat_stats(self):
        """Get overall threat statistics"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(DISTINCT ip) as unique_ips,
                    AVG(score) as avg_score,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
                    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_count,
                    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
            """)


threat_db = ThreatDB()
