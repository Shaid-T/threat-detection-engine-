# test_simple_insert.py
import asyncio
from src.db import threat_db

async def test_insert():
    await threat_db.init_pool()
    
    # Direct database insert
    async with threat_db.pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO events (ip, severity, score, geo, threat, seen_before, raw_data, source_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """, 
        "192.168.1.100", "critical", 25, 
        '{"country": "Test"}', '["test_threat"]', 
        False, "test data", "test")
    
    print("Test data inserted directly")

asyncio.run(test_insert())
