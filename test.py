import asyncio
import streamlit as st
import sys
import os

# Add project path
project_root = "/home/crown/security-detection-engine"
sys.path.insert(0, project_root)

st.title("Database Connection Test")

try:
    from src.db import threat_db
    st.success("Import successful")
    
    # Test async function
    async def test_db():
        await threat_db.init_pool()
        async with threat_db.pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM events")
            return count
    
    # Run async in Streamlit
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    count = loop.run_until_complete(test_db())
    
    st.success(f"Database connection works! Found {count} events")
    
except Exception as e:
    st.error(f"Error: {e}")
    import traceback
    st.code(traceback.format_exc())
