# src/ingestion/json_ingestor.py
import json
import asyncio
from typing import List
from src.ingestion.base_ingestor import BaseIngestor, Event

class TestIngestor(BaseIngestor):
    async def _start(self):
        pass

    async def _stop(self):
        pass

    async def parse_data(self, raw_data: str) -> List[Event]:
        events = []
        raw_data = raw_data.strip()
        if not raw_data:
            return events
        try:
            data = json.loads(raw_data)
            events.append(Event(
                ip=data.get("ip", "unknown"),
                threat=data.get("threat", []),
                severity=data.get("severity", "low"),
                score=data.get("score", 0),
                geo=data.get("geo", ""),
                seen_before=False
            ))
        except Exception as e:
            print("Parse error:", e)
        return events
 
