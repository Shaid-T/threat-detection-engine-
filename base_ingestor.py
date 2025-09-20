# src/ingestion/base_ingestor.py
import asyncio
import aiofiles
from typing import AsyncGenerator, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field
import subprocess
import re
import json
import smtplib  # FIX 1: Added missing import for email functionality
from email.mime.text import MIMEText
import os
import folium 
import aiohttp
from scapy.all import rdpcap, TCP, IP, Raw
import ipaddress
from src.core.engine import BaseEngine
from src.utils.logging import setup_logging
from src.detection.mitre import get_mitre
from src.db import threat_db  # FIX 2: Import the global instance instead of class

logger = setup_logging()

# ----- Config / Rules -----
suspicious_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
patterns = [
    r"bash\s+-i",
    r"sh\s+-i", 
    r"base64\s+-d",
    r"curl\b",
    r"wget\b",
    r"socat\b",
    r"nc\s+-e\b",
    r"python\s+-c",
    r"/bin/bash",
    r"rm\s+-rf"
]
more_patterns = {
    "Base64 or Hex Blobs": r"[A-Za-z0-9+/]{50,}={0,2}",
    "PowerShell": r"powershell\s+-enc|IEX\(New-Object Net.WebClient\)",
    "Exfil Attempt": r"\b(ftp|scp|s3 cp|curl -F)\b",
    "Suspicious UA": r"(curl|wget|python-requests|nikto)",
    "SQL Injection": r"(UNION\s+SELECT|OR\s+1=1|xp_cmdshell)",
    "XSS Attempt": r"(<script>|onerror=|javascript:)"
}

# FIX 3: Remove global variables - these will be replaced with database operations
# seen_ip = set()  # REMOVED - use database
# threat = defaultdict(dict)  # REMOVED - use database

bad_country = ["russia", "china", "ukraine", "north korea", "iran"]
bad_isp = ["tor", "unknown", "anonymous", "proxy", "vpn"]
geo_cache: dict = {}  # Keep this for performance

@dataclass
class Event:
    ip: str
    threat: List[str] = field(default_factory=list)
    severity: str = "low"
    score: int = 0
    geo: str = ""
    seen_before: bool = False
    mitre: List[str] = field(default_factory=list)
    raw: Optional[str] = None
    source_type: str = ""

# ----- Helpers -----
def _run_blocking(fn, *args, **kwargs):
    """Run blocking synchronous code in thread pool."""
    return asyncio.get_running_loop().run_in_executor(None, lambda: fn(*args, **kwargs))

async def send_email(subject: str, body: str, to_email: str):
    """Email functionality with proper error handling."""
    from_email = os.getenv("SEND_EMAIL")
    password = os.getenv("EMAIL_PAS")
    if not (from_email and password):
        logger.warning("Email credentials not configured; skipping send_email")
        return
    
    def _send():
        msg = MIMEText(body)
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["From"] = from_email
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(from_email, password)
                smtp.send_message(msg)
            logger.info(f"SENT EMAIL TO {to_email}")
        except Exception as e:
            logger.error("EMAIL ERROR", error=str(e))
    
    await _run_blocking(_send)

async def geo(ip: str):
    """Async geo lookup with caching."""
    if not ip:
        return "", "", "", "0", "0"
    if ip in geo_cache:
        return geo_cache[ip]
    
    timeout = aiohttp.ClientTimeout(total=3)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"http://ip-api.com/json/{ip}") as resp:
                data = await resp.json()
                results = (
                    data.get("country", ""),
                    data.get("city", ""),
                    data.get("isp", ""),
                    str(data.get("lat", 0)),
                    str(data.get("lon", 0)),
                )
                geo_cache[ip] = results
                return results
    except Exception as e:
        logger.error(f"Geo lookup failed: {e}")
        return "", "", "", "0", "0"

def extract_ip(content) -> Optional[str]:
    """Extract IPv4 address from content."""
    if isinstance(content, dict):
        for k, v in content.items():
            if isinstance(v, str):
                m = re.search(r"(\d{1,3}\.){3}\d{1,3}", v)
                if m:
                    ip = m.group(0)
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue
    elif isinstance(content, str):
        m = re.search(r"(\d{1,3}\.){3}\d{1,3}", content)
        if m:
            ip = m.group(0)
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                return None
    return None

async def ban(ip: str):
    """Ban IP using iptables."""
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    def _ban():
        try:
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"Banned IP {ip}")
        except Exception as e:
            logger.error(f"Failed to ban {ip}: {e}")
    await _run_blocking(_ban)

class BaseIngestor(BaseEngine):
    def __init__(self, name: str, config: dict = None):
        super().__init__(name, config)
        self.queue = asyncio.Queue(maxsize=config.get("queue_size", 1000) if config else 1000)
        self.batch_buffer = []
        self.batch_size = config.get('batch_size', 50) if config else 50
        
    async def _start(self):
        """FIX 4: Initialize database connection pool"""
        await threat_db.init_pool()
        logger.info("Database connection initialized")

    async def _flush_batch(self):
        """FIX 5: Helper method to flush batch buffer to database"""
        if self.batch_buffer:
            try:
                await threat_db.batch_insert(self.batch_buffer)
                logger.info(f"Flushed {len(self.batch_buffer)} events to database")
                self.batch_buffer.clear()
            except Exception as e:
                logger.error(f"Failed to flush batch: {e}")

    async def _process_threat_analysis(self, ip: str, content: str, source_type: str) -> Event:
        """FIX 6: Centralized threat processing using database instead of globals"""
        
        # Get data from database instead of globals
        seen_before = await threat_db.is_ip_seen(ip)
        cumulative_score = await threat_db.get_ip_cumulative_score(ip)
        
        # Initialize threat data
        threats = []
        mitre_techniques = []
        current_score = 0
        
        # Get geo information
        country, city, isp, lat, lon = await geo(ip)
        geo_data = {
            "country": country,
            "city": city, 
            "isp": isp,
            "lat": lat,
            "lon": lon
        }
        
        # Country/ISP threat analysis
        if country and country.lower() in bad_country:
            threats.append("bad_country")
            current_score += 5
            
        if isp and any(x in isp.lower() for x in bad_isp):
            threats.append("bad_isp")
            current_score += 5
        
        # Pattern matching
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(pattern)
                current_score += 5
                
        for name, regex in more_patterns.items():
            if re.search(regex, content, re.IGNORECASE):
                threats.append(name)
                current_score += 5
        
        # MITRE analysis
        try:
            mitre_matches = get_mitre(indicators=[content], content=content)
            if mitre_matches:
                for match in mitre_matches:
                    technique_id = match.get("technique_id", "")
                    technique_name = match.get("technique_name", "")
                    label = f"{technique_id}:{technique_name}" if technique_id else technique_name
                    if label:
                        threats.append(label)
                        mitre_techniques.append(label)
                        current_score += 5
        except Exception as e:
            logger.error(f"MITRE analysis failed: {e}")
        
        # Calculate severity
        total_score = cumulative_score + current_score
        if total_score >= 15:
            severity = "critical"
        elif total_score >= 10:
            severity = "high" 
        elif total_score >= 5:
            severity = "mid"
        else:
            severity = "low"
        
        # Auto-ban logic
        if not seen_before and total_score >= 5:
            await ban(ip)
            logger.warning(f"Auto-banned IP {ip} with score {total_score}")
        
        # Email alerts for high severity
        if total_score >= 15:
            await self._send_critical_alert(ip, threats, geo_data, total_score)
        elif total_score >= 10:
            await self._send_high_alert(ip, threats, geo_data, total_score)
        
        # Create event
        event = Event(
            ip=ip,
            threat=list(dict.fromkeys(threats)),  # Remove duplicates
            severity=severity,
            score=current_score,  # Store incremental score, not cumulative
            geo=json.dumps(geo_data),
            seen_before=seen_before,
            mitre=mitre_techniques,
            raw=content[:1000] if content else None,
            source_type=source_type
        )
        
        return event

    async def _send_critical_alert(self, ip: str, threats: List[str], geo_data: dict, score: int):
        """Send critical threat alert with map"""
        subject = f"CRITICAL THREAT: {ip} - Score: {score}"
        body = f"Critical threat detected:\nIP: {ip}\nThreats: {', '.join(threats)}\nLocation: {geo_data.get('country')}, {geo_data.get('city')}"
        
        await send_email(subject, body, os.getenv("ALERT_EMAIL", "admin@example.com"))
        
        # Generate threat map
        try:
            lat_f = float(geo_data.get("lat", 0))
            lon_f = float(geo_data.get("lon", 0))
            if lat_f != 0 and lon_f != 0:
                m = folium.Map(location=[lat_f, lon_f], zoom_start=4)
                folium.Marker(
                    location=[lat_f, lon_f],
                    popup=f"Critical Threat: {ip}\nScore: {score}",
                    icon=folium.Icon(color="red")
                ).add_to(m)
                map_file = f"threat_map_{ip.replace('.', '_')}.html"
                m.save(map_file)
                logger.info(f"Threat map saved: {map_file}")
        except Exception as e:
            logger.error(f"Map generation failed: {e}")

    async def _send_high_alert(self, ip: str, threats: List[str], geo_data: dict, score: int):
        """Send high severity alert"""
        subject = f"HIGH THREAT: {ip} - Score: {score}"
        body = f"High severity threat:\nIP: {ip}\nThreats: {', '.join(threats)}\nLocation: {geo_data.get('country')}"
        await send_email(subject, body, os.getenv("ALERT_EMAIL", "admin@example.com"))

    async def parse_data(self, data: bytes) -> List[Event]:
        """Parse JSON data"""
        events: List[Event] = []
        try:
            content = json.loads(data.decode(errors="ignore"))
            ip = extract_ip(content)
            if not ip:
                return events
                
            event = await self._process_threat_analysis(ip, json.dumps(content), "json")
            events.append(event)
            
            # Add to batch buffer
            self.batch_buffer.append(event)
            if len(self.batch_buffer) >= self.batch_size:
                await self._flush_batch()  # FIX 7: Fixed method name
                
        except Exception as e:
            logger.error(f"JSON parsing failed: {e}")
        
        return events

    async def parse_pcap(self, filepath: str, limit: Optional[int] = 1000) -> List[Event]:
        """Parse PCAP file"""
        events: List[Event] = []
        logger.info(f"Reading PCAP file: {filepath}")
        
        try:
            packets = rdpcap(filepath)
            logger.info(f"Loaded {len(packets)} packets")
        except Exception as e:
            logger.error(f"Failed to read PCAP: {e}")
            return events
            
        processed_ips = set()  # Avoid duplicate processing per batch
        
        for pkt in packets[:limit]:
            if not (IP in pkt):
                continue
                
            src_ip = pkt[IP].src
            
            # Skip private IPs and already processed IPs in this batch
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj.is_private or src_ip in processed_ips:
                    continue
            except Exception:
                continue
                
            processed_ips.add(src_ip)
            
            # Extract payload
            payload = ""
            try:
                if Raw in pkt:
                    raw_load = pkt[Raw].load
                    if isinstance(raw_load, bytes):
                        payload = raw_load.decode("utf-8", errors="ignore")
                    else:
                        payload = str(raw_load)
            except Exception:
                payload = ""
            
            # Add port analysis to payload
            port_info = ""
            try:
                if TCP in pkt:
                    dst_port = int(pkt[TCP].dport)
                    if dst_port in suspicious_ports:
                        port_info = f" suspicious_port:{dst_port}"
            except Exception:
                pass
            
            content = payload + port_info
            if content.strip():  # Only process if there's actual content
                event = await self._process_threat_analysis(src_ip, content, "pcap")
                events.append(event)
                
                # Add to batch buffer
                self.batch_buffer.append(event)
                if len(self.batch_buffer) >= self.batch_size:
                    await self._flush_batch()
                    
        return events

    async def parse_log(self, text: str) -> List[Event]:
        """Parse plain text logs"""
        events: List[Event] = []
        if not text:
            return events
            
        lines = text.splitlines()
        for line in lines:
            if not line.strip():
                continue
                
            ip = extract_ip(line)
            if not ip:
                continue
                
            event = await self._process_threat_analysis(ip, line, "log")
            events.append(event)
            
            # Add to batch buffer
            self.batch_buffer.append(event)
            if len(self.batch_buffer) >= self.batch_size:
                await self._flush_batch()
                
        return events

    async def ingest_file(self, filepath: str) -> AsyncGenerator[Event, None]:
        """Handle different file types"""
        file_ext = os.path.splitext(filepath)[1].lower()
        
        try:
            if file_ext == ".pcap":
                events = await self.parse_pcap(filepath)
                for event in events:
                    yield event
                    
            elif file_ext in (".json", ".jsonl"):
                async with aiofiles.open(filepath, "rb") as f:
                    if file_ext == ".jsonl":
                        # Process line by line for JSONL
                        async for line in f:
                            events = await self.parse_data(line)
                            for event in events:
                                yield event
                    else:
                        # Process entire file for JSON
                        content = await f.read()
                        events = await self.parse_data(content)
                        for event in events:
                            yield event
                            
            else:
                # Plain text logs
                async with aiofiles.open(filepath, "r", encoding="utf-8") as f:
                    content = await f.read()
                    events = await self.parse_log(content)
                    for event in events:
                        yield event
                        
        except Exception as e:
            logger.error(f"File ingestion failed for {filepath}: {e}")
            
        finally:
            # Flush any remaining events in batch
            await self._flush_batch()

    async def _stop(self):
        """Clean shutdown - flush remaining batches"""
        await self._flush_batch()
        logger.info("Ingestor stopped, all batches flushed")
