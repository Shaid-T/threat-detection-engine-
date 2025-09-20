from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum
import hashlib
import json

class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EventType(str, Enum):
    NETWORK = "network"
    FILE = "file"
    PROCESS = "process"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"

class BaseEvent(BaseModel):
    """Base event model that all events inherit from"""
    
    id: Optional[str] = Field(None, description="Unique event ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(..., description="Event source")
    type: EventType
    severity: EventSeverity = EventSeverity.INFO
    raw_data: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('id', always=True)
    def generate_id(cls, v, values):
        if v is None:
            # Generate deterministic ID from content
            content = f"{values.get('timestamp')}{values.get('source')}{values.get('type')}"
            return hashlib.sha256(content.encode()).hexdigest()[:16]
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class NetworkEvent(BaseEvent):
    """Network traffic event"""
    
    type: EventType = EventType.NETWORK
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    flags: List[str] = Field(default_factory=list)
    
    @validator('src_port', 'dst_port')
    def validate_port(cls, v):
        if not 0 <= v <= 65535:
            raise ValueError(f"Invalid port number: {v}")
        return v

class Detection(BaseModel):
    """Detection result model"""
    
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    rule_id: Optional[str] = None
    rule_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: EventSeverity
    threat_type: str
    indicators: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
