import pytest
from datetime import datetime
from src.core.models import NetworkEvent, EventSeverity, Detection

def test_network_event_creation():
    """Test creating a network event"""
    event = NetworkEvent(
        source="firewall",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        bytes_sent=1024,
        packets=10
    )
    
    assert event.id is not None
    assert event.type == "network"
    assert event.src_port == 54321
    
def test_detection_confidence_validation():
    """Test detection confidence bounds"""
    with pytest.raises(ValueError):
        Detection(
            event_id="test123",
            rule_name="Test Rule",
            confidence=1.5,  # Should fail
            severity=EventSeverity.HIGH,
            threat_type="malware"
        )
        
