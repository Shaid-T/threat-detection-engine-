from src.ingestion.consumer import consume_event
from src.core.models import NetworkEvent

def test_consumer_handles_event():
	events = NetworkEvent(
        source="test_source",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        bytes_sent=200,
        packets=5
		)
    
	results = consume_event(events)
	assert results['src_ip'] == "10.0.0.1"
	assert results['severity'] is not None
    
