import pytest
from wazuh_mcp_server import transform_to_mcp

def test_transform_to_mcp():
    event = {
        "id": "test-event",
        "category": "intrusion_detection",
        "severity": "high",
        "description": "Test description",
        "data": {"key": "value"}
    }
    mcp_message = transform_to_mcp(event, event_type="alert")
    assert mcp_message["protocol_version"] == "1.0"
    assert mcp_message["source"] == "Wazuh"
    assert mcp_message["context"]["id"] == "test-event"
