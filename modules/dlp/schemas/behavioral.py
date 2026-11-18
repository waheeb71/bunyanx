from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class BEFPFeedbackSchema(BaseModel):
    event_id: str = Field(..., description="ID of the BEFP detection event")
    label: str    = Field(..., description="'true_positive' or 'false_positive'")
    features: Optional[Dict[str, Any]] = None

class FeedbackReviewSchema(BaseModel):
    action: str = Field(..., description="'approve' or 'reject'")

class ERSTestSchema(BaseModel):
    """Payload for ad-hoc ERS testing from the UI."""
    src_ip: str  = Field("192.168.1.10")
    dst_ip: str  = Field("8.8.8.8")
    protocol: str = Field("DNS")
    dst_port: int = Field(53)
    payload_hex: str = Field(..., max_length=16384, description="Hex-encoded payload bytes (max 8KB raw)")
