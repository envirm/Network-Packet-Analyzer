from typing import Optional
from pydantic import BaseModel

class ThreatResponse(BaseModel):
    threat_detected: bool
    threat_type: str
    confidence: str
    action: str
    block_cidr: Optional[str]
