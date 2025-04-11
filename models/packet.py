from pydantic import BaseModel

class Packet(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
