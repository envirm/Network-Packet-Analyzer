from fastapi import APIRouter, HTTPException
from models.packet import Packet
from services.firewall_service import FirewallService # type: ignore

router = APIRouter(prefix="/firewall", tags=["Firewall"])
service = FirewallService()

@router.post("/analyze")
def analyze_packet(packet: Packet):
    return service.analyze_packet(packet)

@router.get("/state")
def get_state():
    return service.get_firewall_state()

@router.delete("/unblock/{ip}")
def unblock(ip: str):
    return service.unblock_ip(ip)

@router.post("/block/{ip}")
def block_ip(ip: str):
    return service.manual_block(ip)

@router.delete("/unblock_all")
def unblock_all():
    return service.unblock_all()
