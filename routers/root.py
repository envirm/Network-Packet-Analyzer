from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def read_root():
    return {"message": "✅ FastAPI Firewall is Running. Use /analyze or /firewall_state."}
