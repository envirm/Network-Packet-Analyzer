# Create multi-agent components.
from charset_normalizer import detect
from app import FirewallAgent, FirewallRepository, ManagerAgent, ModelAgent, PacketPipeline, ThreatDetector







# Instantiate components: repository, pipeline, and threat detector.
firewall_repo = FirewallRepository()
pipeline = PacketPipeline()
detector = ThreatDetector()
firewall_agent = FirewallAgent(firewall_repo)
model_agent = ModelAgent(detect)
manager_agent = ManagerAgent(model_agent, firewall_agent)