from .port_scan import detect as port_scan_detect
from .dns_abuse import detect as dns_beaconing_detect

RULES = [
    port_scan_detect,
    dns_beaconing_detect
]
