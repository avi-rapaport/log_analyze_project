from config import INTERNAL_IP, SENSITIVE_PORT,LARGE_PACKET

def is_external_ip(ip_address):
    return not ip_address.startswith(INTERNAL_IP)

def is_sensitive_port(port):
    return port in SENSITIVE_PORT

def is_large_packet(packet):
    return packet > LARGE_PACKET
