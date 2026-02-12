from config import INTERNAL_IP, SENSITIVE_PORTS,NORMAL_SIZE,NIGHT_ACTIVITY

def is_external_ip(ip_address):
    return not ip_address.startswith(INTERNAL_IP)

def is_sensitive_port(port):
    return port in SENSITIVE_PORTS

def is_large_packet(packet):
    return packet > NORMAL_SIZE

def is_night_active(time):
    return time in NIGHT_ACTIVITY
