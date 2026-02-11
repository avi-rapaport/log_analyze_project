from config import INTERNAL_IP

def is_external_ip(ip_address):
    return not ip_address.startswith(INTERNAL_IP)