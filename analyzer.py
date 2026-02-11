from checks import is_external_ip,is_sensitive_port


def identifying_suspicions_ips(data):
    suspicions_ips = [ip[1] for ip in data if is_external_ip(ip[1])]
    return suspicions_ips


def identifying_sensitives_ports(data):
    sensitives_ports = [port for port in data if is_sensitive_port(port[3])]
    return sensitives_ports







