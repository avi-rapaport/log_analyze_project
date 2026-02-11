from checks import is_external_ip,is_sensitive_port,is_large_packet


def identifying_suspicions_ips(data):
    suspicions_ips = [ip[1] for ip in data if is_external_ip(ip[1])]
    return suspicions_ips


def identifying_sensitives_ports(data):
    sensitives_ports = [port for port in data if is_sensitive_port(port[3])]
    return sensitives_ports


def identifying_large_packets(data):
    large_packets = [packet for packet in data if is_large_packet(packet[5])]
    return large_packets

def tag_large_packets(data):
    tag_list = [log + ["LARGE"] if is_large_packet(log[5]) else log + ["NORMAL"] for log in data ]
    return tag_list



