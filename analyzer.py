from checks import is_external_ip, is_sensitive_port, is_large_packet
from reader import csv_list_load


def identifying_suspicions_ips(data):
    suspicions_ips = [ip[1] for ip in data if is_external_ip(ip[1])]
    return suspicions_ips


def identifying_sensitives_ports(data):
    sensitives_ports = [port for port in data if is_sensitive_port(port[3])]
    return sensitives_ports


def identifying_large_packets(data):
    large_packets = [packet for packet in data if is_large_packet(int(packet[5]))]
    return large_packets


def tag_large_packets(data):
    tag_list = [log + ["LARGE"] if is_large_packet(int(log[5])) else log + ["NORMAL"] for log in data]
    return tag_list

d = csv_list_load("network_traffic.log")
def count_requests_by_ip(data):
    ip_counts = {}
    for log in data:
        ip_counts[log[1]] = ip_counts.get(log[1],0) + 1
    return ip_counts
print(count_requests_by_ip(d))


