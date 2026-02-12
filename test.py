from checks import is_external_ip, is_sensitive_port, is_large_packet, is_night_active
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


def count_requests_by_ip(data):
    ip_counts = {}
    for log in data:
        ip_counts[log[1]] = ip_counts.get(log[1], 0) + 1
    return ip_counts


def port_to_protocol_mapping(data):
    mapping_dict = {log[3]: log[4] for log in data}
    return mapping_dict


def suspicion_detection(data):
    return {
        ip: list({
            flag
            for log in data if log[1] == ip
            for flag in (
                "EXTERNAL_IP" if is_external_ip(log[1]) else None,
                "NIGHT_ACTIVITY" if is_night_active(log[0].split()[1].split(":")[0]) else None,
                "SENSITIVE_PORT" if is_sensitive_port(log[3]) else None,
                "LARGE_PACKET" if is_large_packet(int(log[5])) else None,
            )
            if flag
        })
        for ip in {log[1] for log in data}
    }


def suspicion_filtering(suspicions):
    filtered_dict = {ip: suspicions for ip, suspicions in suspicions.items() if len(suspicions) > 1}
    return filtered_dict
