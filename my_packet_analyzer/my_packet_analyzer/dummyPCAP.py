from scapy.all import *

def generate_dummy_packet(domain, source_ip, dest_ip, malware_pattern):
    # Crafting a DNS request packet
    dns_request = Ether()/IP(src=source_ip, dst=dest_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    
    # Crafting a payload packet with malware pattern
    payload_packet = Ether()/IP(src=source_ip, dst=dest_ip)/Raw(load=malware_pattern)

    return dns_request, payload_packet

def create_dummy_pcap(sinkholed_domains, malware_patterns, output_file):
    # Specify source and destination IP addresses
    source_ip = "192.168.1.1"
    dest_ip = "8.8.8.8"

    # Create a list to store generated packets
    packets = []

    # Generate DNS request packets for sinkholed domains
    for domain in sinkholed_domains:
        dns_packet, _ = generate_dummy_packet(domain, source_ip, dest_ip, "")
        packets.append(dns_packet)

    # Generate payload packets with malware patterns
    for pattern in malware_patterns:
        _, payload_packet = generate_dummy_packet("dummy.com", source_ip, dest_ip, pattern)
        packets.append(payload_packet)

    # Write packets to a PCAP file
    wrpcap(output_file, packets)

if __name__ == "__main__":
    sinkholed_domains = ["sunny.com", "anjani.com", "nidhi_mam.com"]
    malware_patterns = ["babbi.exe", "bhavana.dll", "kumaran_Sir.doc", "kavitha_mam.dll"]
    output_file = "dummy_traffic.pcap"

    create_dummy_pcap(sinkholed_domains, malware_patterns, output_file)
    print(f"Dummy PCAP file '{output_file}' created successfully.")
