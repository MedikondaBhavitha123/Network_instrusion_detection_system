from flask import Flask, render_template, request, send_file
import os
import plotly.graph_objects as go
from scapy.all import *
from tabulate import tabulate
import pdfkit  
from datetime import datetime


app = Flask(__name__)

# Define global variables to store statistics and alerts
packet_count = 0
packet_sizes = {}
arp_cache_poisoning_alerts = set()
famous_worms = ["Conficker", "Sasser", "Blaster", "babbi.exe", "bhavana.dll", "kumaran_Sir.doc", "kavitha_mam.dll"]
amplified_dos_alerts = set()
port_scan_alerts = {}
suspicious_user_agents = set()

# Define a list of known sinkholed domains
sinkholed_domains = ["example.com", "malicious.com","sunny.com", "anjani.com", "nidhi_mam.com"]

# Define a dictionary to store ARP cache
arp_cache = {}

# Define a list of known malware-related patterns
malware_patterns = ["malicious.exe", "virus.dll", "trojan.doc"]

# Define a list to collect all alerts
alerts = []

# Function to detect malware patterns in packet data
def detect_malware(packet_data):
    for pattern in malware_patterns:
        if pattern in packet_data:
            return True
    return False

# Function to process each packet
def process_packet(packet):
    global packet_count

    # Count packets
    packet_count += 1

    # Get packet size
    packet_size = len(packet)
    if packet_size in packet_sizes:
        packet_sizes[packet_size] += 1
    else:
        packet_sizes[packet_size] = 1

    # Detect LAN-based servers
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80, 443]:
            alerts.append(["LAN-based server", f"{packet[IP].src}:{packet[TCP].sport}", f"{packet[IP].dst}:{packet[TCP].dport}"])

    # Detect DNS queries for sinkholed domains
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        for domain in sinkholed_domains:
            if domain in query:
                alerts.append(["DNS query for sinkholed domain", f"{packet[IP].src}", f"{packet[IP].dst}", query])

    # Detect ARP cache poisoning attacks
    if packet.haslayer(ARP):
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        if arp_src_ip in arp_cache and arp_cache[arp_src_ip] != arp_dst_ip:
            arp_cache_poisoning_alerts.add(arp_src_ip)
            alerts.append(["ARP Cache Poisoning", arp_src_ip])
        arp_cache[arp_src_ip] = arp_dst_ip

    # Detect the presence of famous worms
    if packet.haslayer(Raw):
        packet_data = packet[Raw].load.decode(errors='ignore')
        for worm in famous_worms:
            if worm in packet_data:
                alerts.append(["Famous Worm", worm])

    # Detect amplified denial-of-service attacks
    if packet.haslayer(UDP) and packet[UDP].dport == 53:
        dns_query = packet[DNS]
        if dns_query.qdcount > 1:
            amplified_dos_alerts.add(packet[IP].src)
            alerts.append(["Amplified DoS Attack", packet[IP].src])

    # Detect port scanning activities
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        if src_port in port_scan_alerts:
            port_scan_alerts[src_port] += 1
        else:
            port_scan_alerts[src_port] = 1
            alerts.append(["Port Scan", f"Source Port: {src_port}", f"Destination: {packet[IP].dst}"])

    # Detect suspicious user agents in HTTP requests
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        packet_data = packet[Raw].load.decode(errors='ignore')
        if "User-Agent:" in packet_data:
            user_agent = packet_data.split("User-Agent:")[1].strip()
            suspicious_user_agents.add(user_agent)
            alerts.append(["Suspicious User Agent", user_agent, packet[IP].src])

    # Detect potential malware patterns in packet data
    if packet.haslayer(Raw):
        packet_data = packet[Raw].load.decode(errors='ignore')
        if detect_malware(packet_data):
            alerts.append(["Potential Malware", f"{packet[IP].src}", f"{packet[IP].dst}"])

def analyze_pcap(pcap_file_path):
    global packet_count, packet_sizes, arp_cache_poisoning_alerts, amplified_dos_alerts, port_scan_alerts, suspicious_user_agents, alerts
    packet_count = 0
    packet_sizes = {}
    arp_cache_poisoning_alerts = set()
    amplified_dos_alerts = set()
    port_scan_alerts = {}
    suspicious_user_agents = set()
    alerts = []

    # Read the pcap file and process each packet
    packets = rdpcap(pcap_file_path)
    for packet in packets:
        process_packet(packet)

    # Check if there are no alerts
    if not alerts:
        return "<p style='font-weight: bold; font-size: 80px; color: black;'>Your network is safe ✅. No suspicious activity detected in the provided pcap file.</p>"

    # Extract FAMOUS WORMS, DNS QUERY FOR SINKHOLED COMMANDS, LAN BASED SERVER details
    famous_worms_alerts = [alert[1] for alert in alerts if alert[0] == "Famous Worm"]
    dns_sinkhole_alerts = [alert[3] for alert in alerts if alert[0] == "DNS query for sinkholed domain"]
    lan_server_alerts = [alert[1] for alert in alerts if alert[0] == "LAN-based server"]

    # Overall statistics
    overall_stats = f"Total packets: {packet_count}"

    # Packet Sizes
    size_table = [["Size", "Count"]] + list(packet_sizes.items())

    # ARP Cache Poisoning Alerts
    arp_table = [["IP Address"]] + [[ip] for ip in arp_cache_poisoning_alerts]

    # Amplified DoS Alerts
    dos_table = [["Source IP"]] + [[ip] for ip in amplified_dos_alerts]

    # Port Scan Alerts
    scan_table = [["Source Port", "Count"]] + [[src_port, count] for src_port, count in port_scan_alerts.items() if count > 10]

    # Suspicious User Agents
    user_agent_table = [["User Agent"]] + [[user_agent] for user_agent in suspicious_user_agents]

    # Malware Alerts
    malware_table = [["Alert Type", "Source IP", "Destination IP", "Details"]] + alerts

    # Extracting the types of alerts for pie chart
    alert_types = [alert[0] for alert in alerts]

    # Counting the occurrences of each alert type
    alert_counts = {alert_type: alert_types.count(alert_type) for alert_type in set(alert_types)}

    # Create a pie chart
    fig = go.Figure(data=[go.Pie(labels=list(alert_counts.keys()), values=list(alert_counts.values()))])

    # Save the pie chart to a file (optional)
    pie_chart_path = "uploads/pie_chart.png"
    fig.write_image(pie_chart_path)

    # Create the result HTML
    result = f"""
    <style>
    # h2 {{
    #     font-size: 24px;
    # }}

    # p {{
    #     font-size: 16px;
    # }}

    details {{
        margin-top: 20px;
    }}

    .dropbtn {{
        cursor: pointer;
        padding: 10px;
        background-color: #1263e6;
        color: white;
        font-weight: bold;
    }}

    .dropdown-content {{
        display: none;
        padding: 10px;
    }}

    details[open] .dropdown-content {{
        display: block;
    }}

    ul {{
        list-style: none;
        padding: 0;
    }}

    li {{
        margin-bottom: 8px;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }}

    th, td {{
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }}

    th {{
        background-color: #056409;
        color: white;
    }}
    </style>
    <h2>Overall Statistics</h2>
    <p>{overall_stats}</p>

    <!-- ... (existing code) -->

    <h2>Types of Attacks Distribution (Pie Chart)</h2>
    <img src='/uploads/pie_chart.png' alt='Types of Attacks Distribution'>

    <details>
        <summary class="dropbtn">FAMOUS WORMS</summary>
        <div class="dropdown-content">
            <ul>
                {"".join(f"<li>{worm}</li>" for worm in famous_worms_alerts)}
            </ul>
        </div>
    </details>

    <details>
        <summary class="dropbtn">DNS QUERY FOR SINKHOLED COMMANDS</summary>
        <div class="dropdown-content">
            <ul>
                {"".join(f"<li>{query}</li>" for query in dns_sinkhole_alerts)}
            </ul>
        </div>
    </details>

    <details>
        <summary class="dropbtn">LAN BASED SERVER</summary>
        <div class="dropdown-content">
            <ul>
                {"".join(f"<li>{server}</li>" for server in lan_server_alerts)}
            </ul>
        </div>
    </details>

    <details>
        <summary class="dropbtn">Packet Sizes</summary>
        <div class="dropdown-content">
            {tabulate(size_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>

    <details>
        <summary class="dropbtn">ARP Cache Poisoning Alerts</summary>
        <div class="dropdown-content">
            {tabulate(arp_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>

    <details>
        <summary class="dropbtn">Amplified DoS Alerts</summary>
        <div class="dropdown-content">
            {tabulate(dos_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>

    <details>
        <summary class="dropbtn">Port Scan Alerts</summary>
        <div class="dropdown-content">
            {tabulate(scan_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>

    <details>
        <summary class="dropbtn">Suspicious User Agents</summary>
        <div class="dropdown-content">
            {tabulate(user_agent_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>

    <details>
        <summary class="dropbtn">Malware Alerts</summary>
        <div class="dropdown-content">
            {tabulate(malware_table, headers="firstrow", tablefmt="html")}
        </div>
    </details>
    """

    return result

# Add this route to serve the pie chart image
@app.route('/uploads/pie_chart.png')
def pie_chart():
    return send_file('uploads/pie_chart.png', mimetype='image/png')

@app.route('/download_html', methods=['POST'])
def download_html():
    result_html = request.form.get('result_html')

    if result_html:
        # Generate a unique filename using the current date and time
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_filename = f"result_{date_str}.html"
        html_path = os.path.join(app.config['UPLOAD_FOLDER'], html_filename)

        # Write the result HTML to a file
        with open(html_path, 'w', encoding='utf-8') as html_file:
            html_file.write(result_html)

        return send_file(html_path, as_attachment=True, download_name=html_filename)

    return "Error: No result HTML provided."

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None

    if request.method == 'POST':
        if 'pcapFile' in request.files:
            pcap_file = request.files['pcapFile']

            if pcap_file.filename != '' and pcap_file.filename.endswith('.pcap'):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], pcap_file.filename)
                pcap_file.save(file_path)

                result = analyze_pcap(file_path)

                os.remove(file_path)

    return render_template('index.html', result=result)



if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)

