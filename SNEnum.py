import logging
import datetime
import csv
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
import urwid
from flask import Flask, render_template_string, jsonify
import threading

# Initialize logging
log_filename = "traffic_log.log"
alert_log_filename = "alert_log.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(message)s')
logging.basicConfig(filename=alert_log_filename, level=logging.WARNING, format='%(message)s')

# Store seen packets to avoid redundancy
seen_packets_v4 = set()
seen_packets_v6 = set()

# Initialize list to store packet details for displaying in the terminal
packet_details_v4 = []
packet_details_v6 = []

console = Console()

# Flask web server setup
app = Flask(__name__)

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic</title>
    <style>
        table {width: 100%; border-collapse: collapse;}
        th, td {border: 1px solid black; padding: 8px; text-align: left;}
        th {background-color: #f2f2f2; cursor: pointer;}
    </style>
</head>
<body>
    <h1>IPv4 Network Traffic</h1>
    <table id="ipv4Table">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'ipv4Table')">Timestamp</th>
                <th onclick="sortTable(1, 'ipv4Table')">Source IP</th>
                <th onclick="sortTable(2, 'ipv4Table')">Source Port</th>
                <th onclick="sortTable(3, 'ipv4Table')">Destination IP</th>
                <th onclick="sortTable(4, 'ipv4Table')">Destination Port</th>
                <th onclick="sortTable(5, 'ipv4Table')">Protocol</th>
            </tr>
        </thead>
        <tbody id="ipv4TableBody">
        </tbody>
    </table>
    <h1>IPv6 Network Traffic</h1>
    <table id="ipv6Table">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'ipv6Table')">Timestamp</th>
                <th onclick="sortTable(1, 'ipv6Table')">Source IP</th>
                <th onclick="sortTable(2, 'ipv6Table')">Source Port</th>
                <th onclick="sortTable(3, 'ipv6Table')">Destination IP</th>
                <th onclick="sortTable(4, 'ipv6Table')">Destination Port</th>
                <th onclick="sortTable(5, 'ipv6Table')">Protocol</th>
            </tr>
        </thead>
        <tbody id="ipv6TableBody">
        </tbody>
    </table>

    <script>
        function fetchDataAndRender() {
            fetch('/data')
            .then(response => response.json())
            .then(data => {
                updateTable('ipv4Table', data.ipv4);
                updateTable('ipv6Table', data.ipv6);
            });
        }

        // Fetch data initially
        fetchDataAndRender();

        // Refresh data every 5 seconds
        setInterval(fetchDataAndRender, 5000);

        function updateTable(tableId, data) {
            const tableBody = document.getElementById(tableId + 'Body');
            tableBody.innerHTML = '';
            data.forEach(rowData => {
                const row = document.createElement('tr');
                rowData.forEach(cellData => {
                    const cell = document.createElement('td');
                    cell.textContent = cellData;
                    row.appendChild(cell);
                });
                tableBody.appendChild(row);
            });
        }

        let dir = 'asc'; // Initialize the direction outside the function

        function sortTable(columnIndex, tableId) {
            const table = document.getElementById(tableId);
            const rows = table.rows;
            let switching = true; // Use let instead of const here
            let i, x, y;

            while (switching) {
                switching = false;
                for (i = 1; i < (rows.length - 1); i++) {
                    x = rows[i].getElementsByTagName('td')[columnIndex];
                    y = rows[i + 1].getElementsByTagName('td')[columnIndex];
                    if ((dir === 'asc' && x.textContent.toLowerCase() > y.textContent.toLowerCase()) || 
                        (dir === 'desc' && x.textContent.toLowerCase() < y.textContent.toLowerCase())) {
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        break; // Exit the loop after a switch
                    }
                }
            }
            // Toggle direction after sorting
            dir = (dir === 'asc') ? 'desc' : 'asc';
        }

    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(html_template, packets_v4=packet_details_v4, packets_v6=packet_details_v6)

@app.route('/data')
def get_data():
    return jsonify({'ipv4': packet_details_v4, 'ipv6': packet_details_v6})

def run_flask_app():
    app.run(host='0.0.0.0', port=5000)

# Function to detect suspicious activity
def detect_suspicious_activity(packet):
    if TCP in packet and packet[TCP].dport == 80:  # Example condition
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src if IP in packet else packet[IPv6].src
        dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
        logging.warning(f"{timestamp} Suspicious activity detected from {src_ip} to {dst_ip}")

# Function to process IPv4 packets
def process_ipv4_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = None
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    if protocol:
        packet_id = (src_ip, dst_ip, protocol, src_port, dst_port)
        if packet_id not in seen_packets_v4:
            seen_packets_v4.add(packet_id)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packet_info = [timestamp, src_ip, src_port, dst_ip, dst_port, protocol]

            # Log to file
            logging.info(f"{timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol}")
            
            # Add to packet details for terminal display
            packet_details_v4.append(packet_info)
            return packet_info
    return None

# Function to process IPv6 packets
def process_ipv6_packet(packet):
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst
    protocol = None
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    if protocol:
        packet_id = (src_ip, dst_ip, protocol, src_port, dst_port)
        if packet_id not in seen_packets_v6:
            seen_packets_v6.add(packet_id)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packet_info = [timestamp, src_ip, src_port, dst_ip, dst_port, protocol]

            # Log to file
            logging.info(f"{timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol}")
            
            # Add to packet details for terminal display
            packet_details_v6.append(packet_info)
            return packet_info
    return None

# Function to process packets
def process_packet(packet):
    detect_suspicious_activity(packet)
    if IP in packet:
        return process_ipv4_packet(packet)
    elif IPv6 in packet:
        return process_ipv6_packet(packet)
    return None

# Function to create the terminal table
def create_table(title, packet_details):
    table = Table(title=title, style="bold blue")
    
    headers = ["Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]
    for header in headers:
        table.add_column(header, style="cyan")
    
    for packet_info in packet_details:
        table.add_row(*[str(item) for item in packet_info])

    return table

# Function to export packet details to CSV
def export_to_csv():
    with open('packet_details.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        headers = ["Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]
        writer.writerow(headers)
        for packet in packet_details_v4 + packet_details_v6:
            writer.writerow(packet)

# Function to update the display
def update_display():
    protocol_filter = None  # None means no filtering

    def refresh_data(loop, user_data):
        sniff(prn=process_packet, store=False, count=1, timeout=1)
        body[:] = [urwid.Text(str(packet)) for packet in packet_details_v4 + packet_details_v6 if not protocol_filter or packet[5] == protocol_filter]
        loop.set_alarm_in(1, refresh_data)

    def set_filter(protocol):
        nonlocal protocol_filter
        protocol_filter = protocol

    def clear_filter(button):
        set_filter(None)

    headers = ["Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]
    body = urwid.SimpleFocusListWalker([urwid.Text(str(packet)) for packet in packet_details_v4 + packet_details_v6])
    listbox = urwid.ListBox(body)
    header_buttons = [urwid.Button(h, on_press=lambda button, h=h: sort_by(h)) for h in headers]
    header = urwid.Columns(header_buttons)
    filter_buttons = [
        urwid.Button('Show All', on_press=clear_filter),
        urwid.Button('Show TCP', on_press=lambda button: set_filter('TCP')),
        urwid.Button('Show UDP', on_press=lambda button: set_filter('UDP'))
    ]
    filter_columns = urwid.Columns(filter_buttons)
    layout = urwid.Frame(header=urwid.Pile([header, filter_columns]), body=listbox)
    loop = urwid.MainLoop(layout)
    loop.set_alarm_in(1, refresh_data)
    loop.run()


if __name__ == "__main__":
    print("Starting packet sniffing... Press Ctrl+C to stop.")
    try:
        flask_thread = threading.Thread(target=run_flask_app)
        flask_thread.daemon = True
        flask_thread.start()
        update_display()
    except KeyboardInterrupt:
        print("Packet sniffing stopped.")
        export_to_csv()                          
