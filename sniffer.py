import socket
import os
import struct
from datetime import datetime
import ipaddress

# Simple banner
BANNER = """
██╗  ██╗ ██████╗  █████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
██║ ██╔╝██╔═══██╗██╔══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
█████╔╝ ██║   ██║███████║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ 
██╔═██╗ ██║   ██║██╔══██║██║╚██╗██║  ╚██╔╝   ██╔██╗ 
██║  ██╗╚██████╔╝██║  ██║██║ ╚████║   ██║   ██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
                    PACKET SNIFFER
=====================================================
"""

# Protocol names
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Common ports and their services
KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NETBIOS",
    138: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-TRAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "PROXY", 1433: "MSSQL", 1521: "ORACLE",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB"
}

# Private IP ranges
PRIVATE_IPS = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8'
]

def is_private_ip(ip):
    """Check if IP is private/local"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(range) for range in PRIVATE_IPS)
    except:
        return False

def get_ip_type(ip):
    """Identify what kind of IP this is"""
    if ip.startswith('224.') or ip.startswith('239.'):
        return "MULTICAST"
    elif ip.startswith('255.') or ip == '255.255.255.255':
        return "BROADCAST"
    elif ip.startswith('0.'):
        return "DEFAULT"
    elif is_private_ip(ip):
        return "LOCAL"
    else:
        return "PUBLIC"

def get_service(port):
    """Get service name from port"""
    return KNOWN_PORTS.get(port, f"UNKNOWN-{port}")

print(BANNER)

# Must run as Administrator
if os.name == 'nt':
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Please run as Administrator!")
        print("[*] Right-click Command Prompt -> Run as Administrator")
        exit(1)

# Get local IP for reference
try:
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"[*] Local IP: {local_ip}")
except:
    local_ip = "Unknown"

print("[*] Sniffer started...")
print("[*] Press Ctrl+C to stop\n")

try:
    # Create socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(('0.0.0.0', 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Enable promiscuous mode
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except:
        pass
    
    packet_count = 0
    traffic_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
    
    while True:
        # Receive packet
        packet, addr = sniffer.recvfrom(65565)
        packet_count += 1
        
        # Parse IP header
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extract IP info
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        ip_header_length = ihl * 4
        total_length = iph[2]
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        
        # Update stats
        proto_name = PROTOCOLS.get(protocol, "OTHER")
        traffic_stats[proto_name] = traffic_stats.get(proto_name, 0) + 1
        
        # Identify traffic direction
        if src_ip == local_ip:
            direction = "OUTGOING"
            direction_symbol = "⬆️"
        elif dest_ip == local_ip:
            direction = "INCOMING"
            direction_symbol = "⬇️"
        else:
            direction = "PASSING"
            direction_symbol = "🔄"
        
        # Get IP types
        src_type = get_ip_type(src_ip)
        dest_type = get_ip_type(dest_ip)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        print(f"\n[{timestamp}] Packet #{packet_count} {direction_symbol} {direction}")
        print(f"    Source: {src_ip} [{src_type}]")
        print(f"    Dest:   {dest_ip} [{dest_type}]")
        print(f"    Protocol: {proto_name} (TTL: {ttl}, Size: {total_length} bytes)")
        
        # Parse based on protocol
        if protocol == 6 and len(packet) > ip_header_length + 20:  # TCP
            tcp_start = ip_header_length
            tcp_header = packet[tcp_start:tcp_start+20]
            tcp = struct.unpack('!HHLLBBHHH', tcp_header[:20])
            
            src_port = tcp[0]
            dest_port = tcp[1]
            flags = tcp[5]
            
            # Decode TCP flags
            flag_names = []
            if flags & 0x01: flag_names.append("FIN")
            if flags & 0x02: flag_names.append("SYN")
            if flags & 0x04: flag_names.append("RST")
            if flags & 0x08: flag_names.append("PSH")
            if flags & 0x10: flag_names.append("ACK")
            if flags & 0x20: flag_names.append("URG")
            
            flag_str = "|".join(flag_names) if flag_names else "None"
            
            src_service = get_service(src_port)
            dest_service = get_service(dest_port)
            
            print(f"    TCP Ports: {src_port} [{src_service}] -> {dest_port} [{dest_service}]")
            print(f"    TCP Flags: {flag_str}")
            
            # Special identification
            if src_port == 80 or dest_port == 80:
                print(f"    📄 HTTP Web Traffic")
            elif src_port == 443 or dest_port == 443:
                print(f"    🔒 HTTPS Encrypted")
            elif src_port == 22 or dest_port == 22:
                print(f"    💻 SSH Remote Access")
            elif src_port == 21 or dest_port == 21:
                print(f"    📁 FTP File Transfer")
            elif src_port == 25 or dest_port == 25:
                print(f"    📧 SMTP Email")
            elif src_port == 53 or dest_port == 53:
                print(f"    🌐 DNS Query")
            elif src_port == 3389 or dest_port == 3389:
                print(f"    🖥️ RDP Remote Desktop")
            
        elif protocol == 17 and len(packet) > ip_header_length + 8:  # UDP
            udp_start = ip_header_length
            udp_header = packet[udp_start:udp_start+8]
            udp = struct.unpack('!HHHH', udp_header)
            
            src_port = udp[0]
            dest_port = udp[1]
            udp_length = udp[2]
            
            src_service = get_service(src_port)
            dest_service = get_service(dest_port)
            
            print(f"    UDP Ports: {src_port} [{src_service}] -> {dest_port} [{dest_service}]")
            print(f"    UDP Length: {udp_length} bytes")
            
            # Special identification
            if src_port == 53 or dest_port == 53:
                print(f"    🌐 DNS Query")
            elif src_port == 67 or src_port == 68 or dest_port == 67 or dest_port == 68:
                print(f"    🏠 DHCP Request")
            elif src_port == 123 or dest_port == 123:
                print(f"    ⏰ NTP Time Sync")
            elif src_port == 161 or dest_port == 161:
                print(f"    📊 SNMP Network Management")
            
        elif protocol == 1:  # ICMP
            icmp_start = ip_header_length
            icmp_header = packet[icmp_start:icmp_start+4]
            icmp = struct.unpack('!BBH', icmp_header[:4])
            
            icmp_type = icmp[0]
            icmp_code = icmp[1]
            
            # ICMP type meanings
            icmp_msgs = {
                0: "Echo Reply (Ping Reply)",
                3: "Destination Unreachable",
                8: "Echo Request (Ping)",
                11: "Time Exceeded"
            }
            
            icmp_msg = icmp_msgs.get(icmp_type, f"Type {icmp_type}")
            print(f"    ICMP: {icmp_msg} (Code: {icmp_code})")
        
        # Show if it's broadcast/multicast
        if dest_ip.endswith('.255') or dest_ip == '255.255.255.255':
            print(f"    📢 BROADCAST Message")
        elif dest_ip.startswith('224.') or dest_ip.startswith('239.'):
            print(f"    👥 MULTICAST Message")
        
        print("-" * 60)

except KeyboardInterrupt:
    print(f"\n\n{'='*50}")
    print("SNIFFER STATISTICS")
    print('='*50)
    print(f"Total packets captured: {packet_count}")
    print(f"TCP packets: {traffic_stats.get('TCP', 0)}")
    print(f"UDP packets: {traffic_stats.get('UDP', 0)}")
    print(f"ICMP packets: {traffic_stats.get('ICMP', 0)}")
    print(f"Other protocols: {traffic_stats.get('OTHER', 0)}")
    print('='*50)
    
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except:
        pass
        
except PermissionError:
    print("[-] Permission denied! Run as Administrator.")
except Exception as e:
    print(f"[-] Error: {e}")