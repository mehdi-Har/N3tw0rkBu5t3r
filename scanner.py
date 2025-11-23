import signal
from scapy.all import ARP, ICMP, IP, sr1, Ether, srp, TCP, UDP , fragment
import ipaddress
import argparse
import sys
import socket
import ssl
import time
import struct
running = True
common_ports = {
    20: "FTP", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "Microsoft-DS", 3389: "RDP"
}
def resolve_hostname(ip):
    try:
        hostname , _ , _ = socket.gethostbyaddr(str(ip))
        return hostname
    except socket.herror:
        return None
def resolve_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def parse_ports(ports):
    port_list = []
    if '-' in ports:
        try:
            start, end = map(int, ports.split('-'))
            if start > end or end > 65535 or start < 1:
                raise ValueError('Port range is invalid')
            port_list = list(range(start, end + 1))
        except ValueError:
            print('Invalid port range, please specify valid port numbers.')
            sys.exit(1)
    else:
        try:
            port = int(ports)
            if port < 1 or port > 65535:
                raise ValueError('Port is outside the valid range.')
            port_list = [port]
        except ValueError:
            print('Choose a valid port number.')
            sys.exit(1)
    return port_list

def signal_handler(signum, frame):
    global running
    print("\nScan interrupted by the user")
    running = False

def is_valid_subnet(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
def fragment_packet(packet, mtu=1500):
    packet_size = len(bytes(packet))
    if packet_size <= mtu:
        return [packet]
    fragments = []
    offset = 0
    while offset < packet_size:
        fragment = packet.copy()
        
        fragment = fragment[:offset] + fragment[offset:offset + mtu]
        fragments.append(fragment)
        offset += mtu
    return fragments
def detect_os(ttl, window_size, tcp_options):
    os_signatures = {
        (64, 5840): "Linux kernel 2.4 or 2.6",
        (64, 5720): "Google's customized Linux",
        (64, 65535): "FreeBSD",
        (128, 65535): "Windows XP",
        (128, 8192): "Windows",
        (128, 4128): "Cisco Router (IOS 12.4)",
    }
    
    os_name = os_signatures.get((ttl, window_size), "Unknown OS")
    
    if tcp_options:
        if b'mss' in tcp_options:
            os_name += " with MSS option"
        if b'wsopt' in tcp_options:
            os_name += " with Window Scale option"
    
    return os_name
def grab_banner(host, port):
    try:
        if port == 443:  
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.send(b'HEAD / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    banner = ssock.recv(1024).decode().strip()
        else:  
            with socket.create_connection((host, port), timeout=2) as s:
                if port == 80:  
                    s.send(b'HEAD / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                elif port == 21: 
                    s.send(b'USER anonymous\r\n')
                elif port == 25:  
                    s.send(b'HELLO example.com\r\n')
                elif port == 139: 
                    s.send(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                elif port == 3389: 
                    s.send(b'\x03\x00\x00\x13\x00\x00\x00\x00')
                else:  
                    s.send(b'Hello\r\n')
                
                banner = s.recv(1024).decode().strip()

        if port in [80, 443]: 
            banner_lines = banner.split("\r\n")
            server_info = next((line.split(": ")[1] for line in banner_lines if "Server:" in line), "Unknown Server")
        else:
            server_info = banner.split("\n")[0]  

        return server_info.strip()

    except Exception as e:
        return "Could not grab server info"
def parse_tcp_flags(flags):
    valid_flags = {'S':'S' , 'A':'A' ,'F':'F' , 'P':'P','R':'R','U':'U'}
    flags = ''
    for flag in flags:
        if flag.upper() in valid_flags:
            flags.join(valid_flags[flag])
    if not flags :
        raise ValueError('Invalid TCP flags specified')
    return flags
def handle_response(response , flag , ports):
    if response is  None:
        return "No response  (port is filtered or closed)"
    if TCP in response:
        tcp_layer = response[TCP]
        flags = tcp_layer.flags
        if flag == 'S':
            if flags == 0x12:
                ports.append(tcp_layer.sport)
                return "Port is open (SYN, ACK response)"
            elif flags == 0x14:  
                return "Port is closed (RST, ACK response)"
            else:
                return "Unexpected response"
        elif flag == 'A':
            if flags == 0x14:
                return "Port is closed (RST, ACK response)"
            else:
                if response is None:
                    return "port is filtered"
                if ICMP in response:
                    icmp_layer = response[ICMP]
                    code = icmp_layer.code
                    if icmp_layer.type == 3:
                        if code == 0 or code == 1 or code == 2 or code == 3 or code == 9 or code == 10 or code == 13:
                            return "port filtered"
                return "could not determine the state of the port"
        elif flag == 'F':
            if flags == 0x14:
                 return "Port is closed (RST, ACK response)"
            else:
                if response is None:
                    ports.append(tcp_layer.sport)
                    return "port is open (no response)"
                return "Port might be open/filtered (no response)"
        elif flag == 'P':
            if flags == 0x14:  
                return "Port is closed (RST, ACK response)"
            else:
                return "Unexpected response"
        elif flag == 'U':  
            if flags == 0x14:  
                return "Port is closed (RST, ACK response)"
            else:
                return "Unexpected response"

        elif flag == 'R':  
            return "RST sent - no connection expected"

    return "Unexpected response or no TCP layer found"

def scan_host(host, ports, syn_scan_mode, OSdetection, udp_scan_mode, tcp_flags, timing_delay):
    open_ports = {'TCP': [], 'UDP': []}
    hostname = resolve_hostname(host)
    display_host = hostname if hostname else host
    print(f"Scanning host: {display_host} ({host})")
    if tcp_flags:
        print(f'Using custom TCP flags: {tcp_flags}')
        for port in ports:
            if not running:
                break
            packet = IP(dst=str(host))/ TCP(dport=port, flags=tcp_flags)
            fragments = fragment_packet(packet)
            for frag in fragments:
                response = sr1(frag, timeout=2, verbose=0)
                feedback = handle_response(response, tcp_flags, open_ports['TCP'])
                print(f'{port} {feedback}')
                time.sleep(timing_delay)  

    if syn_scan_mode and not tcp_flags:
        print("Using SYN scan for TCP port scanning...")
        for port in ports:
            if not running:
                break
            packet = IP(dst=str(host)) / TCP(dport=port, flags='S')
            fragments = fragment_packet(packet)
            for frag in fragments:
                response = sr1(frag, timeout=2, verbose=0)
                if response is not None and TCP in response and response[TCP].flags == 'SA':
                    print(f"Port {port} is open (SYN scan).")
                    open_ports['TCP'].append(port)
                elif response is None:
                    print(f"Port {port} is filtered or closed (no response).")
                else:
                    print(f"Port {port} is closed.")
                time.sleep(timing_delay) 

    elif not udp_scan_mode and not tcp_flags:
        print("Using regular connect scan for TCP ports...")
        for port in ports:
            if not running:
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect((host, port))
                print(f"Port {port} is open.")
                open_ports['TCP'].append(port)
            except socket.timeout:
                print(f"Port {port} is closed (timeout).")
            except:
                print(f"Port {port} is closed.")
            finally:
                s.close()
            time.sleep(timing_delay)  

    if udp_scan_mode:
        print("Using UDP scan for UDP ports...")
        for port in ports:
            if not running:
                break
            packet = IP(dst=str(host)) / UDP(dport=port)
            fragments = fragment_packet(packet)
            for frag in fragments:
                response = sr1(frag, timeout=2, verbose=0)
                if response is not None and UDP in response:
                    print(f"Port {port} is open (UDP scan).")
                    open_ports['UDP'].append(port)
                else:
                    print(f"Port {port} is closed or filtered (no response).")
                time.sleep(timing_delay) 

    if open_ports['TCP']:
        print("\nPort       Service             Server")
        for port in open_ports['TCP']:
            service = common_ports.get(port, "Unknown")
            server_info = grab_banner(host, port)
            print(f"{port:<10}{service:<20}{server_info} ({display_host})")


    if OSdetection and len(open_ports['TCP']) > 0:
        packet = IP(dst=str(host)) / TCP(dport=open_ports['TCP'][0], flags='S')
        response = sr1(packet, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            ttl = response[IP].ttl
            window_size = response[TCP].window
            tcp_options = response[TCP].options
            
            os_name = detect_os(ttl, window_size, tcp_options)
            print(f"Detected OS: {os_name}")
        else:
            print("OS could not be detected .No response received or inappropriate packet")

def icmp_ping(host):
    packet = IP(dst=str(host)) / ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response is not None and ICMP in response:
        print(f"Host {host} is reachable.")
        return True 
    else:
        print(f"Host {host} is unreachable.")
        return False

def arp_ping(host):
    arp_request = ARP(pdst=str(host))
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = broadcast / arp_request
    answered, unanswered = srp(packet, timeout=2, verbose=0)
    if answered:
        for snd, rcv in answered:
            print(f"Received ARP response from {rcv.psrc} ({rcv.hwsrc})")
        return True
    else:
        print(f"No ARP response from {host}.")
        return False

def pingHost(host, arp):
    if arp:
        return arp_ping(host)
    else:
        return icmp_ping(host)

def scan_subnet(subnet, arp, ports, syn_scan_mode, udp_scan_mode , OSdetection , tcp_flags ,timing_delay):
    network = ipaddress.ip_network(subnet, strict=False)
    for host in network.hosts():
        if not running:
            break
        print(f"Pinging {host}...")
        if pingHost(host, arp):
            print(f"Host {host} is active.")
            scan_host(host, ports, syn_scan_mode, OSdetection, udp_scan_mode , tcp_flags , timing_delay)

signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description="Simple subnet scanner.")
parser.add_argument('-nP', action='store_true', help="Use ARP instead of ICMP")
parser.add_argument('-p', type=str, help='Port or range of ports to scan')
parser.add_argument('-sS', action='store_true', help="Use SYN scan for TCP ports")
parser.add_argument('-O', action='store_true', help='Scan to detect OS')
parser.add_argument('-sU', action='store_true', help="Scan UDP ports")
parser.add_argument('--flags' ,type=str , help="Set custom TCP flags (e.g., 'S', 'A', 'P', 'U', 'R', 'F')")
parser.add_argument('--timing', type=float, default=0.5, help="Delay between packets in seconds (default: 0.5)")
parser.add_argument('target', help="Subnet in CIDR notation, e.g., 10.10.50.0/24 or IP address")

args = parser.parse_args()
timing_delay = args.timing
ports = parse_ports(args.p) if args.p else [20 ,21, 22, 25 , 53, 80, 110,139,143, 389,443, 445 ]

if args.sU and args.sS:
    print("You cannot use TCP SYN scan with UDP scanning at the same time.")
    exit(0)


try:
    if is_valid_host(args.target):
        print(f"Scanning host: {args.target}")
        if pingHost(args.target, args.nP):
            scan_host(str(args.target), ports, args.sS, args.O, args.sU , args.flags , args.timing)
        else:
            print("Host unreachable.")
    elif is_valid_host(resolve_ip(args.target)):
        print(f"Scanning host: {args.target}")
        if pingHost(args.target, args.nP):
            scan_host(str(resolve_ip(args.target)), ports, args.sS, args.O, args.sU , args.flags , args.timing)
        else:
            print("Host unreachable.")
    elif is_valid_subnet(args.target):
        print(f"Scanning subnet: {args.target}")
        scan_subnet(args.target, args.nP, ports, args.sS, args.sU , args.O , args.flags , args.timing)
    else:
        print("Invalid target. Please provide a valid IP address or subnet in CIDR notation.")
except KeyboardInterrupt:
    signal_handler(None, None)
finally:
    print("Exiting...")
