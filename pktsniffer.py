import argparse
import ipaddress
import sys
from typing import List, Tuple

try:
    from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    print("Error importing scapy. Make sure scapy is installed (pip install -r requirements.txt).")
    raise


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the pktsniffer program.

    Returns:
        argparse.Namespace: An object containing all parsed arguments
                            (e.g., args.read, args.count, args.filters).
    """
    # Create an ArgumentParser object with a description that will show up in `-h` help output
    parser = argparse.ArgumentParser(description="pktsniffer - simple pcap packet analyzer")
    # Add a required option -r / --read
    parser.add_argument("-r", "--read", required=True, help="Input pcap file")
    # Add an optional argument -c / --count
    parser.add_argument("-c", "--count", type=int, default=0, help="Limit number of packets analyzed (0 = all)")
    # Add a positional argument called 'filters'
    parser.add_argument("filters", nargs="*", help="Filter tokens, e.g. host 192.168.1.5 port 80 tcp")
    return parser.parse_args()


def build_filters(tokens: List[str]) -> List[Tuple[str, str]]:
    """
    Convert a list of filter tokens (strings) into a structured list of (filter_type, value) tuples.

    Supported filter formats:
      - "host <ip>"   → match packets from/to a specific host IP
      - "ip <ip>"     → match packets containing a specific IP
      - "port <num>"  → match packets using a given port number
      - "net <cidr>"  → match packets in a given network (e.g. 192.168.0.0/24)
      - "tcp"         → match only TCP packets
      - "udp"         → match only UDP packets
      - "icmp"        → match only ICMP packets
    Filters are parsed left-to-right. Tokens without value are assumed boolean filters (tcp/udp/icmp).
    """
    i = 0
    filters = []
    while i < len(tokens):
        tok = tokens[i].lower()
        # Filters that require a value (host/ip/port/net)
        if tok in ("host", "ip", "port", "net"):
            if i + 1 >= len(tokens):
                raise ValueError(f"Filter '{tok}' expects a value.")
            filters.append((tok, tokens[i + 1]))
            i += 2
        # Boolean filters that stand alone (tcp/udp/icmp)
        elif tok in ("tcp", "udp", "icmp"):
            filters.append((tok, ""))
            i += 1
        # Handle variants like "-net 10.0.0.0/8"
        else:
            # Allow net expressed as '-net' or 'net' interchangeably
            if tok.startswith("-") and tok[1:] in ("net",):
                # Consume next token
                if i + 1 >= len(tokens):
                    raise ValueError(f"Filter '{tok}' expects a value.")
                filters.append((tok[1:], tokens[i + 1]))
                i += 2
            #  Try to interpret bare values intelligently
            else:
                # If the token looks like an IP address → assume "host <ip>"
                if is_ip_literal(tok):
                    filters.append(("host", tok))
                    i += 1
                # If the token is all digits → assume "port <number>"
                elif tok.isdigit():
                    filters.append(("port", tok))
                    i += 1
                # Otherwise, it’s not recognized → raise an error
                else:
                    raise ValueError(f"Unknown filter token '{tok}'")
    return filters


def is_ip_literal(s: str) -> bool:
    """
    Check if the given string is a valid IP address (IPv4 or IPv6).

    Returns:
        True  → if the string is a valid IP address
        False → if the string is not a valid IP address
    """
    try:
        # Try to interpret the string as an IP address.
        ipaddress.ip_address(s)
        return True
    except Exception:
        # If an error occurs, the string is not a valid IP address.
        return False


def ip_in_network(ip_str: str, network_str: str) -> bool:
    """
        Check if a given IP address belongs to a given network.

        Args:
            ip_str (str): The IP address to test (e.g. "192.168.1.5").
            network_str (str): The network in CIDR form (e.g. "192.168.1.0/24").
                              If no "/mask" is given and it's IPv4, assume "/24".

        Returns:
            True  → if the IP is inside the network
            False → if the IP is not in the network or input is invalid
        """
    try:
        # If the network string doesn't specify a subnet mask (like "/24"),
        # but looks like an IPv4 address (contains '.'), assume "/24".
        if "/" not in network_str and "." in network_str:
            # Treat as /24 for IPv4 if not specified (matches common tcpdump -net example)
            net = ipaddress.ip_network(network_str + "/24", strict=False)
        else:
            # Otherwise, parse the network as given (CIDR required for IPv6)
            net = ipaddress.ip_network(network_str, strict=False)
        # Convert the IP string to an IP address object
        ip = ipaddress.ip_address(ip_str)
        # Return True if the IP belongs to the given network
        return ip in net
    except Exception:
        # If parsing fails, return False
        return False


def match_filters(pkt, filters: List[Tuple[str, str]]) -> bool:
    """
    Check if a packet matches all given filters.
    (All filters must pass → AND logic)

    Args:
        pkt: A Scapy packet object
        filters: A list of (filter_type, value) tuples

    Returns:
        True  → if the packet matches every filter
        False → if the packet fails any filter
    """
    for ftype, fval in filters:
        # Host/IP filter
        if ftype in ("host", "ip"):
            ip_match = False
            # IPv4
            if IP in pkt:
                if pkt[IP].src == fval or pkt[IP].dst == fval:
                    ip_match = True
            # IPv6
            elif IPv6 in pkt:
                if pkt[IPv6].src == fval or pkt[IPv6].dst == fval:
                    ip_match = True
            if not ip_match:
                return False
        # Port filter
        elif ftype == "port":
            # check TCP/UDP ports
            try:
                port_num = int(fval)
            except ValueError:
                return False
            p_ok = False
            # TCP port
            if TCP in pkt:
                if pkt[TCP].sport == port_num or pkt[TCP].dport == port_num:
                    p_ok = True
            # UDP port
            if UDP in pkt:
                if pkt[UDP].sport == port_num or pkt[UDP].dport == port_num:
                    p_ok = True
            if not p_ok:
                return False
        # Protocol filters (tcp/udp/icmp)
        elif ftype == "tcp":
            if TCP not in pkt:
                return False
        elif ftype == "udp":
            if UDP not in pkt:
                return False
        elif ftype == "icmp":
            if ICMP not in pkt:
                return False
        # Network filter
        elif ftype == "net":
            ip_ok = False
            # Check if IPv4 src/dst is in the given network
            if IP in pkt:
                if ip_in_network(pkt[IP].src, fval) or ip_in_network(pkt[IP].dst, fval):
                    ip_ok = True
            # Check if IPv6 src/dst is in the given network
            elif IPv6 in pkt:
                if ip_in_network(pkt[IPv6].src, fval) or ip_in_network(pkt[IPv6].dst, fval):
                    ip_ok = True
            if not ip_ok:
                return False
        else:
            # Unknown filter type: fail-safe
            return False
    return True


def flags_str(flags_field) -> str:
    """
    Convert a packet flags field into a string.

    Args:
        flags_field: The flags value from a packet (e.g., TCP flags)

    Returns:
        String representation of the flags if possible,
        otherwise an empty string "" if conversion fails.
    """
    try:
        # Try to stringify the field
        return str(flags_field)
    except Exception:
        return ""


def print_packet_summary(idx: int, pkt) -> None:
    """Print details for a single Scapy packet object."""
    print("=" * 80)
    print(f"Packet #{idx}")
    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        print("-- Ethernet header:")
        print(f"   Packet Size            : {len(pkt)}")
        print(f"   Destination MAC address: {eth.dst}")
        print(f"   Source MAC address     : {eth.src}")
        # eth.type might be available as .type or .etype depending on scapy version
        eth_type = getattr(eth, "type", None)
        print(f"   Ethertype              : {hex(eth_type) if eth_type is not None else 'unknown'}")

    # IPv4
    if IP in pkt:
        ip = pkt[IP]
        print("-- IPv4 header:")
        print(f"   Version                : {ip.version}")
        print(f"   Header length          : {ip.ihl} ({ip.ihl * 4} bytes)")
        print(f"   Type of Service        : {ip.tos}")
        print(f"   Total length           : {ip.len}")
        print(f"   Identification         : {ip.id}")
        print(f"   Flags                  : {flags_str(ip.flags)}")
        print(f"   Fragment offset        : {ip.frag}")
        print(f"   Time to Live           : {ip.ttl}")
        print(f"   Protocol               : {ip.proto}")
        print(f"   Header checksum        : {ip.chksum}")
        print(f"   Source IP address      : {ip.src}")
        print(f"   Destination IP address : {ip.dst}")
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        print("-- IPv6 header:")
        print(f"   Version                : {ip6.version}")
        print(f"   Traffic Class          : {getattr(ip6, 'tc', '')}")
        print(f"   Flow label             : {getattr(ip6, 'fl', '')}")
        print(f"   Payload length         : {ip6.plen}")
        print(f"   Next header            : {ip6.nh}")
        print(f"   Hop limit              : {ip6.hlim}")
        print(f"   Source IP              : {ip6.src}")
        print(f"   Destination IP         : {ip6.dst}")

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        print("-- TCP header:")
        print(f"   Source port            : {tcp.sport}")
        print(f"   Destination port       : {tcp.dport}")
        print(f"   Sequence Number        : {tcp.seq}")
        print(f"   Acknowledgement Number : {tcp.ack}")
        print(f"   Data offset            : {tcp.dataofs}")
        print(f"   Flags                  : {flags_str(tcp.flags)}")
        print(f"   Window                 : {tcp.window}")
        print(f"   Checksum               : {tcp.chksum}")
        print(f"   Urgent pointer         : {tcp.urgptr}")

    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        print("-- UDP header:")
        print(f"   Source port            : {udp.sport}")
        print(f"   Destination port       : {udp.dport}")
        print(f"   Length                 : {udp.len}")
        print(f"   Checksum               : {udp.chksum}")

    # ICMP
    if ICMP in pkt:
        icmp = pkt[ICMP]
        print("-- ICMP header:")
        print(f"   Type                   : {icmp.type}")
        print(f"   Code                   : {icmp.code}")
        print(f"   Checksum               : {icmp.chksum}")
        # additional fields may exist depending on type
    print("=" * 80)
    print()


def main():
    args = parse_args()
    try:
        filters = build_filters(args.filters)
    except ValueError as e:
        print(f"Filter parse error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        packets = rdpcap(args.read)
    except FileNotFoundError:
        print(f"PCAP file not found: {args.read}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(1)

    limit = args.count if args.count > 0 else len(packets)
    printed = 0
    total = 0
    for i, pkt in enumerate(packets, start=1):
        if total >= limit:
            break
        total += 1
        try:
            if filters and not match_filters(pkt, filters):
                continue
        except Exception:
            # on any failure to match, skip that packet (robustness)
            continue

        print_packet_summary(i, pkt)
        printed += 1
        if printed >= limit:
            break

    if printed == 0:
        print("No matching packets found (or file empty).")


if __name__ == "__main__":
    main()
