#!/usr/bin/env python3
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List


TXT_HEADER = """#
# windscribe_entry_ips.txt
# https://github.com/tn3w/Windscribe-IPs/blob/master/windscribe_entry_ips.txt
#
# An automatically updated list of Entry IPs associated with the
# widely used free and privacy-focused VPN provider, Windscribe.
#
# This list could be used to block access to Windscribe's services.
#
"""


def extract_subdomains(data: dict) -> List[str]:
    """
    Extract all unique hostnames/subdomains from the serverlist.

    Sources:
      - data[].dns_hostname
      - data[].groups[].wg_endpoint
      - data[].groups[].ovpn_x509
      - data[].groups[].nodes[].hostname
    """
    subdomains: set = set()

    for location in data.get("data", []):
        dns_hostname = location.get("dns_hostname")
        if dns_hostname:
            subdomains.add(dns_hostname.strip().lower())

        for group in location.get("groups", []):
            for field in ("wg_endpoint", "ovpn_x509"):
                val = group.get(field)
                if val:
                    subdomains.add(val.strip().lower())

            for node in group.get("nodes", []):
                hostname = node.get("hostname")
                if hostname:
                    subdomains.add(hostname.strip().lower())

    return list(subdomains)


def extract_node_ips(data: dict) -> List[str]:
    """
    Extract all IPs directly listed in nodes and groups (ping_ip, ip–ip5).
    These are used as known entry IPs alongside DNS-resolved ones.
    """
    ip_fields = {"ip", "ip2", "ip3", "ip4", "ip5"}
    ips: set = set()

    for location in data.get("data", []):
        for group in location.get("groups", []):
            ping_ip = group.get("ping_ip")
            if ping_ip:
                ips.add(ping_ip)

            for node in group.get("nodes", []):
                for field in ip_fields:
                    val = node.get(field)
                    if val:
                        ips.add(val)

    return list(ips)


def get_ips_for_hostname(hostname: str) -> List[str]:
    """Get both IPv4 and IPv6 addresses for a hostname."""
    ips = set()

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except (socket.gaierror, socket.herror) as e:
        print(f"IPv4 lookup failed for {hostname}: {e}")

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
            ips.add(info[4][0])
    except (socket.gaierror, socket.herror) as e:
        print(f"IPv6 lookup failed for {hostname}: {e}")

    return list(ips)


def batch_get_ips_for_hostnames(hostnames: List[str], workers: int = 10) -> List[str]:
    """Get IP addresses for multiple hostnames in parallel."""
    ip_addresses: set = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(get_ips_for_hostname, hostname): hostname
            for hostname in hostnames
        }

        for i, future in enumerate(as_completed(futures)):
            hostname = futures[future]
            try:
                ips = future.result()
                if ips:
                    print(f"Found {len(ips)} IPs for {hostname}")
                    ip_addresses.update(ips)
            except Exception as e:
                print(f"Error processing {hostname}: {e}")

            if (i + 1) % 10 == 0:
                print(f"Progress: {i + 1}/{len(hostnames)} hostnames processed")

    return list(ip_addresses)


def main():
    """Extract entry IPs and subdomains from windscribe_serverlist.json."""
    print("Starting Entry IP discovery...")

    with open("windscribe_serverlist.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    subdomains = extract_subdomains(data)
    print(f"Extracted {len(subdomains)} unique hostnames/subdomains from serverlist")

    with open("windscribe_subdomains.json", "w", encoding="utf-8") as f:
        json.dump(subdomains, f, indent=2)

    # IPs directly listed in the serverlist nodes
    node_ips = set(extract_node_ips(data))
    print(f"Extracted {len(node_ips)} IPs directly from serverlist nodes")

    # IPs resolved from hostnames
    print(f"Resolving {len(subdomains)} hostnames...")
    resolved_ips = set(batch_get_ips_for_hostnames(subdomains))
    print(f"Resolved {len(resolved_ips)} IPs from hostnames")

    entry_ips = list(node_ips | resolved_ips)

    with open("windscribe_entry_ips.json", "w", encoding="utf-8") as f:
        json.dump(entry_ips, f, indent=2)

    with open("windscribe_entry_ips.txt", "w", encoding="utf-8") as f:
        f.write(TXT_HEADER)
        f.write("\n".join(entry_ips))

    ipv4_count = sum(1 for ip in entry_ips if ":" not in ip)
    ipv6_count = sum(1 for ip in entry_ips if ":" in ip)
    total = len(entry_ips)

    print("\nSummary:")
    print(f"Total subdomains discovered: {len(subdomains)}")
    print(f"Total unique Entry IPs found: {total}")

    if total:
        print("\nIP Address Distribution:")
        ipv4_bar = "█" * int(30 * ipv4_count / total)
        ipv6_bar = "█" * int(30 * ipv6_count / total)
        print(f"IPv4 ({ipv4_count}): {ipv4_bar} {ipv4_count/total:.1%}")
        print(f"IPv6 ({ipv6_count}): {ipv6_bar} {ipv6_count/total:.1%}")


if __name__ == "__main__":
    main()
