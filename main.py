#!/usr/bin/env python3
import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List


TXT_HEADER = """#
# windscribe_ips.txt
# https://github.com/tn3w/Windscribe-IPs/blob/master/windscribe_ips.txt
#
# An automatically updated list of IP addresses associated with the
# widely used free and privacy-focused VPN provider, Windscribe.
#
# This list could be used to block malicious traffic from Windscribe's servers.
#
"""

SERVERLIST_URLS = [
    "https://assets.windscribe.com/serverlist/mob-v2/0/{ts}",
    "https://assets.windscribe.com/serverlist/mob-v2/1/{ts}",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
}


def fetch_serverlist(url: str) -> Dict[str, Any]:
    """Fetch Windscribe server list from the given URL."""
    print(f"Requesting {url} ...")
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(
                f"Unexpected status {response.status} from {url}"
            )
        return json.loads(response.read().decode("utf-8"))


def combine_serverlists(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine two serverlist responses by merging their 'data' arrays,
    deduplicating by location id.
    """
    seen_ids = set()
    combined: List[Any] = []

    for location in a.get("data", []):
        loc_id = location.get("id")
        if loc_id not in seen_ids:
            seen_ids.add(loc_id)
            combined.append(location)

    for location in b.get("data", []):
        loc_id = location.get("id")
        if loc_id not in seen_ids:
            seen_ids.add(loc_id)
            combined.append(location)

    result = a.copy()
    result["data"] = combined
    return result


def extract_ips(data: Dict[str, Any]) -> List[str]:
    """
    Extract all unique IPs from the serverlist.

    Collects ip, ip2–ip5, and ping_ip from every group and node entry
    using direct JSON traversal (no regex).
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


def main() -> None:
    ts = str(int(time.time()))
    urls = [url.format(ts=ts) for url in SERVERLIST_URLS]

    responses = []
    for url in urls:
        try:
            responses.append(fetch_serverlist(url))
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    if not responses:
        print("Error: could not fetch any serverlist data. Exiting.")
        return

    combined = responses[0]
    for extra in responses[1:]:
        combined = combine_serverlists(combined, extra)

    with open("windscribe_serverlist.json", "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    print(f"Saved windscribe_serverlist.json ({len(combined.get('data', []))} locations)")

    unique_ips = extract_ips(combined)

    with open("windscribe_ips.json", "w", encoding="utf-8") as f:
        json.dump(unique_ips, f, indent=2)

    with open("windscribe_ips.txt", "w", encoding="utf-8") as f:
        f.write(TXT_HEADER)
        f.write("\n".join(unique_ips))

    ipv4_count = sum(1 for ip in unique_ips if ":" not in ip)
    ipv6_count = sum(1 for ip in unique_ips if ":" in ip)
    total = len(unique_ips)

    print("\nSummary:")
    print(f"Total locations: {len(combined.get('data', []))}")
    print(f"Total unique IPs found: {total}")

    if total:
        print("\nIP Address Distribution:")
        ipv4_bar = "█" * int(30 * ipv4_count / total)
        ipv6_bar = "█" * int(30 * ipv6_count / total)
        print(f"IPv4 ({ipv4_count}): {ipv4_bar} {ipv4_count/total:.1%}")
        print(f"IPv6 ({ipv6_count}): {ipv6_bar} {ipv6_count/total:.1%}")


if __name__ == "__main__":
    main()
