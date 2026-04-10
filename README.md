<div align="center">
  
# Windscribe-IPs

An automatically updated list of IP addresses associated with the widely used free and privacy-focused VPN provider, Windscribe.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/Windscribe-IPs/main.yml?label=Build&style=for-the-badge)

### IPInfo Category

[IPBlocklist](https://github.com/tn3w/IPBlocklist) | [IP2X](https://github.com/tn3w/IP2X) | [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) | [TunnelBear-IPs](https://github.com/tn3w/TunnelBear-IPs) | [Windscribe-IPs](https://github.com/tn3w/Windscribe-IPs)

</div>

## Table of Contents

- [Data Files](#data-files)
- [How It Works](#how-it-works)
- [Usage Examples](#usage-examples)
- [License](#license)

## Data Files

| File                         | Raw Link                                                                                                  | Purpose                                                        |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `windscribe_serverlist.json` | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_serverlist.json) | Combined Windscribe server list from both mob-v2 API endpoints |
| `windscribe_ips.json`        | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_ips.json)        | Unique server IP addresses (JSON array)                        |
| `windscribe_ips.txt`         | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_ips.txt)         | Unique server IP addresses (plain text, one per line)          |
| `windscribe_entry_ips.json`  | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_entry_ips.json)  | Unique entry IP addresses (JSON array)                         |
| `windscribe_entry_ips.txt`   | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_entry_ips.txt)   | Unique entry IP addresses (plain text, one per line)           |
| `windscribe_subdomains.json` | [Raw](https://raw.githubusercontent.com/tn3w/Windscribe-IPs/refs/heads/master/windscribe_subdomains.json) | Unique Windscribe hostnames/subdomains                         |

## How It Works

No API keys or authentication are required. Data is fetched from Windscribe's public server list API:

- `https://assets.windscribe.com/serverlist/mob-v2/0/{timestamp}`
- `https://assets.windscribe.com/serverlist/mob-v2/1/{timestamp}`

Both responses are combined into `windscribe_serverlist.json` (deduplicated by location ID).

**`main.py`** extracts all `ip`, `ip2`–`ip5`, and `ping_ip` fields from every node and group entry in the serverlist using direct JSON traversal.

**`entry_ips.py`** extracts entry IPs by:

1. Pulling all hostnames from `nodes[].hostname`, `groups[].wg_endpoint`, `groups[].ovpn_x509`, and `locations[].dns_hostname`
2. DNS-resolving each hostname for IPv4 and IPv6 addresses
3. Combining resolved IPs with node IPs directly listed in the serverlist

## Usage Examples

### Check Server IP

```python
import json

def is_windscribe_ip(ip_to_check):
    with open('windscribe_ips.json', 'r') as f:
        windscribe_ips = set(json.load(f))
    return ip_to_check in windscribe_ips

if is_windscribe_ip("198.54.128.195"):
    print("Windscribe server IP detected")
```

### Check Entry IP

```python
import json

def is_windscribe_entry_ip(ip_to_check):
    with open('windscribe_entry_ips.json', 'r') as f:
        entry_ips = set(json.load(f))
    return ip_to_check in entry_ips

if is_windscribe_entry_ip("198.54.128.195"):
    print("Windscribe entry IP detected")
```

### Bulk IP Check

```python
import json
from typing import List, Dict

def check_multiple_ips(ips_to_check: List[str]) -> Dict[str, Dict[str, bool]]:
    try:
        with open('windscribe_ips.json', 'r') as f:
            server_ips = set(json.load(f))
        with open('windscribe_entry_ips.json', 'r') as f:
            entry_ips = set(json.load(f))

        results = {}
        for ip in ips_to_check:
            results[ip] = {
                'is_server_ip': ip in server_ips,
                'is_entry_ip': ip in entry_ips
            }
        return results
    except Exception as e:
        return {'error': str(e)}

ips = ["198.54.128.195", "74.80.181.146", "192.168.1.1"]
results = check_multiple_ips(ips)
for ip, status in results.items():
    print(f"{ip}: Server={status.get('is_server_ip', False)}, Entry={status.get('is_entry_ip', False)}")
```

## License

[Apache-2.0](LICENSE)
