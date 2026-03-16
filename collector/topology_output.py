import json
from datetime import datetime
from device_info import collect_all_devices
from arp_reader import collect_all_arp_tables
from eigrp_reader import collect_all_eigrp_neighbours

# ============================================================
# IP TO DEVICE NAME LOOKUP
# ============================================================

IP_TO_DEVICE = {
    '10.0.1.1': 'R1',  '10.0.1.2': 'R2',
    '10.0.2.1': 'R1',  '10.0.2.2': 'R3',
    '10.0.3.1': 'R2',  '10.0.3.2': 'R4',
    '10.0.4.1': 'R2',  '10.0.4.2': 'R5',
    '10.0.5.1': 'R3',  '10.0.5.2': 'R6',
    '10.0.6.1': 'R3',  '10.0.6.2': 'R7',
    '10.0.7.1': 'R4',  '10.0.7.2': 'SWL1',
    '10.0.8.1': 'R5',  '10.0.8.2': 'SWL2',
    '10.0.9.1': 'R6',  '10.0.9.2': 'SWL3',
    '10.0.10.1': 'R7', '10.0.10.2': 'SWL4',
    '1.1.1.1': 'R1',   '2.2.2.2': 'R2',
    '3.3.3.3': 'R3',   '4.4.4.4': 'R4',
    '5.5.5.5': 'R5',   '6.6.6.6': 'R6',
    '7.7.7.7': 'R7',   '8.8.8.8': 'SWL1',
    '9.9.9.9': 'SWL2', '10.10.10.10': 'SWL3',
    '11.11.11.11': 'SWL4'
}

# Device layer classification
# Tells Member 2 which tier each device belongs to
# so the graph can be drawn in the correct hierarchy
DEVICE_LAYERS = {
    'R1':   'core',
    'R2':   'distribution',
    'R3':   'distribution',
    'R4':   'dist-access',
    'R5':   'dist-access',
    'R6':   'dist-access',
    'R7':   'dist-access',
    'SWL1': 'access',
    'SWL2': 'access',
    'SWL3': 'access',
    'SWL4': 'access',
}


# ============================================================
# TOPOLOGY OUTPUT BUILDER
# ============================================================

def build_topology_json(alerts=None):
    """
    Runs all three collection modules and combines
    their output into a single clean JSON structure
    that Member 2 and Member 3 can directly consume.
    """
    print("=" * 55)
    print("BUILDING TOPOLOGY JSON OUTPUT")
    print("=" * 55)

    topology = {
        "timestamp":   datetime.now().isoformat(),
        "devices":     [],
        "connections": [],
        "alerts":      alerts or []
    }

    # ── STEP 1: Collect device info ──
    print("\n[1/3] Collecting device info...")
    device_data = collect_all_devices()

    # Build devices list
    for device in device_data:
        # Clean hostname — remove .localdomain suffix if present
        hostname = device['hostname']
        if hostname and '.' in hostname:
            hostname = hostname.split('.')[0]

        device_entry = {
            "id":          hostname,
            "loopback_ip": device['ip'],
            "hostname":    hostname,
            "description": device['description'],
            "layer":       DEVICE_LAYERS.get(hostname, 'unknown'),
            "interfaces":  [
                i['name'] for i in device['interfaces']
                if i['status'] == 'up'
            ]
        }
        topology['devices'].append(device_entry)

    print(f"   ✅ {len(topology['devices'])} devices collected")

    # ── STEP 2: Collect EIGRP neighbours for connections ──
    print("\n[2/3] Collecting EIGRP topology...")
    eigrp_data = collect_all_eigrp_neighbours()

    # Build connections list — deduplicated
    seen_links = set()
    for device_eigrp in eigrp_data:
        source = device_eigrp['device']
        for neighbour in device_eigrp['eigrp_neighbours']:
            target = neighbour['neighbour_name']

            # Skip if we've already recorded this link
            link_key = tuple(sorted([source, target]))
            if link_key in seen_links:
                continue
            seen_links.add(link_key)

            connection = {
                "from":      source,
                "to":        target,
                "interface": neighbour['interface'],
                "protocol":  "EIGRP"
            }
            topology['connections'].append(connection)

    print(f"   ✅ {len(topology['connections'])} connections collected")

    # ── STEP 3: Enrich with ARP data ──
    print("\n[3/3] Enriching with ARP data...")
    arp_data = collect_all_arp_tables()

    # Add MAC addresses to connections using ARP data
    # This helps Member 2 verify connections at layer 2
    arp_lookup = {}
    for device_arp in arp_data:
        for entry in device_arp['arp_table']:
            arp_lookup[entry['neighbour_ip']] = entry['mac']

    # Enrich each connection with MAC info
    for connection in topology['connections']:
        source_device = connection['from']
        target_device = connection['to']

        # Find the link IP for this connection
        for ip, device in IP_TO_DEVICE.items():
            if device == target_device:
                mac = arp_lookup.get(ip)
                if mac:
                    connection['target_mac'] = mac
                    break

    print(f"   ✅ ARP enrichment complete")

    return topology


def save_topology_json(topology, filename='topology.json'):
    """
    Saves the topology to a JSON file.
    This is the file Member 2 reads from.
    """
    import os
    # Always save in the same folder as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(topology, f, indent=2)
    print(f"\n💾 Topology saved to {filepath}")


def print_topology_summary(topology):
    """
    Prints a clean human readable summary
    of the discovered topology.
    """
    print("\n" + "=" * 55)
    print("TOPOLOGY SUMMARY")
    print("=" * 55)

    print(f"\n📅 Timestamp: {topology['timestamp']}")

    print(f"\n🖥️  DEVICES ({len(topology['devices'])}):")
    for device in topology['devices']:
        print(f"   {device['id']:8} | "
              f"IP: {device['loopback_ip']:12} | "
              f"Layer: {device['layer']:15} | "
              f"Active interfaces: "
              f"{len(device['interfaces'])}")

    print(f"\n🔗 CONNECTIONS ({len(topology['connections'])}):")
    for conn in topology['connections']:
        mac_info = f"  MAC: {conn.get('target_mac', 'N/A')}"
        print(f"   {conn['from']:6} ↔ {conn['to']:6} "
              f"via {conn['interface']:25} {mac_info}")

    if topology['alerts']:
        print(f"\n🚨 ALERTS ({len(topology['alerts'])}):")
        for alert in topology['alerts']:
            print(f"   [{alert['severity']}] {alert['message']}")
    else:
        print(f"\n✅ No alerts")

    print("=" * 55)


if __name__ == "__main__":
    # Build complete topology
    topology = build_topology_json()

    # Print summary
    print_topology_summary(topology)

    # Save to JSON file for Member 2
    save_topology_json(topology)

    print("\n✅ topology.json is ready")


## What Each Section Does

#- **`DEVICE_LAYERS`** — tells Member 2 which tier each device is in so D3.js can draw the hierarchy correctly
#- **`build_topology_json()`** — runs all 3 modules and combines into clean JSON
#- **Hostname cleaning** — removes `.localdomain` from R1's hostname so it's just `R1`
#- **Deduplication** — ensures each link appears only once using `seen_links` set
#- **ARP enrichment** — adds MAC addresses to connections for layer 2 verification
#- **`save_topology_json()`** — writes `topology.json` that Member 2 reads
#- **`print_topology_summary()`** — clean human readable output
