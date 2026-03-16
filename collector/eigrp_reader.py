from pysnmp.hlapi import (
    nextCmd, SnmpEngine, UsmUserData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    usmDESPrivProtocol
)

# ============================================================
# SNMP HELPER FUNCTIONS
# ============================================================

def get_snmp_credentials(ip, use_aes=True):
    priv_protocol = usmAesCfb128Protocol if use_aes else usmDESPrivProtocol
    return UsmUserData(
        'snmpuser',
        authKey='AuthPass123',
        privKey='PrivPass123',
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=priv_protocol
    )

def snmp_walk(ip, oid, use_aes=True):
    """
    Walks SNMP table, returns list of (oid_string, raw_value) tuples.
    """
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        get_snmp_credentials(ip, use_aes),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            results.append((str(varBind[0]), varBind[1]))
    return results

# ============================================================
# CONVERSION HELPERS
# ============================================================

def bytes_to_ip(raw):
    """
    Converts raw SNMP bytes to dotted decimal IP.
    """
    try:
        octets = raw.asOctets()
        return '.'.join(str(b) for b in octets)
    except:
        return str(raw)

# ============================================================
# MODULE 3 — EIGRP NEIGHBOUR READER
# ============================================================

DEVICES = {
    '1.1.1.1':     {'name': 'R1',   'use_aes': True},
    '2.2.2.2':     {'name': 'R2',   'use_aes': True},
    '3.3.3.3':     {'name': 'R3',   'use_aes': True},
    '4.4.4.4':     {'name': 'R4',   'use_aes': False},
    '5.5.5.5':     {'name': 'R5',   'use_aes': False},
    '6.6.6.6':     {'name': 'R6',   'use_aes': False},
    '7.7.7.7':     {'name': 'R7',   'use_aes': False},
    '8.8.8.8':     {'name': 'SWL1', 'use_aes': False},
    '9.9.9.9':     {'name': 'SWL2', 'use_aes': False},
    '10.10.10.10': {'name': 'SWL3', 'use_aes': False},
    '11.11.11.11': {'name': 'SWL4', 'use_aes': False},
}

# IP address to device name lookup
# Built from our known addressing plan
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


def get_interface_map(ip, use_aes=True):
    """
    Builds {index: name} map for resolving interface indexes.
    """
    indexes = snmp_walk(ip, '1.3.6.1.2.1.2.2.1.1', use_aes)
    names   = snmp_walk(ip, '1.3.6.1.2.1.2.2.1.2', use_aes)

    interface_map = {}
    for (_, idx_val), (_, name_val) in zip(indexes, names):
        interface_map[str(idx_val)] = str(name_val)
    return interface_map


def read_eigrp_neighbours(ip, device_name, use_aes=True):
    """
    Reads EIGRP neighbour table from a device.
    Returns list of active EIGRP neighbour relationships.
    """
    print(f"\n📡 Reading EIGRP neighbours from {device_name} ({ip})...")

    # Get interface map for resolving index → name
    interface_map = get_interface_map(ip, use_aes)

    # Walk EIGRP neighbour IP addresses
    peer_addrs   = snmp_walk(
        ip, '1.3.6.1.4.1.9.9.449.1.4.1.1.3', use_aes
    )

    # Walk EIGRP neighbour interface indexes
    peer_ifaces  = snmp_walk(
        ip, '1.3.6.1.4.1.9.9.449.1.4.1.1.4', use_aes
    )

    # Walk EIGRP hold times
    hold_times   = snmp_walk(
        ip, '1.3.6.1.4.1.9.9.449.1.4.1.1.8', use_aes
    )

    # Walk EIGRP uptime
    uptimes      = snmp_walk(
        ip, '1.3.6.1.4.1.9.9.449.1.4.1.1.9', use_aes
    )

    neighbours = []

    for i in range(len(peer_addrs)):
        try:
            # Parse neighbour IP
            neighbour_ip = bytes_to_ip(peer_addrs[i][1])

            # Resolve interface name
            if_index = str(peer_ifaces[i][1]) if i < len(peer_ifaces) else None
            if_name  = interface_map.get(if_index, f'ifIndex-{if_index}')

            # Get hold time
            hold_time = str(hold_times[i][1]) if i < len(hold_times) else 'N/A'

            # Get uptime
            uptime = str(uptimes[i][1]) if i < len(uptimes) else 'N/A'

            # Resolve neighbour device name
            neighbour_name = IP_TO_DEVICE.get(neighbour_ip, neighbour_ip)

            neighbours.append({
                'neighbour_ip':   neighbour_ip,
                'neighbour_name': neighbour_name,
                'interface':      if_name,
                'hold_time':      hold_time,
                'uptime':         uptime
            })

        except Exception as e:
            continue

    return {
        'device':            device_name,
        'device_ip':         ip,
        'eigrp_neighbours':  neighbours
    }


def collect_all_eigrp_neighbours():
    """
    Reads EIGRP neighbours from all devices.
    Builds a complete picture of routing topology.
    """
    print("=" * 55)
    print("MODULE 3 — EIGRP NEIGHBOUR READER")
    print("=" * 55)

    all_eigrp_data = []
    # Track unique connections to avoid duplicates
    connections = set()

    for ip, info in DEVICES.items():
        result = read_eigrp_neighbours(ip, info['name'], info['use_aes'])
        all_eigrp_data.append(result)

        if result['eigrp_neighbours']:
            print(f"\n✅ {info['name']} has "
                  f"{len(result['eigrp_neighbours'])} EIGRP neighbours:")
            for n in result['eigrp_neighbours']:
                print(f"   ↔ {n['neighbour_name']:6} "
                      f"({n['neighbour_ip']:15}) "
                      f"via {n['interface']:25} "
                      f"uptime: {n['uptime']}  "
                      f"hold: {n['hold_time']}s")

                # Record unique connection
                link = tuple(sorted([info['name'], n['neighbour_name']]))
                connections.add(link)
        else:
            print(f"\n⚠️  {info['name']} — No EIGRP neighbours found")

    # Print topology summary
    print("\n" + "=" * 55)
    print("TOPOLOGY LINKS DISCOVERED VIA EIGRP:")
    print("=" * 55)
    for link in sorted(connections):
        print(f"   {link[0]} ↔ {link[1]}")
    print(f"\n✅ Total unique links: {len(connections)}")
    print("=" * 55)

    return all_eigrp_data


if __name__ == "__main__":
    eigrp_data = collect_all_eigrp_neighbours()


## What Each Section Does

#- **`IP_TO_DEVICE`** — lookup table that maps IPs to device names so output says `R2` instead of `10.0.1.2`
#- **`read_eigrp_neighbours`** — walks 4 EIGRP MIB tables and combines them
#- **`connections set`** — tracks unique links and deduplicates them so `R1↔R2` doesn't appear twice
#- **Topology summary** — prints every confirmed link at the end
