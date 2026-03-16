from pysnmp.hlapi import (
    nextCmd, SnmpEngine, UsmUserData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    usmDESPrivProtocol
)
from pysnmp.proto.rfc1902 import OctetString, Integer
import socket

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

def bytes_to_mac(raw):
    """
    Converts raw SNMP OctetString to MAC address.
    Example: raw bytes → 00:1a:2b:3c:4d:5e
    """
    try:
        hex_vals = [format(b, '02x') for b in raw.asOctets()]
        return ':'.join(hex_vals)
    except:
        return str(raw)

def bytes_to_ip(raw):
    """
    Converts raw SNMP OctetString to IP address.
    Example: raw bytes → 10.0.1.2
    """
    try:
        octets = raw.asOctets()
        return '.'.join(str(b) for b in octets)
    except:
        return str(raw)

# ============================================================
# MODULE 2 — ARP TABLE READER
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

def get_interface_map(ip, use_aes=True):
    """
    Builds {index: name} map.
    Example: {'1': 'FastEthernet0/0', '2': 'GigabitEthernet1/0'}
    """
    indexes = snmp_walk(ip, '1.3.6.1.2.1.2.2.1.1', use_aes)
    names   = snmp_walk(ip, '1.3.6.1.2.1.2.2.1.2', use_aes)

    interface_map = {}
    for (_, idx_val), (_, name_val) in zip(indexes, names):
        interface_map[str(idx_val)] = str(name_val)
    return interface_map


def read_arp_table(ip, device_name, use_aes=True):
    """
    Reads ARP table from a device.
    Correctly parses binary IP and MAC values.
    """
    print(f"\n📡 Reading ARP table from {device_name} ({ip})...")

    # Get interface map for resolving index → name
    interface_map = get_interface_map(ip, use_aes)

    # Walk all three ARP table columns
    arp_if_raw  = snmp_walk(ip, '1.3.6.1.2.1.4.22.1.1', use_aes)
    arp_mac_raw = snmp_walk(ip, '1.3.6.1.2.1.4.22.1.2', use_aes)
    arp_ip_raw  = snmp_walk(ip, '1.3.6.1.2.1.4.22.1.3', use_aes)

    arp_entries = []

    for i in range(len(arp_ip_raw)):
        try:
            # Parse neighbour IP from binary
            neighbour_ip = bytes_to_ip(arp_ip_raw[i][1])

            # Parse MAC from binary
            mac = bytes_to_mac(arp_mac_raw[i][1])

            # Resolve interface name from index
            if_index = str(arp_if_raw[i][1])
            if_name = interface_map.get(if_index, f'ifIndex-{if_index}')

            arp_entries.append({
                'neighbour_ip': neighbour_ip,
                'mac':          mac,
                'interface':    if_name
            })
        except Exception as e:
            continue

    return {
        'device':     device_name,
        'device_ip':  ip,
        'arp_table':  arp_entries
    }


def collect_all_arp_tables():
    print("=" * 55)
    print("MODULE 2 — ARP TABLE READER")
    print("=" * 55)

    all_arp_data = []

    for ip, info in DEVICES.items():
        result = read_arp_table(ip, info['name'], info['use_aes'])
        all_arp_data.append(result)

        if result['arp_table']:
            print(f"✅ {info['name']} — {len(result['arp_table'])} ARP entries:")
            for entry in result['arp_table']:
                print(f"   {entry['neighbour_ip']:18} "
                      f"MAC: {entry['mac']:20} "
                      f"via {entry['interface']}")
        else:
            print(f"⚠️  {info['name']} — No ARP entries found")

    print("\n" + "=" * 55)
    print("ARP collection complete!")
    print("=" * 55)

    return all_arp_data


if __name__ == "__main__":
    arp_data = collect_all_arp_tables()