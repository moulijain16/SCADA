from pysnmp.hlapi import (
    getCmd, nextCmd, SnmpEngine, UsmUserData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    usmDESPrivProtocol
)

# ============================================================
# SNMP HELPER FUNCTIONS
# ============================================================

def get_snmp_engine(ip, use_aes=True):
    """
    Creates the authentication credentials for a device.
    c7200 uses AES, c3745 uses DES.
    """
    priv_protocol = usmAesCfb128Protocol if use_aes else usmDESPrivProtocol
    return UsmUserData(
        'snmpuser',
        authKey='AuthPass123',
        privKey='PrivPass123',
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=priv_protocol
    )

def snmp_get_single(ip, oid, use_aes=True):
    """
    Fetches a single SNMP value from a device.
    Used for simple values like hostname and description.
    """
    iterator = getCmd(
        SnmpEngine(),
        get_snmp_engine(ip, use_aes),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication or errorStatus:
        return None
    return str(varBinds[0][1])

def snmp_walk_table(ip, oid, use_aes=True):
    """
    Walks an SNMP table and returns all values.
    Used for tables like interfaces where there are multiple rows.
    """
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        get_snmp_engine(ip, use_aes),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False  # stops walking when table ends
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            results.append(str(varBind[1]))
    return results

# ============================================================
# MODULE 1 — DEVICE INFO COLLECTOR
# ============================================================

# Device list with their encryption type
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

def collect_device_info(ip, use_aes=True):
    """
    Collects complete profile of a single device:
    - Hostname
    - Description (IOS version)
    - All interfaces and their status
    """
    print(f"\n📡 Querying {ip}...")

    # Get hostname
    hostname = snmp_get_single(ip, '1.3.6.1.2.1.1.5.0', use_aes)

    # Get description
    description = snmp_get_single(ip, '1.3.6.1.2.1.1.1.0', use_aes)

    # Get interface names (table walk)
    if_names = snmp_walk_table(ip, '1.3.6.1.2.1.2.2.1.2', use_aes)

    # Get interface statuses (table walk)
    # 1 = up, 2 = down, 3 = testing
    if_statuses_raw = snmp_walk_table(ip, '1.3.6.1.2.1.2.2.1.8', use_aes)

    # Convert status numbers to readable text
    status_map = {'1': 'up', '2': 'down', '3': 'testing'}
    if_statuses = [status_map.get(s, 'unknown') for s in if_statuses_raw]

    # Combine interface names and statuses together
    interfaces = []
    for name, status in zip(if_names, if_statuses):
        if status == 'up':  # only include active interfaces
             interfaces.append({
            'name': name,
            'status': status
        })

    # Build complete device profile
    device_profile = {
        'ip': ip,
        'hostname': hostname,
        'description': description[:50] if description else None,
        'interfaces': interfaces
    }

    return device_profile


def collect_all_devices():
    """
    Runs device info collection across entire network.
    Returns list of all device profiles.
    """
    print("=" * 50)
    print("MODULE 1 — DEVICE INFO COLLECTOR")
    print("=" * 50)

    all_devices = []

    for ip, info in DEVICES.items():
        profile = collect_device_info(ip, info['use_aes'])
        all_devices.append(profile)

        # Print summary
        print(f"✅ {profile['hostname']} ({ip})")
        print(f"   Description: {profile['description']}")
        print(f"   Interfaces: {len(profile['interfaces'])} found")
        for iface in profile['interfaces']:
            print(f"     - {iface['name']}: {iface['status']}")

    print("\n" + "=" * 50)
    print(f"✅ Total devices discovered: {len(all_devices)}")
    print("=" * 50)

    return all_devices


# Run it
if __name__ == "__main__":
    network_devices = collect_all_devices()


## What Each Section Does
#- **`get_snmp_engine`** — reusable credentials builder, so we don't repeat auth code everywhere
#- **`snmp_get_single`** — fetches one value, used for hostname and description
#- **`snmp_walk_table`** — walks entire tables, used for interfaces
#- **`collect_device_info`** — builds complete profile for one device
#- **`collect_all_devices`** — runs across all 11 devices and returns everything
