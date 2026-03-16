from pysnmp.hlapi import (
    getCmd, SnmpEngine, UsmUserData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    usmDESPrivProtocol
)

def snmp_get(ip, oid, use_aes=True):
    if use_aes:
        priv_protocol = usmAesCfb128Protocol
    else:
        priv_protocol = usmDESPrivProtocol

    iterator = getCmd(
        SnmpEngine(),
        UsmUserData(
            'snmpuser',
            authKey='AuthPass123',
            privKey='PrivPass123',
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=priv_protocol
        ),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(f"❌ {ip} - Error: {errorIndication}")
    elif errorStatus:
        print(f"❌ {ip} - Error: {errorStatus}")
    else:
        for varBind in varBinds:
            print(f"✅ {ip} - {varBind[1]}")

# c7200 devices — SHA + AES
c7200_devices = {
    '1.1.1.1': 'R1',
    '2.2.2.2': 'R2',
    '3.3.3.3': 'R3',
}

# c3745 devices — SHA + DES
c3745_devices = {
    '4.4.4.4': 'R4',
    '5.5.5.5': 'R5',
    '6.6.6.6': 'R6',
    '7.7.7.7': 'R7',
    '8.8.8.8': 'SWL1',
    '9.9.9.9': 'SWL2',
    '10.10.10.10': 'SWL3',
    '11.11.11.11': 'SWL4'
}

print("=== SNMPv3 Network Discovery Test ===")
for ip, name in c7200_devices.items():
    snmp_get(ip, '1.3.6.1.2.1.1.5.0', use_aes=True)

for ip, name in c3745_devices.items():
    snmp_get(ip, '1.3.6.1.2.1.1.5.0', use_aes=False)