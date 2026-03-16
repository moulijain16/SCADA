import time
import json
from datetime import datetime
from device_info import collect_all_devices
from arp_reader import collect_all_arp_tables
from eigrp_reader import collect_all_eigrp_neighbours

# ============================================================
# MODULE 4 — CHANGE DETECTOR
# ============================================================

# How often to scan in seconds
SCAN_INTERVAL = 30

def take_snapshot():
    """
    Runs all three modules and combines results into
    a single snapshot of the entire network state.
    This is the complete picture of the network at one moment.
    """
    print("\n📸 Taking network snapshot...")

    snapshot = {
        'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'devices':    {},
        'links':      set(),
        'arp_entries': {},
        'alerts':     []
    }

    # ── Collect device info (Module 1) ──
    try:
        device_data = collect_all_devices()
        for device in device_data:
            snapshot['devices'][device['ip']] = {
                'hostname':   device['hostname'],
                'interfaces': [
                    i['name'] for i in device['interfaces']
                    if i['status'] == 'up'
                ]
            }
    except Exception as e:
        print(f"⚠️  Device info collection error: {e}")

    # ── Collect ARP tables (Module 2) ──
    try:
        arp_data = collect_all_arp_tables()
        for device_arp in arp_data:
            device_ip = device_arp['device_ip']
            snapshot['arp_entries'][device_ip] = [
                entry['neighbour_ip']
                for entry in device_arp['arp_table']
            ]
    except Exception as e:
        print(f"⚠️  ARP collection error: {e}")

    # ── Collect EIGRP neighbours (Module 3) ──
    try:
        eigrp_data = collect_all_eigrp_neighbours()
        for device_eigrp in eigrp_data:
            for neighbour in device_eigrp['eigrp_neighbours']:
                link = tuple(sorted([
                    device_eigrp['device'],
                    neighbour['neighbour_name']
                ]))
                snapshot['links'].add(link)
    except Exception as e:
        print(f"⚠️  EIGRP collection error: {e}")

    # Convert set to list for JSON serialisation
    snapshot['links'] = list(snapshot['links'])

    return snapshot


def compare_snapshots(previous, current):
    """
    Compares two snapshots and returns a list of alerts.
    Checks for: new devices, missing devices,
    new links, lost links, new ARP entries.
    """
    alerts = []

    prev_devices = set(previous['devices'].keys())
    curr_devices = set(current['devices'].keys())

    # ── Check for new devices ──
    new_devices = curr_devices - prev_devices
    for ip in new_devices:
        hostname = current['devices'][ip].get('hostname', 'Unknown')
        alerts.append({
            'severity': 'CRITICAL',
            'type':     'NEW_DEVICE',
            'message':  f"New device detected: {hostname} at {ip}",
            'ip':       ip
        })

    # ── Check for missing devices ──
    missing_devices = prev_devices - curr_devices
    for ip in missing_devices:
        hostname = previous['devices'][ip].get('hostname', 'Unknown')
        alerts.append({
            'severity': 'CRITICAL',
            'type':     'DEVICE_MISSING',
            'message':  f"Device no longer responding: {hostname} at {ip}",
            'ip':       ip
        })

    # ── Check for new EIGRP links ──
    prev_links = set(tuple(l) for l in previous['links'])
    curr_links = set(tuple(l) for l in current['links'])

    new_links = curr_links - prev_links
    for link in new_links:
        alerts.append({
            'severity': 'WARNING',
            'type':     'NEW_LINK',
            'message':  f"New EIGRP link appeared: {link[0]} ↔ {link[1]}",
            'link':     list(link)
        })

    # ── Check for lost EIGRP links ──
    lost_links = prev_links - curr_links
    for link in lost_links:
        alerts.append({
            'severity': 'CRITICAL',
            'type':     'LINK_DOWN',
            'message':  f"EIGRP link lost: {link[0]} ↔ {link[1]}",
            'link':     list(link)
        })

    # ── Check for new ARP entries ──
    for device_ip in curr_devices:
        curr_arp = set(current['arp_entries'].get(device_ip, []))
        prev_arp = set(previous['arp_entries'].get(device_ip, []))

        new_arp = curr_arp - prev_arp
        for neighbour_ip in new_arp:
            hostname = current['devices'][device_ip].get(
                'hostname', device_ip
            )
            alerts.append({
                'severity': 'WARNING',
                'type':     'NEW_ARP_ENTRY',
                'message':  f"New ARP entry on {hostname}: "
                           f"{neighbour_ip} appeared",
                'device':   device_ip,
                'new_ip':   neighbour_ip
            })

    return alerts


def save_snapshot(snapshot, filename='last_snapshot.json'):
    """
    Saves snapshot to a JSON file so it persists
    between runs — if the tool restarts, it loads
    the last known state instead of starting blind.
    """
    # Convert links list for JSON
    data = snapshot.copy()
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


def load_snapshot(filename='last_snapshot.json'):
    """
    Loads previous snapshot from file if it exists.
    Returns None if no previous snapshot found.
    """
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def print_alerts(alerts, scan_number):
    """
    Prints alerts in a clear, readable format.
    """
    if not alerts:
        print(f"✅ Scan #{scan_number} — No changes detected")
        return

    print(f"\n{'='*55}")
    print(f"🚨 Scan #{scan_number} — {len(alerts)} ALERT(S) DETECTED!")
    print(f"{'='*55}")
    for alert in alerts:
        icon = "🚨" if alert['severity'] == 'CRITICAL' else "⚠️ "
        print(f"{icon} [{alert['severity']}] {alert['type']}")
        print(f"   {alert['message']}")
    print(f"{'='*55}\n")


def run_change_detector():
    """
    Main loop — runs continuously, scanning every
    SCAN_INTERVAL seconds and detecting changes.
    """
    print("=" * 55)
    print("MODULE 4 — CHANGE DETECTOR")
    print(f"Scanning every {SCAN_INTERVAL} seconds")
    print("Press Ctrl+C to stop")
    print("=" * 55)

    scan_number = 0
    previous_snapshot = load_snapshot()

    if previous_snapshot:
        print(f"📂 Loaded previous snapshot from "
              f"{previous_snapshot['timestamp']}")
    else:
        print("📂 No previous snapshot found — "
              "establishing baseline on first scan")

    while True:
        scan_number += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n🔄 Scan #{scan_number} at {timestamp}")

        # Take current snapshot
        current_snapshot = take_snapshot()

        if previous_snapshot is None:
            # First run — establish baseline
            print(f"✅ Baseline established — "
                  f"{len(current_snapshot['devices'])} devices, "
                  f"{len(current_snapshot['links'])} links")
            save_snapshot(current_snapshot)
        else:
            # Compare with previous
            alerts = compare_snapshots(
                previous_snapshot, current_snapshot
            )
            print_alerts(alerts, scan_number)

            # Save alerts into snapshot
            current_snapshot['alerts'] = alerts
            save_snapshot(current_snapshot)

        # Current becomes previous for next scan
        previous_snapshot = current_snapshot

        # Wait before next scan
        print(f"⏳ Next scan in {SCAN_INTERVAL} seconds...")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_change_detector()


## What Each Section Does

#- **`take_snapshot()`** — runs all 3 modules and combines into one unified network state
#- **`compare_snapshots()`** — diffs two snapshots, generates typed alerts with severity levels
#- **`save_snapshot()`** — persists state to JSON so restarts don't lose history
#- **`load_snapshot()`** — loads previous state on startup
#- **`print_alerts()`** — clean formatted output with 🚨 for critical, ⚠️ for warnings
#- **`run_change_detector()`** — the main loop tying everything together
