#!/usr/bin/env python3
"""
Snort Alert Analysis Script for Assignment A7
"""

import re
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime

def parse_alerts(filename):
    """Parse Snort alerts from file"""
    alerts = []
    
    with open(filename, 'r') as f:
        for line in f:
            # Match alert lines that contain [**]
            if '[**]' in line:
                # Extract components of the alert
                match = re.match(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[[\*]+\]\s+\[(\d+:\d+:\d+)\]\s+"([^"]+)"\s+\[[\*]+\]\s+\[Classification:\s*([^\]]+)\]\s+\[Priority:\s*(\d+)\]\s+\{([^}]+)\}\s+(.+)', line)
                
                if match:
                    timestamp = match.group(1)
                    sid = match.group(2)
                    message = match.group(3)
                    classification = match.group(4)
                    priority = int(match.group(5))
                    protocol = match.group(6)
                    flow = match.group(7)
                    
                    # Parse source and destination
                    flow_match = re.match(r'([^:]+):(\d+)\s*->\s*([^:]+):(\d+)', flow)
                    if flow_match:
                        src_ip = flow_match.group(1)
                        src_port = int(flow_match.group(2))
                        dst_ip = flow_match.group(3)
                        dst_port = int(flow_match.group(4))
                    else:
                        src_ip = src_port = dst_ip = dst_port = None
                    
                    alerts.append({
                        'timestamp': timestamp,
                        'sid': sid,
                        'message': message,
                        'classification': classification,
                        'priority': priority,
                        'protocol': protocol,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'raw': line.strip()
                    })
    
    return alerts

def analyze_alerts(alerts):
    """Analyze the parsed alerts"""
    print("=" * 60)
    print("SNORT ALERT ANALYSIS")
    print("=" * 60)
    
    # Total alerts
    total_alerts = len(alerts)
    print(f"Total alerts: {total_alerts}")
    
    if total_alerts == 0:
        print("No alerts found!")
        return
    
    # Count alerts by rule
    rule_counts = Counter(alert['message'] for alert in alerts)
    print(f"\nTop 5 alerts by number of hits:")
    for i, (rule, count) in enumerate(rule_counts.most_common(5), 1):
        print(f"{i}. {rule}: {count} hits")
    
    # Find Linksys HNAP attacks
    linksys_alerts = [alert for alert in alerts if 'linksys' in alert['message'].lower() or 'hnap' in alert['message'].lower()]
    print(f"\nLinksys E-series HNAP attacks: {len(linksys_alerts)}")
    
    if linksys_alerts:
        linksys_attackers = set()
        for alert in linksys_alerts:
            linksys_attackers.add(alert['src_ip'])
        print(f"Attacking IP addresses: {', '.join(linksys_attackers)}")
        
        # Show earliest attack
        earliest_linksys = min(linksys_alerts, key=lambda x: x['timestamp'])
        print(f"Earliest Linksys attack: {earliest_linksys['timestamp']}")
        print(f"  Source: {earliest_linksys['src_ip']}:{earliest_linksys['src_port']}")
        print(f"  Destination: {earliest_linksys['dst_ip']}:{earliest_linksys['dst_port']}")
    
    # Analyze Gh0st trojan
    ghost_alerts = [alert for alert in alerts if 'gh0st' in alert['message'].lower()]
    print(f"\nGh0st trojan alerts: {len(ghost_alerts)}")
    
    if ghost_alerts:
        ghost_ips = set()
        for alert in ghost_alerts:
            ghost_ips.add(alert['src_ip'])
        print(f"Gh0st trojan source IPs: {len(ghost_ips)} unique IPs")
        print(f"Sample IPs: {', '.join(list(ghost_ips)[:10])}")
    
    # Analyze shellcode alerts
    shellcode_alerts = [alert for alert in alerts if 'shellcode' in alert['message'].lower()]
    print(f"\nShellcode alerts: {len(shellcode_alerts)}")
    
    if shellcode_alerts:
        shellcode_rules = Counter(alert['message'] for alert in shellcode_alerts)
        print("Shellcode rules:")
        for rule, count in shellcode_rules.items():
            print(f"  {rule}: {count} hits")
    
    # Port analysis
    port_counts = Counter()
    for alert in alerts:
        if alert['dst_port']:
            port_counts[alert['dst_port']] += 1
    
    print(f"\nTop 10 targeted ports:")
    for port, count in port_counts.most_common(10):
        print(f"  Port {port}: {count} alerts")
    
    # Classification analysis
    class_counts = Counter(alert['classification'] for alert in alerts)
    print(f"\nAlert classifications:")
    for classification, count in class_counts.items():
        print(f"  {classification}: {count} alerts")
    
    return {
        'total_alerts': total_alerts,
        'rule_counts': rule_counts,
        'linksys_alerts': linksys_alerts,
        'ghost_alerts': ghost_alerts,
        'shellcode_alerts': shellcode_alerts,
        'port_counts': port_counts,
        'class_counts': class_counts
    }

def find_board_cgi_requests(alerts):
    """Look for board.cgi requests in the data"""
    board_cgi_alerts = []
    
    for alert in alerts:
        if 'board.cgi' in alert['message'].lower() or 'board.cgi' in alert['raw'].lower():
            board_cgi_alerts.append(alert)
    
    print(f"\nboard.cgi related alerts: {len(board_cgi_alerts)}")
    
    return board_cgi_alerts

def create_timeline_plot(alerts):
    """Create a timeline plot of alerts"""
    if not alerts:
        return
    
    # Group alerts by rule and timestamp
    timeline_data = defaultdict(list)
    
    for alert in alerts:
        # Convert timestamp to datetime
        try:
            # Parse timestamp format: 03/24-17:26:42.384523
            ts_str = alert['timestamp']
            # Add year (assuming 2024 based on PCAP files)
            dt = datetime.strptime(f"2024/{ts_str}", "%Y/%m/%d-%H:%M:%S.%f")
            timeline_data[alert['message']].append(dt)
        except ValueError:
            continue
    
    # Create plot for rules with <= 1500 alerts
    rules_to_plot = {rule: times for rule, times in timeline_data.items() if len(times) <= 1500}
    
    if not rules_to_plot:
        print("No rules with <= 1500 alerts found")
        return
    
    plt.figure(figsize=(15, 10))
    
    colors = plt.cm.tab10(range(len(rules_to_plot)))
    
    for i, (rule, times) in enumerate(rules_to_plot.items()):
        times.sort()
        y_values = [i] * len(times)
        plt.scatter(times, y_values, alpha=0.6, s=10, color=colors[i], label=rule[:50] + "..." if len(rule) > 50 else rule)
    
    plt.xlabel('Time')
    plt.ylabel('Rule')
    plt.title('Timeline of Snort Alerts (Rules with ≤ 1500 alerts)')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.grid(True, alpha=0.3)
    
    # Save plot
    plt.savefig('/home/za/Desktop/NetSec/A7/alert_timeline.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Timeline plot saved to alert_timeline.png")
    print(f"Plotted {len(rules_to_plot)} rules with {sum(len(times) for times in rules_to_plot.values())} total alerts")

def main():
    alerts_file = '/home/za/Desktop/NetSec/A7/alerts.txt'
    
    print("Parsing alerts...")
    alerts = parse_alerts(alerts_file)
    
    print("Analyzing alerts...")
    analysis = analyze_alerts(alerts)
    
    print("Looking for board.cgi requests...")
    board_cgi_alerts = find_board_cgi_requests(alerts)
    
    print("Creating timeline visualization...")
    create_timeline_plot(alerts)
    
    # Save detailed results
    with open('/home/za/Desktop/NetSec/A7/analysis_results.txt', 'w') as f:
        f.write("SNORT ALERT ANALYSIS RESULTS\n")
        f.write("=" * 40 + "\n\n")
        
        f.write(f"Total alerts: {analysis['total_alerts']}\n\n")
        
        f.write("Top 5 alerts by number of hits:\n")
        for i, (rule, count) in enumerate(analysis['rule_counts'].most_common(5), 1):
            f.write(f"{i}. {rule}: {count} hits\n")
        f.write("\n")
        
        f.write("All rules and hit counts:\n")
        for rule, count in analysis['rule_counts'].most_common():
            f.write(f"{rule}: {count} hits\n")
        f.write("\n")
        
        if analysis['linksys_alerts']:
            f.write("Linksys HNAP attacks:\n")
            linksys_attackers = set(alert['src_ip'] for alert in analysis['linksys_alerts'])
            for ip in linksys_attackers:
                f.write(f"  Attacker IP: {ip}\n")
            f.write("\n")
        
        if analysis['ghost_alerts']:
            f.write("Gh0st trojan source IPs:\n")
            ghost_ips = set(alert['src_ip'] for alert in analysis['ghost_alerts'])
            for ip in sorted(ghost_ips):
                f.write(f"  {ip}\n")
            f.write("\n")
        
        f.write("Port analysis:\n")
        for port, count in analysis['port_counts'].most_common(20):
            f.write(f"  Port {port}: {count} alerts\n")
    
    print("\nDetailed analysis saved to analysis_results.txt")

if __name__ == "__main__":
    main()
