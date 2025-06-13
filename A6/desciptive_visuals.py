import matplotlib.pyplot as plt

# Port data
ports = [
    '22 (SSH)', '3389 (RDP)', '80 (HTTP)', '808/8087/8555',
    '443 (HTTPS)', '8122', '12103', '514 (Syslog)', '53 (DNS)', '5060/1194'
]
packet_counts = [175000, 25000, 150000, 30000, 125000, 20000, 15000, 10000, 75000, 18000]

# Plot
plt.figure(figsize=(12, 6))
bars = plt.bar(ports, packet_counts, color='blue', edgecolor='black')

plt.title("Port Targeting", fontsize=16, fontweight='bold')
plt.ylabel("Packet Count")
plt.xticks(rotation=45, ha='right')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()

# Save
plt.savefig("report/figures/descriptive_visual1.pdf")
