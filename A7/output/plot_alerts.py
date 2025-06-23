import re
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Load alert lines from file
with open("alerts_output.txt") as f:
    lines = f.readlines()

# Pattern to extract timestamp and SID
pattern = re.compile(r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2})\.\d+\s+\[\*\*\]\s+\[1:(\d+):\d+\]")

# Dictionary to hold (sid -> time bucket -> count)
data = defaultdict(lambda: defaultdict(int))

for line in lines:
    match = pattern.search(line)
    if match:
        ts_str, sid = match.groups()
        # Convert timestamp to datetime and round to the nearest minute
        dt = datetime.strptime(ts_str, "%m/%d-%H:%M:%S")
        dt = dt.replace(second=0)
        data[sid][dt] += 1

# Filter out SIDs with > 1500 alerts
filtered_data = {sid: counts for sid, counts in data.items() if sum(counts.values()) <= 1500}

# Convert to DataFrame
df = pd.DataFrame(filtered_data).fillna(0).sort_index()

# Plotting
plt.figure(figsize=(12, 6))
for sid in df.columns:
    plt.plot(df.index, df[sid], label=f"SID {sid}")

plt.title("Snort Alerts Over Time (Rules with ≤ 1500 alerts)")
plt.xlabel("Time (minute)")
plt.xticks(rotation=45)

plt.ylabel("Alert Count")
# Place legend outside to the right
plt.legend(
    title="SID",
    bbox_to_anchor=(1, 1),  # Position legend outside right
    loc='upper left',
    borderaxespad=0.,
    # fontsize='small',
    ncol=2
)
plt.tight_layout()
plt.grid(True)
# plt.savefig("alert_plot_q13.png", dpi=900)
plt.show()
