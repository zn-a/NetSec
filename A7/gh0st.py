with open("gh0st_payloads.txt") as f:
    lines = f.readlines()

true_positives = 0
for hex_payload in lines:
    if "4768307374" not in hex_payload:  # ASCII for "Gh0st"
        continue
    if "000000" not in hex_payload:
        continue
    if "0000789c" not in hex_payload:
        continue
    true_positives += 1

print(f"True positives: {true_positives} out of {len(lines)}")
