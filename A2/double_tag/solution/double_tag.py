from scapy.all import *

import sys

# Terminal color codes
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RESET = "\033[0m"


def main():
    if len(sys.argv) != 4:
        print(f"{RED}Error: Incorrect Usage!{RESET}")
        print(
            f"{RED}Usage: python3 double_tag.py <first VLAN ID> <second VLAN ID> <destination ip>{RESET}")
        sys.exit(1)

    outer_vlan = int(sys.argv[1])
    inner_vlan = int(sys.argv[2])
    destination_ip = sys.argv[3]

    print(
        f"Sending double-tagged ICMP packet to {destination_ip} via VLANs {outer_vlan}, {inner_vlan}")


if __name__ == "__main__":
    main()
