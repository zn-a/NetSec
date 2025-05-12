# CS4430 Network Security (2024-2025)

This course explores the principles and practices of securing computer networks, including topics such as cryptography, network protocols, intrusion detection, and ethical hacking.

## Assignments Overview

Below is a list of all the assignments for the course, along with their respective weights toward the final grade:

| Assignment Number | Title/Topic                          | Weight (%) |
| ----------------- | ------------------------------------ | ---------- |
| Assignment 1      | Docker & Scapy Tutorial (Not Graded) | 0%         |
| Assignment 2      | Link Layer Security                  | 10%        |
| Assignment 3      | Network Layer Security               | 10%        |
| Assignment 4      |                                      | 10%        |
| Assignment 5      |                                      | 10%        |
| Assignment 6      |                                      | 25%        |
| Assignment 7      |                                      | 25%        |

## Grading Rubric for Assignments

Below is the detailed grading rubric for each assignment and sub-assignment in the course.

---

### Assignment 2: Link Layer Security

#### 2.1: ARP Spoofing

**Due Date:** May 10, 18:00  
**Environment:** `arp_poisoning.zip`

**Grading Rubric:**

- [x] The student successfully poisons the ARP cache of both hosts – **25 points**
- [x] The student is able to capture packets continuously and print their IP addresses and contents – **10 points**
- [x] The student successfully restores the ARP table – **15 points**

---

#### 2.2: VLAN Hopping

**Due Date:** May 10, 18:00  
**Environment:** `double_tag.zip`

**Grading Rubric:**

- [x] The student is able to generate and send a double-tagged Ethernet frame – **10 points**
- [x] The Ethernet frame is received and correctly processed by `host02` – **40 points**

---

### Assignment 3: Network Layer Security

#### 3.1: IP Spoofing

**Due Date:** May 16, 18:00  
**Environment:** `ip_spoofing.zip`

**Grading Rubric:**

- [ ] The student sends an ICMP packet with a spoofed source address – **5 points**
- [ ] The student implements a functional attack and opens the port – **10 points**
- [ ] The student retrieves and prints the secret – **5 points**

---

#### 3.2: Data Exfiltration using ICMP

**Due Date:** May 16, 18:00  
**Environment:** `icmp_exfiltration.zip`

**Grading Rubric:**

- [ ] The student sends ICMP packets with payload to the destination host – **5 points**
- [ ] The file is correctly read, transmitted, received, and saved – **25 points**
- [ ] During transmission, the file is encrypted and then decrypted – **10 points**

---

#### 3.3: ICMP Covert Channel

**Due Date:** May 16, 18:00  
**Environment:** `icmp_covert.zip`

**Grading Rubric:**

- [ ] The student transmits ICMP packets passing through the firewall – **5 points**
- [ ] The student manipulates unused parts of the header and transmits packets – **10 points**
- [ ] The student successfully transmits the message and reconstructs it on the receiving end – **25 points**

---

### Assignment 4:

---

### Assignment 5:

---

### Assignment 6:

---

### Assignment 7:
