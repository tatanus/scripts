# Capture Traffic Script

`capture_traffic.sh` is a robust Bash script designed to capture and display bidirectional TCP communication between two IP addresses and ports using `tshark`. It provides flexible configuration, formatted output, and thorough error handling.

---

## Features

- **Bidirectional TCP Traffic Capture**: Filters traffic both from A→B and B→A.
- **Configurable Capture Options**:
  - Capture duration (in seconds)
  - Maximum number of packets/messages
  - Network interface selection
- **Structured Output**: Includes timestamps, IPs, ports, and application payloads.
- **Graceful Error Handling**: Validates inputs, dependencies, and tool availability.

---

## Requirements

- **Dependencies**:
  - `tshark` (part of the Wireshark suite)
  - `awk`
- **Permissions**:
  - Requires privileges to capture packets (e.g., via `sudo` or `setcap` on `tshark`).

---

## Usage

### Syntax

```bash
./capture_traffic.sh <src_ip> <dst_ip> <src_port> <dst_port> [options]
```

### Options

| Option            | Description                                         | Default          |
|------------------|-----------------------------------------------------|------------------|
| `-t`, `--time`    | Duration of the capture in seconds                  | `10`             |
| `-m`, `--messages`| Maximum number of packets to capture                | `100`            |
| `--interface`     | Network interface used for capture (e.g., `eth0`)   | `any`            |
| `--help`          | Display usage information                           | N/A              |

### Examples

#### Example 1: Capture for 10 Seconds
```bash
./capture_traffic.sh 192.168.1.1 192.168.1.2 5000 5001 -t 10
```

#### Example 2: Limit to 50 Messages
```bash
./capture_traffic.sh 192.168.1.1 192.168.1.2 5000 5001 -m 50
```

#### Example 3: Use Specific Interface
```bash
./capture_traffic.sh 192.168.1.1 192.168.1.2 5000 5001 --interface eth0
```

---

## Output Format

Output includes:

- Timestamp of the packet
- Source and destination IPs and ports
- Decoded application-layer payload (if available)

```
[Timestamp] <src_ip>:<src_port> -> <dst_ip>:<dst_port>: <payload>
```

### Sample Output

```plaintext
[2024-12-21 15:02:30.123456] 192.168.1.1:5000 -> 192.168.1.2:23: telnet 192.168.1.2
[2024-12-21 15:02:30.223456] 192.168.1.2:23 -> 192.168.1.1:5000: Welcome to Telnet Server
[2024-12-21 15:02:30.323456] 192.168.1.1:5000 -> 192.168.1.2:23: login: user1
[2024-12-21 15:02:30.423456] 192.168.1.2:23 -> 192.168.1.1:5000: Password:
[2024-12-21 15:02:31.123456] 192.168.1.1:5000 -> 192.168.1.2:23: *****
[2024-12-21 15:02:31.223456] 192.168.1.2:23 -> 192.168.1.1:5000: Login successful!
```

---

## Error Handling

- **Missing `tshark` or `awk`**: Script checks and exits with error if dependencies are missing.
- **Invalid Arguments**: Usage instructions are shown if arguments are insufficient or unknown.
- **No Matching Traffic**: Outputs a warning if no relevant packets are found during capture.

---

## File Structure

- `capture_traffic.sh` – Main script
- `CAPTURE_TRAFFIC_README.md` – This README file

---

## 📅 Authorship & Licensing

**Author**: Adam Compton  
**Date Created**: December 8, 2024  
This script is provided under the [MIT License](./LICENSE). Feel free to use and modify it for your needs.
