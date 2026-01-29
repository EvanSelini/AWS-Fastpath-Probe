# Fastest Path Finder - AWS Region Network Path Analyzer

A Python application to find the fastest network path between two IP addresses across AWS regions, using the 5-tuple networking concept.

## Overview

This application helps identify the optimal network path between two IP addresses by:
- Detecting AWS regions for source and destination IPs
- Testing multiple paths using the 5-tuple concept
- Measuring latency across different paths
- Identifying the fastest successful path

## 5-Tuple Concept

The 5-tuple is a fundamental concept in AWS networking used to identify unique network flows:

1. **Source IP Address** - Origin of the network packet
2. **Destination IP Address** - Target of the network packet
3. **Source Port** - Port number on the source (ephemeral for outbound connections)
4. **Destination Port** - Port number on the destination (e.g., 80 for HTTP, 443 for HTTPS)
5. **Protocol** - Network protocol (TCP, UDP)

## Features

- ✅ AWS region detection for IP addresses
- ✅ Multi-protocol support (TCP, UDP)
- ✅ Adaptive source port testing with convergence detection
- ✅ CSV output per protocol with averaged results
- ✅ Concurrent path testing for performance
- ✅ Latency measurement and comparison
- ✅ 5-tuple flow identification
- ✅ Configurable test parameters

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Find the fastest path between two IPs (tests both TCP and UDP by default):
```bash
python fastest_path.py --source 192.168.1.1 --destination 10.0.0.1:8080
```

### Advanced Usage

```bash
# Specify protocol (TCP or UDP)
python fastest_path.py --source 192.168.1.1 --destination 10.0.0.1:8080 --protocol TCP

# Multiple destinations
python fastest_path.py --source 192.168.1.1 \
    --destination 10.0.0.1:8080,10.0.0.2:443

# Custom test parameters
python fastest_path.py --source 192.168.1.1 --destination 10.0.0.1:8080 \
    --test-count 10 --port-sample-size 500

# Convergence parameters
python fastest_path.py --source 192.168.1.1 --destination 10.0.0.1:8080 \
    --top-k 20 --convergence-rounds 5
```

### Command Line Options

```
required arguments:
  --source, -s          Source IP address
  --destination, -d     Destination in format IP:PORT (e.g., 10.0.0.1:8080)
                        Can specify multiple times or use comma-separated values

optional arguments:
  -h, --help            Show help message
  --protocol, -p        Protocol to use: TCP or UDP (default: tests both)
  --test-count, -n      Number of tests per source port (default: 5)
  --port-sample-size    Maximum number of source ports to test (default: 300)
  --top-k               Number of top ports to track for convergence (default: 10)
  --convergence-rounds  Rounds with stable Top-K for convergence (default: 3)
  --convergence-threshold  Jaccard similarity threshold (default: 0.9)
  --latency-improvement-threshold  Max latency improvement in ms (default: 1.0)
  --latency-improvement-percent   Max latency improvement % (default: 5.0)
  --timeout, -t         Timeout per test in seconds (default: 5.0)
```

## Examples

### Example 1: Test HTTP connection (TCP)
```bash
python fastest_path.py --source 192.168.1.100 --destination 54.239.28.85:80 --protocol TCP
```

### Example 2: Test HTTPS connection (TCP)
```bash
python fastest_path.py --source 192.168.1.100 --destination 54.239.28.85:443 --protocol TCP
```

### Example 3: Test DNS (UDP)
```bash
python fastest_path.py --source 192.168.1.100 --destination 8.8.8.8:53 --protocol UDP
```

### Example 4: Test both TCP and UDP (default)
```bash
python fastest_path.py --source 192.168.1.100 --destination 10.0.0.1:8080
```

## Architecture

The application consists of several modules:

- **`fastest_path.py`** - Main application entry point and path finder logic
- **`five_tuple.py`** - 5-tuple data structure and validation
- **`aws_region_mapper.py`** - AWS region detection and IP-to-region mapping
- **`network_tester.py`** - Network connectivity testing and latency measurement

## How It Works

1. **Local Machine Detection**: Detects the local machine's IP and AWS region (where tests run from)
2. **Region Detection**: Queries AWS IP ranges to determine which regions contain the source and destination IPs
3. **5-Tuple Generation**: Creates 5-tuple configurations based on the specified protocol and ports
4. **Path Testing**: Tests network paths from the local machine to the destination IP concurrently
5. **Latency Measurement**: Measures connection latency for each path
6. **Result Analysis**: Identifies the fastest successful path and displays results

## Setup: Running from Region X to Region Y

### Important: Testing from Different Regions

**Critical Note**: The application tests network paths **FROM the local machine** where the script is running **TO the destination IP**.

To accurately test a path from **Region X → Region Y**:
- **You must run the script from a host located in Region X**
- The application will detect your local machine's region and warn you if it doesn't match the specified source IP

### Step 1: Prepare Destination Host (Region Y)

You need a service listening on the destination host in Region Y. The application tests connectivity using the 5-tuple, so you need something listening on the target port.

#### Option A: Netcat (Simple TCP/UDP Testing)

**For TCP testing:**
```bash
# On Region Y host, listen on port 8080
nc -l -p 8080

# Or for a specific IP interface
nc -l -p 8080 -s <target_ip>
```

**For UDP testing:**
```bash
# On Region Y host, listen on UDP port 53
nc -u -l -p 53
```

#### Option B: iperf3 (Better for Performance Testing)

**On Region Y (server):**
```bash
# Install iperf3 if needed
# Ubuntu/Debian: sudo apt-get install iperf3
# Amazon Linux: sudo yum install iperf3

# Start iperf3 server on port 5201 (default)
iperf3 -s -p 5201

# Or specify IP and port
iperf3 -s -B <target_ip> -p 5201
```

**Note**: The current `fastest_path.py` tests basic connectivity (TCP connect, UDP send). It doesn't use iperf3 directly, but you can use iperf3 to verify connectivity separately.

#### Option C: Simple HTTP Server (For TCP Port 80/443)

```bash
# Python HTTP server on port 8000
python3 -m http.server 8000

# Or use nginx/apache if already installed
```

### Step 2: Run from Region X

```bash
# SSH into host in Region X
ssh ec2-user@instance-in-region-x

# Run the test (destination format: IP:PORT)
python fastest_path.py --source <source_ip_in_region_x> \
    --destination <target_ip_in_region_y>:8080 \
    --test-count 5
```

## Output

The application provides comprehensive testing results:

### Console Output
- **Testing Progress**: Shows which protocols are being tested, batch progress, and convergence status
- **Convergence Information**: Displays when Top-K ports stabilize and testing stops early
- **Summary Statistics**: Total successful tests, ports tested, and convergence rounds

### CSV Files
Separate CSV files are generated for each protocol tested, with filename format:
`{region}-{ipaddress}-{protocol}-fastestpath-{YYYYMMDD-HHMMSS}.csv`

Example: `us-east-1-192-168-1-1-tcp-fastestpath-20240115-143022.csv`

The timestamp prevents overwriting previous results when running multiple times.

Each CSV file contains:
- **Source (IP and region)**: The source IP address and its detected AWS region
- **Source port (dynamic from average of runs)**: The source port number used for testing
- **Destination (IP and region)**: The destination IP address and its detected AWS region  
- **Destination port (static)**: The destination port specified in the command
- **Protocol**: The protocol used (tcp or udp, lowercase)

**Note**: Each row represents one source port tested. The latency values shown are averaged from multiple test runs (default 5 runs per port). Only ports that were actually tested (up to convergence or sample size limit) are included in the CSV. All raw data is preserved in the CSV files.

### Example Output Flow

```
Testing from local machine:
   Local IP: 54.123.45.67
   Local region(s): ['us-east-1']

Testing to 1 destination(s):
   - 10.0.0.1:8080 (regions: ['us-west-2'])

Protocols to test: TCP, UDP

Testing 300 source ports (sample size: 300)

Testing destination 10.0.0.1:8080...
   Round 1: Testing batch of 50 ports...
      TCP Top-10 ports: [32768, 32890, 33012, ...] (showing first 5)
      TCP best median latency: 12.45 ms
      UDP Top-10 ports: [32769, 32891, 33013, ...] (showing first 5)
      UDP best median latency: 15.23 ms
   Round 2: Testing batch of 50 ports...
      TCP Top-10 ports: [32768, 32890, 33012, ...] (showing first 5)
      TCP best median latency: 12.42 ms
      UDP Top-10 ports: [32769, 32891, 33013, ...] (showing first 5)
      UDP best median latency: 15.18 ms
   Round 3: Testing batch of 50 ports...
      TCP Top-10 ports: [32768, 32890, 33012, ...] (showing first 5)
      TCP best median latency: 12.40 ms
      UDP Top-10 ports: [32769, 32891, 33013, ...] (showing first 5)
      UDP best median latency: 15.20 ms
   TCP convergence reached after 3 rounds!
   Round 4: Testing batch of 50 ports...
      UDP Top-10 ports: [32769, 32891, 33013, ...] (showing first 5)
      UDP best median latency: 15.19 ms
   UDP convergence reached after 4 rounds!
   All protocols converged after 4 rounds!
   Completed testing 200 source ports for 10.0.0.1:8080

Results written to us-east-1-54-123-45-67-tcp-fastestpath-20240115-143022.csv
Results written to us-east-1-54-123-45-67-udp-fastestpath-20240115-143022.csv

================================================================================
TOP 5 LOWEST LATENCY PATHS
================================================================================

1. TCP - Source Port 32890
   Source:      54.123.45.67 (us-east-1)
   Destination: 10.0.0.1 (us-west-2):8080
   Latency:     12.40 ms

2. TCP - Source Port 33012
   Source:      54.123.45.67 (us-east-1)
   Destination: 10.0.0.1 (us-west-2):8080
   Latency:     12.58 ms

3. TCP - Source Port 33134
   Source:      54.123.45.67 (us-east-1)
   Destination: 10.0.0.1 (us-west-2):8080
   Latency:     12.89 ms

4. UDP - Source Port 32891
   Source:      54.123.45.67 (us-east-1)
   Destination: 10.0.0.1 (us-west-2):8080
   Latency:     15.19 ms

5. TCP - Source Port 33256
   Source:      54.123.45.67 (us-east-1)
   Destination: 10.0.0.1 (us-west-2):8080
   Latency:     13.12 ms
================================================================================

Completed: 2000 successful tests out of 2000 total
CSV files written: us-east-1-54-123-45-67-tcp-fastestpath-20240115-143022.csv, us-east-1-54-123-45-67-udp-fastestpath-20240115-143022.csv
```

## How to Interpret Results

### 1. Latency Measurement

**What it means:**
- **Latency (ms)**: Round-trip time or connection establishment time
  - TCP: Time to establish connection (3-way handshake)
  - UDP: Time to send packet (may not get response)

**Interpreting values:**
- **< 10 ms**: Same region or very close (e.g., us-east-1 -> us-east-1)
- **10-50 ms**: Same continent, different regions (e.g., us-east-1 -> us-west-2)
- **50-150 ms**: Cross-continent (e.g., us-east-1 -> eu-west-1)
- **150-300 ms**: Long distance (e.g., us-east-1 -> ap-southeast-1)
- **> 300 ms**: Very long distance or network issues

### 2. Region Information

**Source Region**: Where the test originates (your local machine's region)
**Destination Region**: Where the target IP is located

**Example:**
```
Source IP: 54.123.45.67 (us-east-1)  <- You're running from here
Destination IP: 54.234.56.78 (eu-west-1)  <- Testing to here
Latency: 45.23 ms  <- us-east-1 -> eu-west-1 connection time
```

### 3. 5-Tuple Information

The result shows the complete 5-tuple used:
- **Source IP**: Your local machine's IP
- **Destination IP**: Target IP
- **Source Port**: Dynamically selected from ephemeral port range
- **Destination Port**: The port you specified in destination format (e.g., 8080)
- **Protocol**: TCP or UDP

### 4. Success vs Failure

**Success**: 
- Connection established (TCP)
- Packet sent successfully (UDP)
- Latency value is meaningful

**Failure**:
- Connection timeout
- Connection refused (no service listening)
- Network unreachable
- Security group/firewall blocking

### 5. Top 5 Lowest Latency Summary

At the end of testing, the application displays the top 5 lowest latency paths across all protocols:
- Ranked by average latency (lowest first)
- Shows protocol, source port, source/destination IPs and regions, and latency
- Helps identify the best performing source ports for your use case

### 6. CSV File Contents

Each CSV file contains all tested ports with their averaged latencies:
- One row per (source_port, protocol, destination) combination
- Sorted by destination IP, then source port
- Includes timestamp in filename to prevent overwriting previous runs
- All raw data is preserved for further analysis

## Troubleshooting

### Connection Refused
- **Cause**: No service listening on destination port
- **Fix**: Start netcat, iperf3, or other service on destination host

### Timeout
- **Cause**: Security group blocking, network unreachable, or firewall
- **Fix**: Check security groups, network ACLs, and firewall rules

### High Latency
- **Cause**: Geographic distance, network congestion, or routing issues
- **Fix**: Test multiple times, check for consistent patterns

### Wrong Region Detected
- **Cause**: IP not in AWS IP ranges, or private IP
- **Fix**: Application uses heuristics - verify manually if needed

### Convergence Not Reached
- **Cause**: Network conditions changing, or convergence parameters too strict
- **Fix**: Adjust `--convergence-threshold` or `--convergence-rounds` parameters

## Requirements

- Python 3.7+
- Internet connection (for AWS IP ranges and network testing)
- Linux system (for `/proc/sys/net/ipv4/ip_local_port_range` access)
- Appropriate network permissions for socket binding

## Limitations

- **Tests run from local machine**: Network paths are tested from wherever the script is executed, not from the specified source IP
- Some UDP services may not respond, but packet send time is measured
- Region detection relies on AWS IP ranges; private IPs use heuristics
- For accurate cross-region testing, deploy and run the script in the source region
- Port range file (`/proc/sys/net/ipv4/ip_local_port_range`) is Linux-specific; falls back to default range on other systems

## Future Enhancements

Potential improvements:
- Integration with AWS CloudWatch for real-time metrics
- Support for traceroute/path visualization
- Historical path performance tracking
- Integration with AWS Global Accelerator
- Support for custom region endpoints