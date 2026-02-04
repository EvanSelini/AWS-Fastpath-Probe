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

# Override port range
python fastest_path.py --source 192.168.1.1 --destination 10.0.0.1:8080 \
    --port-range 32768-60999

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
  --port-range          Override source port range in format MIN-MAX (e.g., 32768-60999).
                        Default: read from /proc/sys/net/ipv4/ip_local_port_range
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

1. **Source IP Validation**: Validates that the `--source` IP address is configured on the host
2. **Region Detection**: Determines AWS regions for source and destination IPs using multiple methods:
   - **Source Region**: 
     - First tries AWS instance metadata endpoint (169.254.169.254) to get region and availability zone
     - Falls back to IP-based detection if metadata is unavailable
   - **Destination Region** (determined at the very beginning):
     - First scans all AWS regions via ENI/EC2 API to find which region contains the destination IP (most accurate for private IPs)
     - Stops scanning as soon as the region is found
     - Falls back to IP-based detection if ENI scanning fails or is unavailable
     - If blocked by missing credentials/permissions, displays a warning and sets region to "Unknown"
3. **5-Tuple Generation**: Creates 5-tuple configurations based on the specified protocol and ports
4. **Path Testing**: Tests network paths by binding sockets to the source IP, ensuring packets go out the correct interface
5. **Latency Measurement**: Measures connection latency for each path
6. **Result Analysis**: Identifies the fastest successful path and displays results

## Setup: Running from Region X to Region Y

### Important: Source IP Requirements

**Critical Note**: The `--source` IP address **must be configured on the host** where the script is running. The script will:
- Validate that the source IP is configured on a network interface
- Bind sockets to the source IP to ensure packets go out the correct interface
- Use the source IP for region detection (not auto-detected local IP)

To accurately test a path from **Region X → Region Y**:
- **The `--source` IP must be configured on a network interface of the host**
- **The host must be able to route traffic from that source IP to the destination**
- The application will exit with an error if the source IP is not configured

### Step 1: Prepare Destination Host (Region Y)

You need a service listening on the destination host in Region Y. The application tests connectivity using the 5-tuple, so you need something listening on the target port.

#### Option A: Netcat (Simple TCP/UDP Testing)

**Important**: The application makes multiple connections per port (controlled by `--test-count`, default: 5). Use the `-k` (keep listening) flag so netcat continues accepting connections after each one closes. For UDP, the `-k` flag requires the `--sh-exec` option to handle each connection.

**For TCP testing:**
```bash
# On Region Y host, listen on port 8080 (Linux)
# The -k flag keeps netcat listening after each connection closes
nc -l -k -p 8080

# macOS syntax (no -p flag needed)
nc -l -k 8080

# Or for a specific IP interface (Linux)
nc -l -k -p 8080 -s <target_ip>
```

**For UDP testing:**
```bash
# On Region Y host, listen on UDP port 8080 (Linux)
# The -k flag with --sh-exec keeps netcat listening after each connection
nc -u -l 8080 -k --sh-exec 'timeout 1 cat'

# macOS syntax (may vary - check your netcat version)
nc -u -l 8080 -k --sh-exec 'timeout 1 cat'
```

**Note**: If your system doesn't support the `-k` flag for TCP, you can also use a loop:
```bash
# Alternative for TCP on systems without -k flag
while true; do nc -l -p 8080; done
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

Each CSV file contains the following columns:
- **source region**: The AWS region detected for the source IP (from `--source` argument)
- **destination region**: The AWS region detected for the destination IP
- **source ip**: The source IP address (from `--source` argument)
- **source port**: The source port number used for testing
- **destination ip**: The destination IP address
- **destination port**: The destination port specified in the command
- **protocol**: The protocol used (tcp or udp, lowercase)
- **latency**: Average latency in milliseconds (averaged from multiple test runs per port)

**Note**: Each row represents one source port tested. The latency values are averaged from multiple test runs (default 5 runs per port). Only ports that were actually tested (up to convergence or sample size limit) are included in the CSV.

### Example Output Flow

```
   Source region from metadata: us-east-2 (AZ: us-east-2a)

Testing from source IP: 10.50.1.54
   Source region: us-east-2

Determining destination regions...
   Scanning for 10.181.10.197... Found in region: ap-east-1 (via ENI scan)

Testing to 1 destination(s):
   - 10.181.10.197:8080 (region: ap-east-1)

Protocols to test: TCP, UDP

Testing 300 source ports (sample size: 300)

Testing destination 10.181.10.197:8080...
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
   Completed testing 200 source ports for 10.181.10.197:8080

Results written to us-east-2-10-50-1-54-tcp-fastestpath-20240115-143022.csv
Results written to us-east-2-10-50-1-54-udp-fastestpath-20240115-143022.csv

================================================================================
TOP 5 LOWEST LATENCY PATHS
================================================================================

1. TCP - Source Port 32890
   Source:      10.50.1.54 (us-east-2)
   Destination: 10.181.10.197 (ap-east-1):8080
   Latency:     12.40 ms

2. TCP - Source Port 33012
   Source:      10.50.1.54 (us-east-2)
   Destination: 10.181.10.197 (ap-east-1):8080
   Latency:     12.58 ms

3. TCP - Source Port 33134
   Source:      10.50.1.54 (us-east-2)
   Destination: 10.181.10.197 (ap-east-1):8080
   Latency:     12.89 ms

4. UDP - Source Port 32891
   Source:      10.50.1.54 (us-east-2)
   Destination: 10.181.10.197 (ap-east-1):8080
   Latency:     15.19 ms

5. TCP - Source Port 33256
   Source:      10.50.1.54 (us-east-2)
   Destination: 10.181.10.197 (ap-east-1):8080
   Latency:     13.12 ms
================================================================================

Completed: 2000 successful tests out of 2000 total
CSV files written: us-east-2-10-50-1-54-tcp-fastestpath-20240115-143022.csv, us-east-2-10-50-1-54-udp-fastestpath-20240115-143022.csv
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

**Source Region**: 
- Detected from AWS instance metadata endpoint (169.254.169.254) when running on EC2
- Falls back to IP-based detection if metadata is unavailable
- Based on the `--source` IP address (must be configured on the host)

**Destination Region**: 
- Detected by scanning all AWS regions via ENI/EC2 API to find which region contains the destination IP
- Scanning stops as soon as the region is found
- Falls back to IP-based detection if ENI scanning fails
- If blocked by missing credentials/permissions, displays a warning and sets to "Unknown"

**Example:**
```
Source IP: 10.50.1.54 (us-east-2)  <- Detected from metadata endpoint or IP ranges
Destination IP: 10.181.10.197 (ap-east-1)  <- Detected via ENI scanning or IP ranges
Latency: 45.23 ms  <- us-east-2 -> ap-east-1 connection time
```

### 3. 5-Tuple Information

The result shows the complete 5-tuple used:
- **Source IP**: The IP address from `--source` argument (must be configured on the host)
- **Destination IP**: Target IP from `--destination` argument
- **Source Port**: Dynamically selected from ephemeral port range (or `--port-range` if specified)
- **Destination Port**: The port you specified in destination format (e.g., 8080)
- **Protocol**: TCP or UDP

**Important**: The script binds sockets to the source IP to ensure packets go out the correct network interface.

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
- **Fix**: Start netcat with `-k` flag (see Setup section above), iperf3, or other service on destination host. Remember to use `nc -l -k -p <port>` so it accepts multiple connections.

### Timeout
- **Cause**: Security group blocking, network unreachable, or firewall
- **Fix**: Check security groups, network ACLs, and firewall rules

### High Latency
- **Cause**: Geographic distance, network congestion, or routing issues
- **Fix**: Test multiple times, check for consistent patterns

### Source IP Not Configured
- **Cause**: The `--source` IP address is not configured on any network interface
- **Fix**: Ensure the source IP is assigned to a network interface on the host. The script will exit with an error if the IP is not configured.

### ENI Scanning Blocked (Missing Credentials)
- **Cause**: Destination region detection via ENI scanning is blocked due to missing AWS credentials or insufficient permissions
- **Fix**: The script will display a warning and set the destination region to "Unknown". To enable accurate destination region detection:
  - Ensure AWS credentials are configured (via IAM role, environment variables, or credentials file)
  - Ensure the IAM role/user has `ec2:DescribeNetworkInterfaces` permission in the regions being scanned
  - The script will fall back to IP-based detection, which may be less accurate

### Wrong Region Detected
- **Cause**: IP not found via ENI scanning or in AWS IP ranges
- **Fix**: 
  - For destination IPs: Ensure you have AWS credentials with `ec2:DescribeNetworkInterfaces` permission for accurate detection
  - If ENI scanning fails, the script falls back to IP-based detection which may be less accurate
  - If an IP is not found in AWS ranges, the region will be "Unknown"

### Convergence Not Reached
- **Cause**: Network conditions changing, or convergence parameters too strict
- **Fix**: Adjust `--convergence-threshold` or `--convergence-rounds` parameters

## Requirements

- Python 3.7+
- Internet connection (for AWS IP ranges and network testing)
- Linux system (for `/proc/sys/net/ipv4/ip_local_port_range` access, or use `--port-range` to override)
- Appropriate network permissions for socket binding
- **Optional but recommended**: AWS credentials with `ec2:DescribeNetworkInterfaces` permission for accurate destination region detection via ENI scanning

## Limitations

- **Source IP must be configured**: The `--source` IP address must be configured on a network interface of the host running the script
- **Socket binding**: The script binds sockets to the source IP to ensure packets use the correct interface. If binding fails, the test will fail.
- **Destination region detection**: 
  - ENI scanning (most accurate) requires AWS credentials with `ec2:DescribeNetworkInterfaces` permission
  - If credentials are missing or insufficient, the script will warn and fall back to IP-based detection
  - ENI scanning only works for private IPs; public IPs use IP-based detection
  - Scanning stops as soon as the destination region is found
- Some UDP services may not respond, but packet send time is measured
- Region detection: Source region uses metadata endpoint (when on EC2) or IP ranges; destination region uses ENI scanning (when credentials available) or IP ranges
- If an IP is not found via any method, region will be "Unknown"
- Port range file (`/proc/sys/net/ipv4/ip_local_port_range`) is Linux-specific; falls back to default range (32768-60999) on other systems, or use `--port-range` to override