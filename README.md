# Mini IDS (Intrusion Detection System)

A simple network intrusion detection system built with Python that monitors network traffic and detects potential attacks.

## Features

- Real-time packet capture and analysis
- Detection of multiple attack types:
  - ICMP Flood
  - Port Scanning
  - SYN Flood
  - Brute Force Attempts
- GUI interface with:
  - Live packet monitoring
  - Alert display
  - Logging system
  - Configurable network interface and packet filters

## Detection Modules

### ICMP Flood Detector
- Monitors for excessive ICMP packets from a single source
- Configurable threshold and time interval

### Port Scan Detector
- Detects rapid connection attempts to multiple ports
- Tracks unique ports accessed within time window

### SYN Flood Detector
- Identifies TCP SYN flood attacks
- Monitors frequency of SYN packets from each source

### Brute Force Detector
- Detects repeated login attempts
- Configurable attempt threshold and monitoring period
