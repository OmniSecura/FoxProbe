# FoxProbe

FoxProbe is a desktop network inspection suite that captures live traffic, enriches it with protocol awareness, and presents the results through a richly instrumented interface. It is designed for analysts who need rapid feedback while troubleshooting, hunting anomalies, or studying how protocols behave on the wire.

[Visit the FoxProbe website](https://omnisecura.github.io/FoxProbeWebsite)

## Overview
- **Live capture control** – Pick an interface, toggle promiscuous mode, and apply BPF filters without leaving the toolbar. Capture sessions run in a worker thread so the interface stays responsive.
- **Layer-aware decoding** – Parse Ethernet II and Linux Cooked Capture frames, drill down into IPv4/IPv6, TCP/UDP, ICMP, VPN tunnels, MPLS, RSVP, PIM, and more. A protocol tree and hex/ASCII pane expose every field and payload byte.
- **Conversation reconstruction** – Follow TCP or UDP streams with bidirectional timelines, payload rendering, metadata such as TCP flags and sequence numbers, and quick export options.
- **Visual context** – Track protocol distribution with live pie charts and geolocate flows on an embedded world map, complete with animated flight paths.
- **Coloring and annotations** – Apply rule-driven highlighting based on BPF expressions, annotate packets with threat levels or tags, and persist annotated selections as JSON reports.
- **Session intelligence** – Persist PCAP files, statistics, and metadata for offline review. Dedicated dialogs surface stored sessions, charts (bar/line), and geo-temporal exploration of historic traffic.

## Getting Started

### Prerequisites
- Qt toolchain with `qmake`
- `libpcap` development headers
- A compiler toolchain compatible with your platform (e.g., GCC or Clang on Linux)

### Clone the repository
```bash
git clone https://github.com/omnisecura/FoxProbe.git
cd FoxProbe
```

### Build the application
```bash
qmake PacketSniffer.pro CONFIG+=release && make -j"$(nproc)"
```

### Run FoxProbe
```bash
sudo ./PacketSniffer
```

### Keep your workspace clean
```bash
# Remove build artifacts and generated files
make distclean
```

## Operating FoxProbe
1. Launch the application and choose the capture interface from the toolbar dropdown.
2. Optionally enter a BPF filter and enable promiscuous mode.
3. Press **Start** to begin capturing packets. The session timer, packet counter, charts, and GeoMap update in real time.
4. Select a packet to inspect decoded headers, payload bytes, and protocol-specific summaries.
5. Use **Follow Stream** to reconstruct conversations, or open **Statistics** dialogs for charts and geo-overview timelines.
6. Save sessions for later via the session manager, or export annotated selections from the reporting dialog.

## Project Resources
- Source code: this repository (`mainwindow_*`, `packets/`, `statistics/`, and `packetworker.cpp` house the core logic)
- Website: [https://omnisecura.github.io/FoxProbeWebsite](https://omnisecura.github.io/FoxProbeWebsite)

FoxProbe continues to evolve toward a comprehensive network analysis companion. Contributions, issue reports, and feature ideas are welcome.
