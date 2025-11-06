#ifndef PROTO_STRUCT_H
#define PROTO_STRUCT_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string>
#include <stdint.h>
#include <netinet/in.h>

#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP 89
#endif

// -------------------------------------------------------------------------
// LINK LAYER
// -------------------------------------------------------------------------
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {    // IEEE: 802.3
    u_char  ether_dhost[ETHER_ADDR_LEN];  // Destination MAC
    u_char  ether_shost[ETHER_ADDR_LEN];  // Source MAC
    u_short ether_type;                   // Ethertype (IP, ARP, VLAN, etc.)
};

struct sniff_dot1q {       // IEEE: 802.1Q
    u_short tci;         // Tag Control Info (VLAN ID, priority)
    u_short ether_type;  // Next Ethertype after VLAN
};

struct sniff_qinq {        // IEEE: 802.1ad (Q-in-Q)
    struct sniff_dot1q outer_tag; // Service VLAN tag
    struct sniff_dot1q inner_tag; // Customer VLAN tag
};

struct sniff_llc {         // IEEE: 802.2 Logical Link Control
    uint8_t  dsap;        // Destination Service Access Point
    uint8_t  ssap;        // Source Service Access Point
    uint8_t  control;     // Control field (I/S/U format)
};

struct sniff_snap {        // Subnetwork Access Protocol header
    uint8_t  oui[3];      // Organizationally Unique Identifier
    uint16_t protocol_id; // Protocol identifier (Ethertype)
};

struct sniff_token_ring {  // IEEE: 802.5 Token Ring
    uint8_t  access_control;
    uint8_t  frame_control;
    uint8_t  dest_addr[6];
    uint8_t  src_addr[6];
};

struct sniff_fddi {        // ANSI: X3T9.5 FDDI
    uint8_t  frame_control;
    uint8_t  dest_addr[6];
    uint8_t  src_addr[6];
};

struct sniff_ppp {         // RFC: 1661 (Point-to-Point Protocol)
    uint8_t  address;     // Usually 0xFF
    uint8_t  control;     // Usually 0x03
    uint16_t protocol;    // Protocol field (PPP Protocol IDs)
};

struct sniff_pppoe_discovery { // RFC: 2516 (PPPoE Discovery stage)
    uint8_t  ver_type;    // Version (4 bits) | Type (4 bits)
    uint8_t  code;        // PPPoE Code (PADI, PADO, etc.)
    uint16_t session_id;  // Must be zero in discovery stage
    uint16_t length;      // Length of payload
};

struct sniff_pppoe_session {   // RFC: 2516 (PPPoE Session stage)
    uint8_t  ver_type;    // Version (4 bits) | Type (4 bits)
    uint8_t  code;        // Should be 0x00 during session
    uint16_t session_id;  // Session identifier
    uint16_t length;      // Length of PPP payload
};

#pragma pack(push, 1)
struct sniff_linux_cooked {   // Linux "any" pseudo header (DLT_LINUX_SLL)
    uint16_t packet_type;  // From PACKET_ constants
    uint16_t arphrd_type;  // ARPHRD_ value describing link-layer type
    uint16_t addr_len;     // Length of the link-layer address
    uint8_t  addr[8];      // Link-layer address (padded with zeros)
    uint16_t protocol;     // Upper-layer protocol (EtherType)
};
#pragma pack(pop)

static constexpr int LINUX_SLL_HEADER_LEN = sizeof(sniff_linux_cooked);
static_assert(LINUX_SLL_HEADER_LEN == 16, "Linux cooked header should be 16 bytes");

struct sniff_cdp {         // Cisco Discovery Protocol
    uint8_t  version;
    uint8_t  ttl;
    uint16_t checksum;
    // Followed by TLV entries
};

struct sniff_lldp {        // IEEE: 802.1AB Link Layer Discovery Protocol
    uint16_t tlv_type_length; // Type (7 bits) | Length (9 bits)
    uint8_t  value[1];        // Placeholder for TLV value (variable length)
};

struct sniff_arp {         // RFC: 826
    u_short ar_hrd;
    u_short ar_pro;
    u_char  ar_hln;
    u_char  ar_pln;
    u_short ar_op;
    u_char  ar_sha[6];
    u_char  ar_sip[4];
    u_char  ar_tha[6];
    u_char  ar_tip[4];
};

// -------------------------------------------------------------------------
// NETWORK LAYER (IPv4 / IPv6 + ICMPs + IGMP + OSPF + BGP marker)
// -------------------------------------------------------------------------
struct sniff_ip {          // RFC: 791
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

struct sniff_ipv6 {        // RFC: 8200
    uint32_t ip6_flow;
    uint16_t ip6_plen;
    uint8_t  ip6_nxt;
    uint8_t  ip6_hlim;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

struct sniff_ipv6_hopopts { // RFC: 8200 (Hop-by-Hop Options)
    uint8_t  next_header;  // Next header value
    uint8_t  hdr_ext_len;  // Extension header length in 8-octet units
    // Followed by options
};

struct sniff_ipv6_dstopts { // RFC: 8200 (Destination Options)
    uint8_t  next_header;  // Next header value
    uint8_t  hdr_ext_len;  // Extension header length in 8-octet units
    // Followed by options
};

struct sniff_ipv6_routing { // RFC: 8200 (Routing Header)
    uint8_t  next_header;  // Next header value
    uint8_t  hdr_ext_len;  // Extension header length
    uint8_t  routing_type; // Routing type
    uint8_t  segments_left;// Segments left
    uint32_t reserved;     // Reserved / type-specific data
    // Followed by type-specific routing data
};

struct sniff_ipv6_fragment { // RFC: 8200 (Fragment Header)
    uint8_t  next_header;  // Next header value
    uint8_t  reserved;     // Reserved
    uint16_t frag_offset;  // Offset, Res, M flag
    uint32_t identification; // Fragment identification
};

struct sniff_ipv6_mobility { // RFC: 6275 (Mobility Header)
    uint8_t  next_header;  // Next header value
    uint8_t  hdr_ext_len;  // Header extension length
    uint8_t  mh_type;      // Mobility message type
    uint8_t  reserved;     // Reserved
    uint16_t checksum;     // Checksum
    // Followed by mobility options / data
};

struct sniff_icmp {        // RFC: 792
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_cksum;
    uint16_t icmp_id;
    uint16_t icmp_seq;
};

struct sniff_icmp_timestamp { // RFC: 792 (Timestamp message)
    uint8_t  type;        // 13 = Timestamp, 14 = Timestamp Reply
    uint8_t  code;        // Zero
    uint16_t checksum;    // Checksum
    uint16_t id;          // Identifier
    uint16_t seq;         // Sequence number
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
};

struct sniff_icmpv6 {      // RFC: 4443
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
    uint16_t icmp6_cksum;
    union {
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;
        // other ICMPv6 message formats
    } icmp6_data;
};

struct sniff_igmpv1v2 {    // RFC: 1112 (v1), RFC: 2236 (v2)
    uint8_t  type;     // Message type
    uint8_t  mrt;      // Max Response Time (v1: 0)
    uint16_t cksum;    // Checksum
    struct in_addr group_addr; // Group Address
};

struct sniff_igmpv3_query {  // RFC: 3376 (Membership Query)
    uint8_t  type;           // 0x11
    uint8_t  resv_s_qrv;     // Reserved + Suppress + QRV
    uint8_t  qqic;           // Querier's Query Interval Code
    uint16_t num_sources;    // Number of source addresses
    struct in_addr group_addr; // Group Address
    // Followed by source addresses (variable) and optional data
};

struct sniff_igmpv3_record { // RFC: 3376 (Group Record)
    uint8_t  record_type;    // e.g. 1=MODE_IS_INCLUDE
    uint8_t  aux_data_len;   // In 32-bit words
    uint16_t num_sources;    // Number of source addresses
    struct in_addr group_addr; // Multicast Address
    // Followed by source addresses and optional auxiliary data
};

struct sniff_igmpv3_report { // RFC: 3376 (Membership Report)
    uint8_t  type;           // 0x22
    uint8_t  reserved1;
    uint16_t cksum;          // Checksum
    uint16_t reserved2;
    uint16_t num_group_records; // Number of group records
    // Followed by sniff_igmpv3_record entries
};

struct sniff_rip {         // RFC: 2453 (Routing Information Protocol v2)
    uint8_t  command;      // 1=Request, 2=Response
    uint8_t  version;      // RIP version (1 or 2)
    uint16_t zero;         // Must be zero
    // Followed by route entries (RTEs)
};

struct sniff_eigrp {       // Cisco Enhanced Interior Gateway Routing Protocol
    uint8_t  version;
    uint8_t  opcode;       // Update, Query, Reply, Hello, ACK
    uint16_t checksum;
    uint32_t flags;
    uint32_t sequence;
    uint32_t ack;
    uint32_t autonomous_system;
    // Followed by TLVs
};

struct sniff_is_is {       // ISO/IEC 10589 (IS-IS)
    uint8_t  nlpid;        // Network Layer Protocol ID (typically 0x83)
    uint8_t  length;       // Length indicator
    uint8_t  version;      // Protocol version (1)
    uint8_t  id_length;    // System ID length
    uint16_t pdu_type_reserved; // PDU type + reserved bits
    uint8_t  max_area_addresses;
    // Followed by PDU-specific fields
};

struct sniff_babel {       // RFC: 8966 (Babel routing protocol)
    uint8_t  version;
    uint8_t  body_length;  // In 16-byte units
    uint16_t seqno;
    uint16_t interval;
    uint16_t body_checksum;
    // Followed by TLVs
};

struct sniff_ospf {        // RFC: 2328
    uint8_t  version;
    uint8_t  type;      // 1=Hello, 2=DB Description, 3=LS Request, 4=LS Update, 5=LS Ack
    uint16_t length;    // length of entire OSPF packet
    struct in_addr router_id;
    struct in_addr area_id;
    uint16_t checksum;  // standard IP-style checksum
    uint16_t autype;    // authentication type
    // then authentication data (8 bytes), and message-specific data
};

struct sniff_rsvp {        // RFC: 2205
    uint8_t  ver_flags;    // Version (4 bits) | Flags (4 bits)
    uint8_t  msg_type;     // Path, Resv, Err, etc.
    uint16_t checksum;     // Standard checksum
    uint8_t  send_ttl;     // Send TTL
    uint8_t  reserved;     // Reserved
    uint16_t length;       // Length of entire RSVP message
    // Followed by RSVP objects
};

struct sniff_pim {         // RFC: 7761
    uint8_t  ver_type;     // Version (4 bits) | Message Type (4 bits)
    uint8_t  reserved;     // Reserved
    uint16_t checksum;     // Checksum over entire PIM message
    // Followed by PIM message-specific data
};

struct sniff_lisp {        // RFC: 6830 (Locator/ID Separation Protocol)
    uint8_t  type;         // Type and flags
    uint8_t  reserved1;
    uint8_t  reserved2;
    uint8_t  nonce_present_map_version;
    uint32_t eid_mask_len_instance_id;
    // Followed by type-specific data
};

// not commonly used nowadays
struct sniff_egp {         // RFC: 904
    uint8_t  version;      // Protocol version
    uint8_t  type;         // Message type
    uint8_t  code;         // Code within the type
    uint8_t  status;       // Status field
    uint16_t checksum;     // Checksum
    uint16_t autonomous_system; // Sender AS number
    uint16_t sequence;     // Sequence number
    // Followed by type-specific data
};

struct sniff_pup {         // PARC Universal Packet
    uint8_t  transport_control; // Hop count
    uint8_t  type;         // Packet type
    uint16_t id;           // Identification
    uint16_t dst_net;      // Destination network
    uint8_t  dst_host[6];  // Destination host
    uint16_t dst_socket;   // Destination socket
    uint16_t src_net;      // Source network
    uint8_t  src_host[6];  // Source host
    uint16_t src_socket;   // Source socket
};

struct sniff_idp {         // RFC: 906 (XNS IDP)
    uint16_t checksum;     // Checksum (0 if unused)
    uint16_t length;       // Packet length
    uint8_t  transport_control; // Hop count
    uint8_t  packet_type;  // Packet type
    uint32_t dst_network;  // Destination network
    uint8_t  dst_host[6];  // Destination host
    uint16_t dst_socket;   // Destination socket
    uint32_t src_network;  // Source network
    uint8_t  src_host[6];  // Source host
    uint16_t src_socket;   // Source socket
};

struct sniff_tp4 {         // ISO Transport Protocol Class 4
    uint8_t  li;           // Header length indicator
    uint8_t  code;         // TPDU code
    uint16_t dst_ref;      // Destination reference
    uint16_t src_ref;      // Source reference
    uint8_t  class_options;// Class/options flags
    // Followed by variable parameters
};

struct sniff_mtp {         // RFC: 1301 (Multicast Transport Protocol)
    uint8_t  version;      // Protocol version
    uint8_t  reserved;     // Reserved
    uint16_t checksum;     // Checksum
    uint16_t length;       // Total length
    uint16_t session_id;   // Session identifier
    uint32_t seq_number;   // Sequence number
    // Followed by payload
};

// -------------------------------------------------------------------------
// TRANSPORT LAYER (TCP, UDP)
// -------------------------------------------------------------------------
typedef u_int tcp_seq;

struct sniff_tcp {         // RFC: 793
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
// #define TH_OFF(th)  (((th)->th_offx2 & 0xF0) >> 4) //for options+padding and data

struct sniff_udp {         // RFC: 768
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
};

struct sniff_sctp {        // RFC: 4960
    uint16_t src_port;     // Source port
    uint16_t dst_port;     // Destination port
    uint32_t verification_tag; // Verification tag
    uint32_t checksum;     // Adler-32 checksum
    // Followed by one or more chunks
};

struct sniff_dccp {        // RFC: 4340 (Datagram Congestion Control Protocol)
    uint16_t src_port;     // Source port
    uint16_t dst_port;     // Destination port
    uint8_t  data_offset;  // Header length and type-specific bits
    uint8_t  ccval_cscov;  // CCID value and checksum coverage
    uint16_t checksum;     // Checksum
    uint32_t seq_high;     // Sequence number high bits (depends on type)
    uint32_t seq_low;      // Sequence number low bits
    // Followed by type-dependent fields
};

struct sniff_rtp {         // RFC: 3550 (Real-time Transport Protocol)
    uint8_t  vpxcc;        // Version, Padding, Extension, CSRC count
    uint8_t  mpt;          // Marker, Payload Type
    uint16_t sequence;     // Sequence number
    uint32_t timestamp;    // Timestamp
    uint32_t ssrc;         // Synchronization source identifier
    // Followed by optional CSRC list and payload
};

struct sniff_rtcp {        // RFC: 3550 (Real-time Control Protocol)
    uint8_t  vprc;         // Version, Padding, Reception report count
    uint8_t  packet_type;  // Packet type
    uint16_t length;       // Length in 32-bit words minus one
    uint32_t ssrc;         // Synchronization source identifier
    // Followed by report blocks / payload
};

struct sniff_udplite {     // RFC: 3828
    uint16_t src_port;     // Source port
    uint16_t dst_port;     // Destination port
    uint16_t checksum_cov; // Checksum coverage
    uint16_t checksum;     // Checksum
};

// -------------------------------------------------------------------------
// TUNNELING (GRE, IPv4-in-IPv4, L2TP, MPLS-in-IP, etc.)
// -------------------------------------------------------------------------
struct sniff_gre {         // RFC: 2784
    u_short flags_version;  // bits: C,R,K,S,etc. + version
    u_short protocol;       // Ethertype of encapsulated payload
    // optional fields if flags are set: checksum, key, sequence, etc.
};

struct sniff_ipip {        // RFC: 2003 (IPv4-in-IPv4)
    struct sniff_ip outer_header; // Encapsulating IPv4 header
    // Followed by inner IP packet
};

struct sniff_l2tp {        // RFC: 3931
    uint16_t flags_version; // Flags and version
    uint16_t length;        // Length (optional depending on flags)
    uint16_t tunnel_id;     // Tunnel ID
    uint16_t session_id;    // Session ID
    uint16_t ns;            // Sequence number (optional)
    uint16_t nr;            // Next sequence (optional)
    uint16_t offset_size;   // Offset size (optional)
    // Followed by payload
};

struct sniff_mpls {        // RFC: 3032
    uint32_t label_stack_entry; // Label (20 bits), TC (3 bits), S (1 bit), TTL (8 bits)
};

struct sniff_vxlan {       // RFC: 7348 (Virtual eXtensible LAN)
    uint32_t flags;        // Flags (I flag indicates valid VNI)
    uint32_t vni_reserved; // 24-bit VNI | 8-bit reserved
};

struct sniff_nvgre {       // RFC: 7637 (Network Virtualization using GRE)
    uint16_t flags_version; // Flags and version
    uint16_t protocol_type; // Protocol type (0x6558)
    uint16_t tni_hi;        // Upper bits of Tunnel Network Identifier
    uint16_t tni_flowid;    // Lower bits of TNI and flow ID
};

struct sniff_gtpv1 {       // 3GPP TS 29.060 (GPRS Tunneling Protocol v1)
    uint8_t  flags;        // Version, protocol type, etc.
    uint8_t  message_type; // Message type
    uint16_t length;       // Length of payload
    uint32_t teid;         // Tunnel Endpoint ID
    uint16_t seq_number;   // Sequence number (optional)
    uint8_t  n_pdu_number; // N-PDU number (optional)
    uint8_t  next_ext;     // Next extension header type (optional)
};

struct sniff_ipcomp {      // RFC: 3173
    uint8_t  next_header;  // Next header
    uint8_t  flags;        // Flags
    uint16_t cpi;          // Compression Parameter Index
};

struct sniff_beetph {      // RFC: 5566 (BEET Mode IPsec)
    uint8_t  next_header;  // Next header value
    uint8_t  hdr_len;      // Header length in 32-bit words
    uint16_t reserved;     // Reserved
    uint32_t spi;          // Security Parameter Index
    // Followed by optional BEET-specific data
};

struct sniff_ipencap {     // Generic IP-in-IP encapsulation header
    uint16_t reserved;     // Reserved
    uint16_t length;       // Payload length (if used)
};

// -------------------------------------------------------------------------
// IPsec (AH, ESP)
// -------------------------------------------------------------------------
struct sniff_ipsec_ah {    // RFC: 4302
    uint8_t  next_header;   // e.g. 6 for TCP, 17 for UDP
    uint8_t  payload_len;   // AH length in 32-bit words minus 2
    uint16_t reserved;
    uint32_t spi;           // Security Parameter Index
    uint32_t seq_no;        // Sequence number
    // variable Authentication Data
};

struct sniff_ipsec_esp {   // RFC: 4303
    uint32_t spi;     // Security Parameter Index
    uint32_t seq_no;  // Sequence number
    // Encrypted payload (variable), optional padding, etc.
};

struct sniff_dtls {        // RFC: 9147 (Datagram TLS 1.2/1.3 common header)
    uint8_t  content_type; // Handshake, Application Data, etc.
    uint16_t version;      // DTLS version
    uint16_t epoch;        // Epoch
    uint16_t sequence_hi;  // Sequence number high bits
    uint32_t sequence_lo;  // Sequence number low bits
    uint16_t length;       // Length of fragment
};

// -------------------------------------------------------------------------
// BGP (Border Gateway Protocol)
// -------------------------------------------------------------------------
#define BGP_MARKER_LEN 16

struct sniff_bgp {         // RFC: 4271
    u_char marker[BGP_MARKER_LEN]; // Always 0xFF repeated
    u_short length;                // total length of BGP message
    u_char type;                   // 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE
    // Then variable payload depending on type
};

// -------------------------------------------------------------------------
// APPLICATION LAYER (DNS, DHCP, NTP, HTTP basics)
// -------------------------------------------------------------------------
struct sniff_dns {         // RFC: 1035
    u_short id;
    u_short flags;
    u_short q_count;
    u_short ans_count;
    u_short auth_count;
    u_short add_count;
};

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128

struct sniff_dhcp {        // RFC: 2131
    u_char  op;
    u_char  htype;
    u_char  hlen;
    u_char  hops;
    u_int   xid;
    u_short secs;
    u_short flags;
    u_int   ciaddr;
    u_int   yiaddr;
    u_int   siaddr;
    u_int   giaddr;
    u_char  chaddr[DHCP_CHADDR_LEN * 2];
    u_char  sname[DHCP_SNAME_LEN];
    u_char  file[DHCP_FILE_LEN];
    // Then variable DHCP options
};

struct sniff_ntp {         // RFC: 5905 (Network Time Protocol)
    uint8_t  li_vn_mode;   // Leap Indicator, Version, Mode
    uint8_t  stratum;      // Stratum level of the clock
    uint8_t  poll;         // Maximum interval between messages
    uint8_t  precision;    // Precision of the local clock
    uint32_t root_delay;   // Total round-trip delay to primary source
    uint32_t root_dispersion; // Nominal error relative to primary source
    uint32_t ref_id;       // Reference ID
    uint64_t ref_timestamp; // Reference timestamp
    uint64_t orig_timestamp;// Originate timestamp
    uint64_t recv_timestamp;// Receive timestamp
    uint64_t transmit_timestamp; // Transmit timestamp
};

struct sniff_tls_record {  // RFC: 8446 (TLS 1.3 record header)
    uint8_t  content_type; // Handshake, Application Data, etc.
    uint16_t protocol_version; // Legacy version field
    uint16_t length;       // Length of TLS payload
};

struct sniff_tls_handshake { // TLS Handshake header
    uint8_t  handshake_type; // ClientHello, ServerHello, etc.
    uint8_t  length_msb;
    uint8_t  length_mid;
    uint8_t  length_lsb;
};

struct sniff_http_request { // Basic HTTP request-line representation
    const char *method;    // Method (GET, POST, ...)
    const char *uri;       // Request URI
    const char *version;   // HTTP version string
};

struct sniff_http_response { // Basic HTTP status-line representation
    const char *version;   // HTTP version string
    uint16_t status_code;  // Status code
    const char *reason;    // Reason phrase
};

#endif // PROTO_STRUCT_H
