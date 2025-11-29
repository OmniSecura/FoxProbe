#include <QtTest/QtTest>
#include "packets/sniffing.h"
#include "packets/packethelpers.h"
#include "tst_sniffing.h"
#include <netinet/in.h>

// PacketWorker normally relies on Qt's meta-object system for its signal
// implementation. The unit tests only need Sniffing's parsing helpers, so we
// provide a stub to satisfy the linker when Sniffing::packet_callback is
// compiled into the test binary.
class PacketWorker
{
public:
    void newPacket(const QByteArray &, QStringList, int);
};

void PacketWorker::newPacket(const QByteArray &, QStringList, int) {}


static QByteArray tcpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_tcp tcp{};
    tcp.th_sport = htons(1234);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(0);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

static QByteArray udpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_udp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_UDP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_udp udp{};
    udp.uh_sport = htons(1111);
    udp.uh_dport = htons(2222);
    udp.uh_len = htons(sizeof(sniff_udp));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&udp), sizeof(udp));
    return pkt;
}

static QByteArray icmpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_icmp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_ICMP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_icmp icmp{};
    icmp.icmp_type = 8;
    icmp.icmp_code = 0;

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&icmp), sizeof(icmp));
    return pkt;
}

static QByteArray tcpIpv6Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IPV6);

    sniff_ipv6 ip6{};
    ip6.ip6_flow = htonl(6 << 28);
    ip6.ip6_plen = htons(sizeof(sniff_tcp));
    ip6.ip6_nxt = IPPROTO_TCP;
    ip6.ip6_hlim = 64;
    inet_pton(AF_INET6, "2001:db8::1", &ip6.ip6_src);
    inet_pton(AF_INET6, "2001:db8::2", &ip6.ip6_dst);

    sniff_tcp tcp{};
    tcp.th_sport = htons(1234);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(0);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip6), sizeof(ip6));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

static QByteArray arpPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_ARP);

    sniff_arp arp{};
    arp.ar_hrd = htons(1);
    arp.ar_pro = htons(0x0800);
    arp.ar_hln = 6;
    arp.ar_pln = 4;
    arp.ar_op = htons(1);
    memcpy(arp.ar_sha, "\x66\x77\x88\x99\xaa\xbb", 6);
    inet_pton(AF_INET, "192.0.2.1", arp.ar_sip);
    memset(arp.ar_tha, 0, 6);
    inet_pton(AF_INET, "192.0.2.2", arp.ar_tip);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&arp), sizeof(arp));
    return pkt;
}

static QByteArray icmpv6Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IPV6);

    sniff_ipv6 ip6{};
    ip6.ip6_flow = htonl(6 << 28);
    ip6.ip6_plen = htons(sizeof(sniff_icmpv6));
    ip6.ip6_nxt = IPPROTO_ICMPV6;
    ip6.ip6_hlim = 255;
    inet_pton(AF_INET6, "2001:db8::5", &ip6.ip6_src);
    inet_pton(AF_INET6, "2001:db8::6", &ip6.ip6_dst);

    sniff_icmpv6 icmp6{};
    icmp6.icmp6_type = 128;
    icmp6.icmp6_code = 0;
    icmp6.icmp6_cksum = htons(0x1a2b);
    icmp6.icmp6_data.echo.id = htons(0x1234);
    icmp6.icmp6_data.echo.seq = htons(0x0001);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip6), sizeof(ip6));
    pkt.append(reinterpret_cast<const char*>(&icmp6), sizeof(icmp6));
    return pkt;
}

static QByteArray igmpPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x01\x00\x5e\x00\x00\x01", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_ttl = 1;
    ip.ip_p = IPPROTO_IGMP;
    ip.ip_src.s_addr = inet_addr("192.0.2.3");
    ip.ip_dst.s_addr = inet_addr("224.0.0.1");

    sniff_igmpv1v2 igmp{};
    igmp.type = 0x16;
    igmp.mrt = 10;
    igmp.cksum = htons(0xbeef);
    igmp.group_addr.s_addr = inet_addr("239.255.0.1");

    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_igmpv1v2));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&igmp), sizeof(igmp));
    return pkt;
}

static QByteArray sctpPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_p = IPPROTO_SCTP;
    ip.ip_src.s_addr = inet_addr("192.0.2.4");
    ip.ip_dst.s_addr = inet_addr("192.0.2.5");

    sniff_sctp sctp{};
    sctp.src_port = htons(5000);
    sctp.dst_port = htons(6000);
    sctp.verification_tag = htonl(0x01020304);
    sctp.checksum = htonl(0xAABBCCDD);

    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_sctp));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&sctp), sizeof(sctp));
    return pkt;
}

static QByteArray udplitePacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_p = IPPROTO_UDPLITE;
    ip.ip_src.s_addr = inet_addr("192.0.2.7");
    ip.ip_dst.s_addr = inet_addr("192.0.2.8");

    sniff_udplite udplite{};
    udplite.src_port = htons(15000);
    udplite.dst_port = htons(16000);
    udplite.checksum_cov = htons(12);
    udplite.checksum = htons(0x1234);

    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_udplite));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&udplite), sizeof(udplite));
    return pkt;
}

static QByteArray grePacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_p = IPPROTO_GRE;
    ip.ip_src.s_addr = inet_addr("203.0.113.1");
    ip.ip_dst.s_addr = inet_addr("203.0.113.2");

    sniff_gre gre{};
    gre.flags_version = htons(0x2001);
    gre.protocol = htons(ETHERTYPE_IP);

    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_gre));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&gre), sizeof(gre));
    return pkt;
}



static QByteArray httpRequestPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    QByteArray httpPayload("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp) + httpPayload.size());
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_src.s_addr = inet_addr("198.51.100.1");
    ip.ip_dst.s_addr = inet_addr("203.0.113.5");

    sniff_tcp tcp{};
    tcp.th_sport = htons(49152);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1000);
    tcp.th_ack = htonl(1);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_PUSH | TH_ACK;
    tcp.th_win = htons(2048);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    pkt.append(httpPayload);
    return pkt;
}

static QByteArray dnsQueryPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_UDP;
    ip.ip_src.s_addr = inet_addr("198.51.100.2");
    ip.ip_dst.s_addr = inet_addr("203.0.113.8");

    sniff_udp udp{};
    udp.uh_sport = htons(53000);
    udp.uh_dport = htons(53);

    sniff_dns dns{};
    dns.id = htons(0x1a2b);
    dns.flags = htons(0x0100);
    dns.q_count = htons(1);

    QByteArray question;
    question.append(char(0x07));
    question.append("example", 7);
    question.append(char(0x03));
    question.append("com", 3);
    question.append(char(0x00));
    question.append(char(0x00));
    question.append(char(0x01));
    question.append(char(0x00));
    question.append(char(0x01));

    quint16 dnsLen = sizeof(sniff_dns) + question.size();
    udp.uh_len = htons(sizeof(sniff_udp) + dnsLen);

    ip.ip_len = htons(sizeof(sniff_ip) + ntohs(udp.uh_len));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&udp), sizeof(udp));
    pkt.append(reinterpret_cast<const char*>(&dns), sizeof(dns));
    pkt.append(question);
    return pkt;
}

static QByteArray tlsClientHelloPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    QByteArray serverName("example.com");

    QByteArray clientHello;
    clientHello.append(char(0x03));
    clientHello.append(char(0x03));
    clientHello.append(QByteArray(32, '\0'));
    clientHello.append(char(0x00));
    clientHello.append(char(0x00));
    clientHello.append(char(0x02));
    clientHello.append(char(0x13));
    clientHello.append(char(0x01));
    clientHello.append(char(0x01));
    clientHello.append(char(0x00));

    QByteArray extensions;
    QByteArray serverNameExt;
    serverNameExt.append(char(0x00));
    serverNameExt.append(char(0x00));
    serverNameExt.append(char(0x00));
    serverNameExt.append(char(0x10));
    QByteArray serverNameData;
    serverNameData.append(char(0x00));
    serverNameData.append(char(0x0E));
    serverNameData.append(char(0x00));
    serverNameData.append(char((serverName.size() >> 8) & 0xFF));
    serverNameData.append(char(serverName.size() & 0xFF));
    serverNameData.append(serverName);
    serverNameExt.append(serverNameData);
    extensions.append(serverNameExt);

    quint16 extensionsLen = quint16(extensions.size());
    clientHello.append(char((extensionsLen >> 8) & 0xFF));
    clientHello.append(char(extensionsLen & 0xFF));
    clientHello.append(extensions);

    quint32 bodyLen = clientHello.size();
    QByteArray handshake;
    handshake.append(char(0x01));
    handshake.append(char((bodyLen >> 16) & 0xFF));
    handshake.append(char((bodyLen >> 8) & 0xFF));
    handshake.append(char(bodyLen & 0xFF));
    handshake.append(clientHello);

    QByteArray record;
    record.append(char(0x16));
    record.append(char(0x03));
    record.append(char(0x01));
    quint16 recordLen = quint16(handshake.size());
    record.append(char((recordLen >> 8) & 0xFF));
    record.append(char(recordLen & 0xFF));
    record.append(handshake);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp) + record.size());
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_src.s_addr = inet_addr("198.51.100.3");
    ip.ip_dst.s_addr = inet_addr("203.0.113.9");

    sniff_tcp tcp{};
    tcp.th_sport = htons(49153);
    tcp.th_dport = htons(443);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(1);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_PUSH | TH_ACK;
    tcp.th_win = htons(4096);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    pkt.append(record);
    return pkt;
}

void SniffingTest::parseTcpIpv4()
{
    Sniffing s;
    auto pkt = tcpIpv4Packet();
    auto vals = s.parseTcp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(2), QString("1234"));
    QCOMPARE(vals.at(3), QString("80"));
}

void SniffingTest::parseUdpIpv4()
{
    Sniffing s;
    auto pkt = udpIpv4Packet();
    auto vals = s.parseUdp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(2), QString("1111"));
    QCOMPARE(vals.at(3), QString("2222"));
}

void SniffingTest::parseIcmpIpv4()
{
    Sniffing s;
    auto pkt = icmpIpv4Packet();
    auto vals = s.parseIcmp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QString("8"));
    QCOMPARE(vals.at(1), QString("0"));
}

void SniffingTest::parseTcpIpv6()
{
    Sniffing s;
    auto pkt = tcpIpv6Packet();
    auto vals = s.parseTcp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QString("2001:db8::1"));
    QCOMPARE(vals.at(1), QString("2001:db8::2"));
}

void SniffingTest::parseArp()
{
    Sniffing s;
    auto pkt = arpPacket();
    auto vals = s.parseArp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(6), QString("Request"));
}

void SniffingTest::parseHttpRequest()
{
    Sniffing s;
    auto pkt = httpRequestPacket();
    ParsedHttp http = s.parseHttp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QVERIFY(http.valid);
    QVERIFY(http.isRequest);
    QCOMPARE(http.method, QStringLiteral("GET"));
    QCOMPARE(http.target, QStringLiteral("/index.html"));
    QCOMPARE(http.host, QStringLiteral("example.com"));
}

void SniffingTest::parseDnsQuery()
{
    Sniffing s;
    auto pkt = dnsQueryPacket();
    ParsedDns dns = s.parseDns(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QVERIFY(dns.valid);
    QCOMPARE(dns.id, quint16(0x1a2b));
    QVERIFY(!dns.isResponse);
    QCOMPARE(dns.questions.size(), 1);
    const auto &question = dns.questions.first();
    QCOMPARE(question.name, QStringLiteral("example.com"));
    QCOMPARE(question.type, QStringLiteral("A"));
    QCOMPARE(question.klass, QStringLiteral("IN"));
}

void SniffingTest::parseTlsClientHello()
{
    Sniffing s;
    auto pkt = tlsClientHelloPacket();
    ParsedTls tls = s.parseTls(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QVERIFY(tls.valid);
    QCOMPARE(tls.handshakeType, QStringLiteral("ClientHello"));
    QCOMPARE(tls.version, QStringLiteral("TLS 1.2"));
    QVERIFY(tls.isClientHello);
    QCOMPARE(tls.serverName, QStringLiteral("example.com"));
    QVERIFY(tls.cipherSuites.contains(QStringLiteral("TLS_AES_128_GCM_SHA256")));
}

void SniffingTest::parseIcmpv6()
{
    Sniffing s;
    auto pkt = icmpv6Packet();
    auto vals = s.parseIcmpv6(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QStringLiteral("128"));
    QCOMPARE(vals.at(1), QStringLiteral("0"));
    QCOMPARE(vals.at(2), QStringLiteral("0X1A2B"));
    QCOMPARE(vals.at(3), QStringLiteral("4660"));
    QCOMPARE(vals.at(4), QStringLiteral("1"));
    QCOMPARE(vals.at(5), QStringLiteral("Echo Request"));
}

void SniffingTest::parseIgmp()
{
    Sniffing s;
    auto pkt = igmpPacket();
    auto vals = s.parseIgmp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QStringLiteral("22"));
    QCOMPARE(vals.at(1), QStringLiteral("Membership Report v2"));
    QCOMPARE(vals.at(2), QStringLiteral("10"));
    QCOMPARE(vals.at(3), QStringLiteral("0XBEEF"));
    QCOMPARE(vals.at(4), QStringLiteral("239.255.0.1"));
}

void SniffingTest::parseSctp()
{
    Sniffing s;
    auto pkt = sctpPacket();
    auto vals = s.parseSctp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QStringLiteral("5000"));
    QCOMPARE(vals.at(1), QStringLiteral("6000"));
    QCOMPARE(vals.at(2), QStringLiteral("0X01020304"));
    QCOMPARE(vals.at(3), QStringLiteral("0XAABBCCDD"));
}

void SniffingTest::parseUdplite()
{
    Sniffing s;
    auto pkt = udplitePacket();
    auto vals = s.parseUdplite(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QStringLiteral("15000"));
    QCOMPARE(vals.at(1), QStringLiteral("16000"));
    QCOMPARE(vals.at(2), QStringLiteral("12"));
    QCOMPARE(vals.at(3), QStringLiteral("0X1234"));
}

void SniffingTest::parseGre()
{
    Sniffing s;
    auto pkt = grePacket();
    auto vals = s.parseGre(reinterpret_cast<const u_char*>(pkt.constData()), DLT_EN10MB);
    QCOMPARE(vals.at(0), QStringLiteral("0X2001"));
    QCOMPARE(vals.at(1), QStringLiteral("1"));
    QCOMPARE(vals.at(2), QStringLiteral("0X0800"));
}