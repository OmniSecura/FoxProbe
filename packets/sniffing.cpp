#include "sniffing.h"
#include "packethelpers.h"
#include "src/packetworker.h"
#include <ctype.h>
#include <QMutexLocker>
#include <QBitArray>
#include <linux/if_packet.h>
#include <QSet>
#include <algorithm>
#include <netinet/in.h>

namespace {
QString packetTypeToString(uint16_t type) {
    switch (type) {
        case PACKET_HOST:       return QStringLiteral("HOST");
        case PACKET_BROADCAST:  return QStringLiteral("BROADCAST");
        case PACKET_MULTICAST:  return QStringLiteral("MULTICAST");
        case PACKET_OTHERHOST:  return QStringLiteral("OTHERHOST");
        case PACKET_OUTGOING:   return QStringLiteral("OUTGOING");
        case PACKET_FASTROUTE:  return QStringLiteral("FASTROUTE");
        default:
            return QString::number(type);
    }
}

QString cookedAddressToString(const sniff_linux_cooked *hdr) {
    const int addrLen = qMin<int>(ntohs(hdr->addr_len), int(sizeof hdr->addr));
    if (addrLen <= 0)
        return QStringLiteral("-");

    QStringList parts;
    parts.reserve(addrLen);
    for (int i = 0; i < addrLen; ++i) {
        parts << QStringLiteral("%1").arg(hdr->addr[i], 2, 16, QLatin1Char('0')).toUpper();
    }
    return parts.join(QLatin1Char(':'));
}

bool isLikelyHttpPort(quint16 port) {
    switch (port) {
        case 80:
        case 8080:
        case 8000:
        case 8008:
        case 3128:
            return true;
        default:
            return false;
    }
}

bool isLikelyDnsPort(quint16 port) {
    switch (port) {
        case 53:
        case 5353:
            return true;
        default:
            return false;
    }
}

bool isLikelyTlsPort(quint16 port) {
    switch (port) {
        case 443:
        case 853:
        case 8443:
            return true;
        default:
            return false;
    }
}

bool isLikelyHttpMethod(const QByteArray &method) {
    static const QSet<QByteArray> httpMethods = {
        "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS",
        "TRACE", "CONNECT", "PATCH"
    };
    return httpMethods.contains(method.toUpper());
}

QString dnsTypeToString(quint16 type) {
    switch (type) {
        case 1:   return QStringLiteral("A");
        case 2:   return QStringLiteral("NS");
        case 5:   return QStringLiteral("CNAME");
        case 6:   return QStringLiteral("SOA");
        case 12:  return QStringLiteral("PTR");
        case 15:  return QStringLiteral("MX");
        case 16:  return QStringLiteral("TXT");
        case 28:  return QStringLiteral("AAAA");
        case 33:  return QStringLiteral("SRV");
        case 41:  return QStringLiteral("OPT");
        default:  return QStringLiteral("TYPE%1").arg(type);
    }
}

QString dnsClassToString(quint16 klass) {
    switch (klass) {
        case 1:   return QStringLiteral("IN");
        case 3:   return QStringLiteral("CH");
        case 4:   return QStringLiteral("HS");
        default:  return QStringLiteral("CLASS%1").arg(klass);
    }
}

QString tlsContentTypeName(quint8 type) {
    switch (type) {
        case 20: return QStringLiteral("ChangeCipherSpec");
        case 21: return QStringLiteral("Alert");
        case 22: return QStringLiteral("Handshake");
        case 23: return QStringLiteral("ApplicationData");
        case 24: return QStringLiteral("Heartbeat");
        default: return QStringLiteral("0x%1").arg(type, 2, 16, QLatin1Char('0'));
    }
}

QString tlsVersionName(quint16 version) {
    switch (version) {
        case 0x0300: return QStringLiteral("SSL 3.0");
        case 0x0301: return QStringLiteral("TLS 1.0");
        case 0x0302: return QStringLiteral("TLS 1.1");
        case 0x0303: return QStringLiteral("TLS 1.2");
        case 0x0304: return QStringLiteral("TLS 1.3");
        default:     return QStringLiteral("0x%1").arg(version, 4, 16, QLatin1Char('0'));
    }
}

QString tlsHandshakeTypeName(quint8 type) {
    switch (type) {
        case 0:  return QStringLiteral("HelloRequest");
        case 1:  return QStringLiteral("ClientHello");
        case 2:  return QStringLiteral("ServerHello");
        case 4:  return QStringLiteral("NewSessionTicket");
        case 11: return QStringLiteral("Certificate");
        case 12: return QStringLiteral("ServerKeyExchange");
        case 13: return QStringLiteral("CertificateRequest");
        case 14: return QStringLiteral("ServerHelloDone");
        case 16: return QStringLiteral("ClientKeyExchange");
        case 20: return QStringLiteral("Finished");
        default: return QStringLiteral("0x%1").arg(type, 2, 16, QLatin1Char('0'));
    }
}

QString tlsCipherName(quint16 id) {
    switch (id) {
        case 0x0000: return QStringLiteral("TLS_NULL_WITH_NULL_NULL");
        case 0x0035: return QStringLiteral("TLS_RSA_WITH_AES_256_CBC_SHA");
        case 0x003C: return QStringLiteral("TLS_RSA_WITH_AES_128_CBC_SHA256");
        case 0x009C: return QStringLiteral("TLS_RSA_WITH_AES_128_GCM_SHA256");
        case 0x009D: return QStringLiteral("TLS_RSA_WITH_AES_256_GCM_SHA384");
        case 0xC02F: return QStringLiteral("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        case 0xC030: return QStringLiteral("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        case 0xC02B: return QStringLiteral("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        case 0xC02C: return QStringLiteral("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        case 0x1301: return QStringLiteral("TLS_AES_128_GCM_SHA256");
        case 0x1302: return QStringLiteral("TLS_AES_256_GCM_SHA384");
        case 0x1303: return QStringLiteral("TLS_CHACHA20_POLY1305_SHA256");
        default:
            return QStringLiteral("0x%1").arg(id, 4, 16, QLatin1Char('0')).toUpper();
    }
}

QString bytesToHex(const uint8_t *data, int len) {
    QString out;
    out.reserve(len * 2);
    for (int i = 0; i < len; ++i)
        out += QStringLiteral("%1").arg(data[i], 2, 16, QLatin1Char('0')).toUpper();
    return out;
}

QString decodeDnsName(const uint8_t *data, int length, int offset, int &nextOffset, int depth = 0) {
    if (!data || offset < 0 || offset >= length) {
        nextOffset = offset;
        return {};
    }

    QStringList labels;
    int pos = offset;
    bool jumped = false;
    nextOffset = offset;
    const int maxDepth = 8;
    QBitArray visited(length);

    while (pos < length) {
        if (depth > maxDepth)
            break;
        if (visited.testBit(pos)) {
            nextOffset = qMax(nextOffset, pos + 1);
            break;
        }
        visited.setBit(pos);
        quint8 len = data[pos];
        if (len == 0) {
            if (!jumped) {
                ++pos;
                nextOffset = pos;
            }
            else {
                nextOffset = offset + 2;
            }
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= length) {
                nextOffset = qMax(nextOffset, pos + 1);
                break;
            }
            int ptr = ((len & 0x3F) << 8) | data[pos + 1];
            if (ptr < 0 || ptr >= length) {
                nextOffset = qMax(nextOffset, pos + 2);
                break;
            }
            if (visited.testBit(ptr)) {
                nextOffset = qMax(nextOffset, pos + 2);
                break;
            }
            if (!jumped)
                nextOffset = pos + 2;
            pos = ptr;
            jumped = true;
            ++depth;
            continue;
        }
        ++pos;
        if (pos + len > length)
            break;
        labels << QString::fromLatin1(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        if (!jumped)
            nextOffset = pos;
    }

    if (labels.isEmpty())
        return QStringLiteral(".");
    return labels.join(QLatin1Char('.'));
}

QString makeStreamKey(int ipVersion,
                      quint8 protocol,
                      const QByteArray &addrA,
                      quint16 portA,
                      const QByteArray &addrB,
                      quint16 portB)
{
    return QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(protocol)
        .arg(ipVersion)
        .arg(QString::fromLatin1(addrA.toHex().toUpper()))
        .arg(portA)
        .arg(QString::fromLatin1(addrB.toHex().toUpper()))
        .arg(portB);
}

QString ipBytesToString(const QByteArray &addr, int ipVersion)
{
    if (addr.isEmpty())
        return QStringLiteral("-");

    char buffer[INET6_ADDRSTRLEN] = {0};
    switch (ipVersion) {
        case 6:
            if (addr.size() >= int(sizeof(in6_addr))) {
                if (inet_ntop(AF_INET6,
                              reinterpret_cast<const void*>(addr.constData()),
                              buffer,
                              sizeof(buffer)))
                    return QString::fromLatin1(buffer);
            }
            break;
        default:
            if (addr.size() >= int(sizeof(in_addr))) {
                if (inet_ntop(AF_INET,
                              reinterpret_cast<const void*>(addr.constData()),
                              buffer,
                              sizeof(buffer)))
                    return QString::fromLatin1(buffer);
            }
            break;
    }
    return QStringLiteral("-");
}
}

Sniffing::Sniffing() {}
Sniffing::~Sniffing() {}

QString Sniffing::StreamConversation::protocolName() const
{
    switch (protocol) {
        case IPPROTO_TCP:
            return QStringLiteral("TCP");
        case IPPROTO_UDP:
            return QStringLiteral("UDP");
        case IPPROTO_SCTP:
            return QStringLiteral("SCTP");
        case IPPROTO_UDPLITE:
            return QStringLiteral("UDPLITE");
        default:
            return QStringLiteral("IP%1").arg(protocol);
    }
}

QString Sniffing::StreamConversation::label() const
{
    return QStringLiteral("%1 %2:%3 ⇄ %4:%5")
        .arg(protocolName())
        .arg(endpointA.address)
        .arg(endpointA.port)
        .arg(endpointB.address)
        .arg(endpointB.port);
}

void Sniffing::packet_callback(u_char *args,
                               const pcap_pkthdr *header,
                               const u_char *packet)
{
    auto *worker = reinterpret_cast<PacketWorker*>(args);
    QByteArray raw(reinterpret_cast<const char*>(packet),
                   header->caplen);

    CapturedPacket captured{raw, worker ? worker->linkType() : DLT_EN10MB};
    Sniffing::appendPacket(captured);
    Sniffing::recordStreamSegment(raw,
                                  captured.linkType,
                                  header->ts.tv_sec,
                                  header->ts.tv_usec);

    QStringList infos;
    infos << QString::number(header->ts.tv_sec)
          << QString::number(header->caplen);

    emit worker->newPacket(raw, infos, captured.linkType);
}


QString Sniffing::toHexAscii(const u_char *data, int len) const {
    QString out;
    int offset = 0;
    const int line_width = 16;

    while (offset < len) {
        int line_len = qMin(line_width, len - offset);
        const u_char *line = data + offset;

        // Offset
        out += QString("%1   ").arg(offset, 5, 10, QLatin1Char('0'));

        // Hex bytes
        for (int i = 0; i < line_len; ++i) {
            out += QString("%1 ").arg(line[i], 2, 16, QLatin1Char('0')).toUpper();
            if (i == 7) out += " ";
        }

        // Padding for shorter lines
        if (line_len < 8) out += " ";
        if (line_len < line_width) {
            out += QString((line_width - line_len) * 3 + 1, ' ');
        }

        // ASCII characters
        out += "   ";
        for (int i = 0; i < line_len; ++i) {
            char c = isprint(line[i]) ? line[i] : '.';
            out += QChar(c);
        }

        out += "\n";
        offset += line_len;
    }

    return out;
}

// --- simple summary for table ---
QStringList Sniffing::packetSummary(const u_char *packet,
                                    int total_len,
                                    int linkType) const
{
    uint16_t ethertype = ethType(packet, linkType);
    QString src   = "-",
            dst   = "-",
            proto = "OTHER";

    if (ethertype == ETHERTYPE_IP) {
        auto ip  = ipv4Hdr(packet, linkType);

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
        src = QString::fromLatin1(buf);
        inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
        dst = QString::fromLatin1(buf);
        switch (ip->ip_p) {
            case IPPROTO_TCP:    proto = "TCP";     break;
            case IPPROTO_UDP:    proto = "UDP";     break;
            case IPPROTO_ICMP:   proto = "ICMP";    break;
            case IPPROTO_IGMP:   proto = "IGMP";    break;
            case IPPROTO_IPIP:   proto = "IPIP";    break;
            case IPPROTO_EGP:    proto = "EGP";     break;
            case IPPROTO_PUP:    proto = "PUP";     break;
            case IPPROTO_IDP:    proto = "IDP";     break;
            case IPPROTO_TP:     proto = "TP";      break;
            case IPPROTO_RSVP:   proto = "RSVP";    break;
            case IPPROTO_GRE:    proto = "GRE";     break;
            case IPPROTO_ESP:    proto = "ESP";     break;
            case IPPROTO_AH:     proto = "AH";      break;
            case IPPROTO_MTP:    proto = "MTP";     break;
            case IPPROTO_BEETPH: proto = "BEETPH";  break;
            case IPPROTO_ENCAP:  proto = "ENCAP";   break;
            case IPPROTO_PIM:    proto = "PIM";     break;
            case IPPROTO_COMP:   proto = "COMP";    break;
            case IPPROTO_L2TP:   proto = "L2TP";    break;
            case IPPROTO_SCTP:   proto = "SCTP";    break;
            case IPPROTO_UDPLITE:proto = "UDPLITE"; break;
            case IPPROTO_MPLS:   proto = "MPLS";    break;
            case 89:             proto = "OSPF";    break;  
            case 41:             proto = "IPv6";    break;  // IPv6-in-IPv4
            default:             proto = "OTHER";   break;
        }
    }
    else if (ethertype == ETHERTYPE_ARP) {
      auto arpData = parseArp(packet, linkType);
      return { arpData[0], arpData[1], "ARP", QString::number(total_len) };
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(packet, linkType);

        char buf6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6));
        src = QString::fromLatin1(buf6);
        inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6));
        dst = QString::fromLatin1(buf6);

        switch (ip6->ip6_nxt) {
            case IPPROTO_TCP:      proto = "TCP";      break;
            case IPPROTO_UDP:      proto = "UDP";      break;
            case IPPROTO_ICMPV6:   proto = "ICMPv6";   break;
            case IPPROTO_HOPOPTS:  proto = "HOPOPTS";  break;
            case IPPROTO_ROUTING:  proto = "ROUTING";  break;
            case IPPROTO_FRAGMENT: proto = "FRAGMENT"; break;
            case IPPROTO_AH:       proto = "AH";       break;
            case IPPROTO_ESP:      proto = "ESP";      break;
            case IPPROTO_DSTOPTS:  proto = "DSTOPTS";  break;
            case IPPROTO_NONE:     proto = "NONE";     break;
            case IPPROTO_MH:       proto = "MH";       break;
            case IPPROTO_SCTP:     proto = "SCTP";     break;   
            case IPPROTO_UDPLITE:  proto = "UDPLITE";  break;
            case IPPROTO_PIM:      proto = "PIM";      break;
            case IPPROTO_RSVP:     proto = "RSVP";     break;
            default:               proto = "OTHER";    break;
        }
    }

    QString len = QString::number(total_len);

    return { src, dst, proto, len };
}

QStringList Sniffing::parseArp(const u_char *pkt, int linkType) const {
    auto arp = arpHdr(pkt, linkType);

    in_addr sip{}, tip{};
    memcpy(&sip, arp->ar_sip, 4);
    memcpy(&tip, arp->ar_tip, 4);

    QString hrd   = QString::number(ntohs(arp->ar_hrd));
    QString pro   = QString::number(ntohs(arp->ar_pro));
    QString hln   = QString::number(arp->ar_hln);
    QString pln   = QString::number(arp->ar_pln);
    QString op    = (ntohs(arp->ar_op)==1 ? "Request" : "Reply");
    QString sha   = macToStr(arp->ar_sha);
    QString tha   = macToStr(arp->ar_tha);
    QString sipStr = QString::fromUtf8(inet_ntoa(sip));
    QString tipStr = QString::fromUtf8(inet_ntoa(tip));

    return { sipStr, tipStr, hrd, pro, hln, pln, op, sha, tha};
}

QStringList Sniffing::parseTcp(const u_char *pkt, int linkType) const {
    uint16_t ethertype = ethType(pkt, linkType);
    
    const sniff_tcp *tcp = nullptr;
    char buf6[INET6_ADDRSTRLEN];
    char buf[INET_ADDRSTRLEN];

    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt, linkType);
        tcp = tcpHdr(pkt, linkType);
        inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
            src = QString::fromLatin1(buf);
        inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(pkt, linkType);
        tcp = tcp6Hdr(pkt, linkType);
        inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6));
            src = QString::fromLatin1(buf6);
        inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6));
            dst = QString::fromLatin1(buf6);
    } else {
        return {};
    }

    quint16 sport = ntohs(tcp->th_sport);
    quint16 dport = ntohs(tcp->th_dport);
    quint32 seq   = ntohl(tcp->th_seq);
    quint32 ack   = ntohl(tcp->th_ack);
    quint16 win = ntohs(tcp->th_win);
    quint16 sum = ntohs(tcp->th_sum);
    quint16 urp = ntohs(tcp->th_urp);
    int tcpHeaderLenWords = TH_OFF(tcp);    
    int tcpHeaderLenBytes = tcpHeaderLenWords * 4;

    QStringList flagsList;
    quint8 flags = tcp->th_flags;
    if (flags & TH_FIN)  flagsList << "FIN";
    if (flags & TH_SYN)  flagsList << "SYN";
    if (flags & TH_RST)  flagsList << "RST";
    if (flags & TH_PUSH) flagsList << "PSH";
    if (flags & TH_ACK)  flagsList << "ACK";
    if (flags & TH_URG)  flagsList << "URG";
    if (flags & TH_ECE)  flagsList << "ECE";
    if (flags & TH_CWR)  flagsList << "CWR";
    QString flagsStr = flagsList.join("|");

    QStringList out;
    out << src
        << dst
        << QString::number(sport)
        << QString::number(dport)
        << QString::number(seq)
        << QString::number(ack)
        << QString::number(tcpHeaderLenBytes)
        << flagsStr
        << QString::number(win)
        << QString::number(sum)
        << QString::number(urp);
    return out;
}

QStringList Sniffing::parseUdp(const u_char *pkt, int linkType) const {
    uint16_t ethertype = ethType(pkt, linkType);

    const sniff_udp *udp = nullptr;
    char buf[INET_ADDRSTRLEN];
    char buf6[INET6_ADDRSTRLEN];
    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt, linkType);
        udp = udpHdr(pkt, linkType);
        if (inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)))
            src = QString::fromLatin1(buf);
        if (inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)))
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6){
        auto ip6 = ipv6Hdr(pkt, linkType);
        udp = udp6Hdr(pkt, linkType);
        if (inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6)))
            src = QString::fromLatin1(buf6);
        if (inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6)))
            dst = QString::fromLatin1(buf6);
    } else {
        return {};
    }

    quint16 sport = ntohs(udp->uh_sport);
    quint16 dport = ntohs(udp->uh_dport);
    quint32 len   = ntohs(udp->uh_len);
    quint32 sum   = ntohs(udp->uh_sum);

    QStringList out;
    out << src
        << dst
        << QString::number(sport)
        << QString::number(dport)
        << QString::number(len)
        << QString::number(sum);
    return out;
}

QStringList Sniffing::parseIcmp(const u_char *pkt, int linkType) const {
    auto icmp = icmpHdr(pkt, linkType);
    QString message;
    uint8_t type = icmp->icmp_type;
    uint8_t code = icmp->icmp_code;

    uint16_t checksum = icmp->icmp_cksum;
    uint16_t identifier = ntohs(icmp->icmp_id);
    uint16_t sequence = ntohs(icmp->icmp_seq);

    switch (type) {
        case 0: message = "Echo Reply"; break;
        case 3:
            message = "Destination Unreachable";
            switch (code) {
                case 0: message += " (Network Unreachable)"; break;
                case 1: message += " (Host Unreachable)"; break;
                case 2: message += " (Protocol Unreachable)"; break;
                case 3: message += " (Port Unreachable)"; break;
                case 4: message += " (Fragmentation Needed and DF set)"; break;
                case 5: message += " (Source Route Failed)"; break;
                case 6: message += " (Destination Network Unknown)"; break;
                case 7: message += " (Destination Host Unknown)"; break;
                case 8: message += " (Source Host Isolated)"; break;
                case 9: message += " (Network Administratively Prohibited)"; break;
                case 10: message += " (Host Administratively Prohibited)"; break;
                case 11: message += " (Network Unreachable for ToS)"; break;
                case 12: message += " (Host Unreachable for ToS)"; break;
                case 13: message += " (Communication Administratively Prohibited)"; break;
                case 14: message += " (Host Precedence Violation)"; break;
                case 15: message += " (Precedence Cutoff in Effect)"; break;
            }
            break;
        case 4: message = "Source Quench (Deprecated)"; break;
        case 5:
            message = "Redirect";
            switch (code) {
                case 0: message += " (Redirect Datagram for the Network)"; break;
                case 1: message += " (Redirect Datagram for the Host)"; break;
                case 2: message += " (Redirect for ToS & Network)"; break;
                case 3: message += " (Redirect for ToS & Host)"; break;
            }
            break;
        case 8: message = "Echo Request"; break;
        case 9: message = "Router Advertisement"; break;
        case 10: message = "Router Solicitation"; break;
        case 11:
            message = "Time Exceeded";
            switch (code) {
                case 0: message += " (TTL Exceeded in Transit)"; break;
                case 1: message += " (Fragment Reassembly Time Exceeded)"; break;
            }
            break;
        case 12:
            message = "Parameter Problem";
            switch (code) {
                case 0: message += " (Pointer indicates error)"; break;
                case 1: message += " (Missing required option)"; break;
                case 2: message += " (Bad length)"; break;
            }
            break;
        case 13: message = "Timestamp Request"; break;
        case 14: message = "Timestamp Reply"; break;
        case 15: message = "Information Request (Deprecated)"; break;
        case 16: message = "Information Reply (Deprecated)"; break;
        case 17: message = "Address Mask Request"; break;
        case 18: message = "Address Mask Reply"; break;
        case 30: message = "Traceroute (Deprecated)"; break;
        default: message = "Unknown or Reserved"; break;
    }

    
    QStringList out;
    out << QString::number(type)
        << QString::number(code)
        << QStringLiteral("0x%1")
             .arg(checksum, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(identifier)
        << QString::number(sequence)
        << message;

    return out;
}

QStringList Sniffing::parseIcmpv6(const u_char *pkt, int linkType) const {
    auto icmp6 = icmp6Hdr(pkt, linkType);
    if (!icmp6) return {};

    uint8_t type = icmp6->icmp6_type;
    uint8_t code = icmp6->icmp6_code;
    uint16_t checksum = ntohs(icmp6->icmp6_cksum);

    QString message;
    switch (type) {
        case 1:  message = "Destination Unreachable"; break;
        case 2:  message = "Packet Too Big"; break;
        case 3:  message = "Time Exceeded"; break;
        case 4:  message = "Parameter Problem"; break;
        case 128: message = "Echo Request"; break;
        case 129: message = "Echo Reply"; break;
        case 130: message = "Multicast Listener Query"; break;
        case 131: message = "Multicast Listener Report"; break;
        case 132: message = "Multicast Listener Done"; break;
        case 133: message = "Router Solicitation"; break;
        case 134: message = "Router Advertisement"; break;
        case 135: message = "Neighbor Solicitation"; break;
        case 136: message = "Neighbor Advertisement"; break;
        case 137: message = "Redirect"; break;
        default: message = "Unknown"; break;
    }

    uint16_t identifier = 0;
    uint16_t sequence   = 0;
    if (type == 128 || type == 129) {
        identifier = ntohs(icmp6->icmp6_data.echo.id);
        sequence   = ntohs(icmp6->icmp6_data.echo.seq);
    }

    QStringList out;
    out << QString::number(type)
        << QString::number(code)
        << QStringLiteral("0x%1").arg(checksum, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(identifier)
        << QString::number(sequence)
        << message;

    return out;
}

QStringList Sniffing::parseIgmp(const u_char *pkt, int linkType) const {
    auto igmp = reinterpret_cast<const sniff_igmpv1v2*>(ipv4Payload(pkt, linkType));
    if (!igmp) return {};

    uint8_t type = igmp->type;
    QString typeName;
    switch (type) {
        case 0x11: typeName = "Membership Query"; break;
        case 0x12: typeName = "Membership Report v1"; break;
        case 0x16: typeName = "Membership Report v2"; break;
        case 0x17: typeName = "Leave Group"; break;
        default:   typeName = "Unknown"; break;
    }

    QString groupAddr = QString::fromLatin1(inet_ntoa(igmp->group_addr));

    QStringList out;
    out << QString::number(type)
        << typeName
        << QString::number(igmp->mrt)
        << QStringLiteral("0x%1").arg(ntohs(igmp->cksum), 4, 16, QLatin1Char('0')).toUpper()
        << groupAddr;

    return out;
}

QStringList Sniffing::parseSctp(const u_char *pkt, int linkType) const {
    const sniff_sctp *sctp = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        sctp = reinterpret_cast<const sniff_sctp*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        sctp = reinterpret_cast<const sniff_sctp*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!sctp) return {};

    QStringList out;
    out << QString::number(ntohs(sctp->src_port))
        << QString::number(ntohs(sctp->dst_port))
        << QStringLiteral("0x%1").arg(ntohl(sctp->verification_tag), 8, 16, QLatin1Char('0')).toUpper()
        << QStringLiteral("0x%1").arg(ntohl(sctp->checksum), 8, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseUdplite(const u_char *pkt, int linkType) const {
    const sniff_udplite *udplite = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        udplite = reinterpret_cast<const sniff_udplite*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        udplite = reinterpret_cast<const sniff_udplite*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!udplite) return {};

    QStringList out;
    out << QString::number(ntohs(udplite->src_port))
        << QString::number(ntohs(udplite->dst_port))
        << QString::number(ntohs(udplite->checksum_cov))
        << QStringLiteral("0x%1").arg(ntohs(udplite->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseGre(const u_char *pkt, int linkType) const {
    const sniff_gre *gre = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        gre = reinterpret_cast<const sniff_gre*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        gre = reinterpret_cast<const sniff_gre*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!gre) return {};

    uint16_t flagsVersion = ntohs(gre->flags_version);
    uint16_t protocol     = ntohs(gre->protocol);
    uint8_t version       = flagsVersion & 0x7;

    QStringList out;
    out << QStringLiteral("0x%1").arg(flagsVersion, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(version)
        << QStringLiteral("0x%1").arg(protocol, 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseOspf(const u_char *pkt, int linkType) const {
    auto ospf = reinterpret_cast<const sniff_ospf*>(ipv4Payload(pkt, linkType));
    if (!ospf) return {};

    QStringList out;
    out << QString::number(ospf->version)
        << QString::number(ospf->type)
        << QString::number(ntohs(ospf->length))
        << QString::fromLatin1(inet_ntoa(ospf->router_id))
        << QString::fromLatin1(inet_ntoa(ospf->area_id))
        << QStringLiteral("0x%1").arg(ntohs(ospf->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohs(ospf->autype));

    return out;
}

QStringList Sniffing::parseRsvp(const u_char *pkt, int linkType) const {
    const sniff_rsvp *rsvp = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        rsvp = reinterpret_cast<const sniff_rsvp*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        rsvp = reinterpret_cast<const sniff_rsvp*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!rsvp) return {};

    QStringList out;
    out << QString::number(rsvp->ver_flags >> 4)
        << QString::number(rsvp->msg_type)
        << QStringLiteral("0x%1").arg(ntohs(rsvp->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(rsvp->send_ttl)
        << QString::number(ntohs(rsvp->length));

    return out;
}

QStringList Sniffing::parsePim(const u_char *pkt, int linkType) const {
    const sniff_pim *pim = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        pim = reinterpret_cast<const sniff_pim*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        pim = reinterpret_cast<const sniff_pim*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!pim) return {};

    uint8_t version = pim->ver_type >> 4;
    uint8_t type    = pim->ver_type & 0x0F;

    QStringList out;
    out << QString::number(version)
        << QString::number(type)
        << QStringLiteral("0x%1").arg(ntohs(pim->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseEgp(const u_char *pkt, int linkType) const {
    auto egp = reinterpret_cast<const sniff_egp*>(ipv4Payload(pkt, linkType));
    if (!egp) return {};

    QStringList out;
    out << QString::number(egp->version)
        << QString::number(egp->type)
        << QString::number(egp->code)
        << QString::number(egp->status)
        << QStringLiteral("0x%1").arg(ntohs(egp->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohs(egp->autonomous_system))
        << QString::number(ntohs(egp->sequence));

    return out;
}

QStringList Sniffing::parseAh(const u_char *pkt, int linkType) const {
    const sniff_ipsec_ah *ah = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        ah = reinterpret_cast<const sniff_ipsec_ah*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        ah = reinterpret_cast<const sniff_ipsec_ah*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!ah) return {};

    QStringList out;
    out << QString::number(ah->next_header)
        << QString::number(ah->payload_len)
        << QStringLiteral("0x%1").arg(ntohl(ah->spi), 8, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohl(ah->seq_no));

    return out;
}

QStringList Sniffing::parseEsp(const u_char *pkt, int linkType) const {
    const sniff_ipsec_esp *esp = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        esp = reinterpret_cast<const sniff_ipsec_esp*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        esp = reinterpret_cast<const sniff_ipsec_esp*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!esp) return {};

    QStringList out;
    out << QStringLiteral("0x%1").arg(ntohl(esp->spi), 8, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohl(esp->seq_no));

    return out;
}

QStringList Sniffing::parseMpls(const u_char *pkt, int linkType) const {
    const sniff_mpls *mpls = nullptr;
    uint16_t ethertype = ethType(pkt, linkType);

    if (ethertype == ETHERTYPE_IP) {
        mpls = reinterpret_cast<const sniff_mpls*>(ipv4Payload(pkt, linkType));
    } else if (ethertype == ETHERTYPE_IPV6) {
        mpls = reinterpret_cast<const sniff_mpls*>(ipv6Payload(pkt, linkType));
    } else {
        return {};
    }

    if (!mpls) return {};

    uint32_t entry = ntohl(mpls->label_stack_entry);
    uint32_t label = entry >> 12;
    uint8_t tc     = (entry >> 9) & 0x07;
    uint8_t s      = (entry >> 8) & 0x01;
    uint8_t ttl    = entry & 0xFF;

    QStringList out;
    out << QString::number(label)
        << QString::number(tc)
        << QString::number(s)
        << QString::number(ttl);

    return out;
}

QStringList Sniffing::parseIpip(const u_char *pkt, int linkType) const {
    auto innerIp = reinterpret_cast<const sniff_ip*>(ipv4Payload(pkt, linkType));
    if (!innerIp) return {};

    QStringList out;
    out << QString::fromLatin1(inet_ntoa(innerIp->ip_src))
        << QString::fromLatin1(inet_ntoa(innerIp->ip_dst))
        << QString::number(innerIp->ip_p)
        << QString::number(ntohs(innerIp->ip_len));

    return out;
}

QStringList Sniffing::parseIpv6HopByHop(const u_char *pkt, int linkType) const {
    auto hop = reinterpret_cast<const sniff_ipv6_hopopts*>(ipv6Payload(pkt, linkType));
    if (!hop) return {};

    QStringList out;
    out << QString::number(hop->next_header)
        << protoName(hop->next_header)
        << QString::number(hop->hdr_ext_len);

    return out;
}

QStringList Sniffing::parseIpv6Routing(const u_char *pkt, int linkType) const {
    auto routing = reinterpret_cast<const sniff_ipv6_routing*>(ipv6Payload(pkt, linkType));
    if (!routing) return {};

    QStringList out;
    out << QString::number(routing->next_header)
        << protoName(routing->next_header)
        << QString::number(routing->routing_type)
        << QString::number(routing->segments_left);

    return out;
}

QStringList Sniffing::parseIpv6Fragment(const u_char *pkt, int linkType) const {
    auto frag = reinterpret_cast<const sniff_ipv6_fragment*>(ipv6Payload(pkt, linkType));
    if (!frag) return {};

    uint16_t offsetField = ntohs(frag->frag_offset);
    uint16_t offset = (offsetField >> 3) & 0x1FFF;
    bool moreFragments = offsetField & 0x1;

    QStringList out;
    out << QString::number(frag->next_header)
        << protoName(frag->next_header)
        << QString::number(offset)
        << (moreFragments ? "Yes" : "No")
        << QStringLiteral("0x%1").arg(ntohl(frag->identification), 8, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseIpv6Destination(const u_char *pkt, int linkType) const {
    auto dest = reinterpret_cast<const sniff_ipv6_dstopts*>(ipv6Payload(pkt, linkType));
    if (!dest) return {};

    QStringList out;
    out << QString::number(dest->next_header)
        << protoName(dest->next_header)
        << QString::number(dest->hdr_ext_len);

    return out;
}

QStringList Sniffing::parseIpv6Mobility(const u_char *pkt, int linkType) const {
    auto mobility = reinterpret_cast<const sniff_ipv6_mobility*>(ipv6Payload(pkt, linkType));
    if (!mobility) return {};

    QStringList out;
    out << QString::number(mobility->next_header)
        << protoName(mobility->next_header)
        << QString::number(mobility->mh_type)
        << QStringLiteral("0x%1").arg(ntohs(mobility->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

ParsedHttp Sniffing::parseHttp(const u_char *pkt, int linkType) const {
    ParsedHttp result;
    auto segment = tcpSegmentView(pkt, linkType);
    if (!segment.header || segment.payloadLength <= 0)
        return result;

    quint16 sport = ntohs(segment.header->th_sport);
    quint16 dport = ntohs(segment.header->th_dport);
    QByteArray payload(reinterpret_cast<const char*>(segment.payload), segment.payloadLength);

    int headerEnd = payload.indexOf("\r\n\r\n");
    if (headerEnd == -1)
        headerEnd = payload.size();
    if (headerEnd <= 0)
        return result;

    QByteArray headerSection = payload.left(headerEnd);
    QList<QByteArray> lines = headerSection.split('\n');
    if (lines.isEmpty())
        return result;

    QByteArray firstLine = lines.takeFirst().trimmed();
    if (firstLine.isEmpty())
        return result;

    bool portMatch = isLikelyHttpPort(sport) || isLikelyHttpPort(dport);
    bool isResponse = firstLine.startsWith("HTTP/");
    bool isRequest = false;

    if (!isResponse) {
        int spaceIdx = firstLine.indexOf(' ');
        if (spaceIdx > 0)
            isRequest = isLikelyHttpMethod(firstLine.left(spaceIdx));
    }

    if (!portMatch && !isRequest && !isResponse)
        return result;

    if (isResponse) {
        int firstSpace = firstLine.indexOf(' ');
        if (firstSpace <= 0)
            return result;
        int secondSpace = firstLine.indexOf(' ', firstSpace + 1);
        if (secondSpace <= firstSpace)
            secondSpace = firstLine.size();

        QByteArray version = firstLine.left(firstSpace);
        QByteArray statusBytes = firstLine.mid(firstSpace + 1, secondSpace - firstSpace - 1);
        QByteArray reasonBytes = secondSpace < firstLine.size()
                ? firstLine.mid(secondSpace + 1).trimmed()
                : QByteArray();

        bool ok = false;
        int statusCode = statusBytes.toInt(&ok);
        if (!ok)
            return result;

        result.valid = true;
        result.isRequest = false;
        result.version = QString::fromLatin1(version);
        result.statusCode = statusCode;
        result.reason = QString::fromLatin1(reasonBytes);
    }
    else if (isRequest) {
        int firstSpace = firstLine.indexOf(' ');
        int secondSpace = firstLine.indexOf(' ', firstSpace + 1);
        if (firstSpace <= 0 || secondSpace <= firstSpace)
            return result;

        QByteArray method = firstLine.left(firstSpace);
        QByteArray target = firstLine.mid(firstSpace + 1, secondSpace - firstSpace - 1);
        QByteArray version = firstLine.mid(secondSpace + 1).trimmed();
        if (!version.startsWith("HTTP/"))
            return result;

        result.valid = true;
        result.isRequest = true;
        result.method = QString::fromLatin1(method);
        result.target = QString::fromLatin1(target);
        result.version = QString::fromLatin1(version);
    }
    else {
        return result;
    }

    for (QByteArray &rawLine : lines) {
        QByteArray line = rawLine.trimmed();
        if (line.endsWith('\r'))
            line.chop(1);
        if (line.isEmpty())
            continue;
        int sep = line.indexOf(':');
        if (sep <= 0)
            continue;

        QByteArray name = line.left(sep).trimmed();
        QByteArray value = line.mid(sep + 1).trimmed();
        HttpHeader header{QString::fromLatin1(name), QString::fromLatin1(value)};
        result.headers.append(header);
        if (name.compare("Host", Qt::CaseInsensitive) == 0)
            result.host = header.value;
    }

    return result;
}


ParsedDns Sniffing::parseDns(const u_char *pkt, int linkType) const {
    ParsedDns result;
    auto udpView = udpDatagramView(pkt, linkType);
    QByteArray payload;
    bool fromTcp = false;

    if (udpView.header && udpView.payloadLength > 0) {
        quint16 sport = ntohs(udpView.header->uh_sport);
        quint16 dport = ntohs(udpView.header->uh_dport);
        bool likelyPort = isLikelyDnsPort(sport) || isLikelyDnsPort(dport);
        if (!likelyPort)
            return result;
        payload = QByteArray(reinterpret_cast<const char*>(udpView.payload), udpView.payloadLength);
    }
    else {
        auto tcpView = tcpSegmentView(pkt, linkType);
        if (!tcpView.header || tcpView.payloadLength <= 2)
            return result;
        quint16 sport = ntohs(tcpView.header->th_sport);
        quint16 dport = ntohs(tcpView.header->th_dport);
        bool likelyPort = isLikelyDnsPort(sport) || isLikelyDnsPort(dport);
        if (!likelyPort)
            return result;
        payload = QByteArray(reinterpret_cast<const char*>(tcpView.payload), tcpView.payloadLength);
        fromTcp = true;
    }

    if (payload.isEmpty())
        return result;

    const uint8_t *raw = reinterpret_cast<const uint8_t*>(payload.constData());
    int rawLen = payload.size();
    int offset = 0;

    if (fromTcp) {
        if (rawLen < 2)
            return result;
        int announced = (raw[0] << 8) | raw[1];
        offset = 2;
        if (announced > rawLen - offset)
            announced = rawLen - offset;
        rawLen = offset + announced;
    }

    const uint8_t *dnsData = raw + offset;
    int dnsLen = rawLen - offset;
    if (dnsLen < int(sizeof(sniff_dns)))
        return result;

    const sniff_dns *hdr = reinterpret_cast<const sniff_dns*>(dnsData);
    result.id = ntohs(hdr->id);
    uint16_t flags = ntohs(hdr->flags);
    result.isResponse = flags & 0x8000;
    result.opcode = (flags >> 11) & 0x0F;
    result.authoritative = flags & 0x0400;
    result.truncated = flags & 0x0200;
    result.rcode = flags & 0x000F;
    result.recursionDesired = flags & 0x0100;
    result.recursionAvailable = flags & 0x0080;
    result.authenticatedData = flags & 0x0020;
    result.checkingDisabled = flags & 0x0010;

    int qdcount = ntohs(hdr->q_count);
    int ancount = ntohs(hdr->ans_count);
    int nscount = ntohs(hdr->auth_count);
    int arcount = ntohs(hdr->add_count);

    int pos = sizeof(sniff_dns);
    auto hasBytes = [&](int needed) { return pos + needed <= dnsLen; };

    for (int i = 0; i < qdcount && pos < dnsLen; ++i) {
        int next = pos;
        QString name = decodeDnsName(dnsData, dnsLen, pos, next);
        if (next > dnsLen)
            break;
        pos = next;
        if (!hasBytes(4))
            break;
        quint16 qtype = (dnsData[pos] << 8) | dnsData[pos + 1];
        quint16 qclass = (dnsData[pos + 2] << 8) | dnsData[pos + 3];
        pos += 4;

        DnsQuestion q;
        q.name = name;
        q.type = dnsTypeToString(qtype);
        q.klass = dnsClassToString(qclass);
        result.questions.append(q);
    }

    auto parseRecords = [&](int count, QVector<DnsRecord> &bucket) {
        for (int i = 0; i < count && pos < dnsLen; ++i) {
            int nameNext = pos;
            QString name = decodeDnsName(dnsData, dnsLen, pos, nameNext);
            if (nameNext > dnsLen)
                return;
            pos = nameNext;
            if (!hasBytes(10))
                return;

            quint16 type = (dnsData[pos] << 8) | dnsData[pos + 1];
            quint16 klass = (dnsData[pos + 2] << 8) | dnsData[pos + 3];
            quint32 ttl = (quint32(dnsData[pos + 4]) << 24)
                        | (quint32(dnsData[pos + 5]) << 16)
                        | (quint32(dnsData[pos + 6]) << 8)
                        | quint32(dnsData[pos + 7]);
            quint16 rdlen = (dnsData[pos + 8] << 8) | dnsData[pos + 9];
            pos += 10;
            if (!hasBytes(rdlen))
                return;

            const uint8_t *rdata = dnsData + pos;
            QString dataStr;

            switch (type) {
                case 1: {
                    if (rdlen == 4) {
                        char buf[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, rdata, buf, sizeof(buf)))
                            dataStr = QString::fromLatin1(buf);
                    }
                    break;
                }
                case 28: {
                    if (rdlen == 16) {
                        char buf6[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, rdata, buf6, sizeof(buf6)))
                            dataStr = QString::fromLatin1(buf6);
                    }
                    break;
                }
                case 2:
                case 5:
                case 12:
                case 39: {
                    int nameOffset = pos;
                    int tmp = 0;
                    dataStr = decodeDnsName(dnsData, dnsLen, nameOffset, tmp);
                    break;
                }
                case 6: {
                    int mnameOffset = pos;
                    int tmp = 0;
                    QString mname = decodeDnsName(dnsData, dnsLen, mnameOffset, tmp);
                    int rnameOffset = pos + (tmp - pos);
                    tmp = 0;
                    QString rname = decodeDnsName(dnsData, dnsLen, rnameOffset, tmp);
                    if (rdlen >= (tmp - pos) + 20) {
                        int numericOffset = pos + (tmp - pos);
                        quint32 serial = (quint32(dnsData[numericOffset]) << 24)
                                       | (quint32(dnsData[numericOffset + 1]) << 16)
                                       | (quint32(dnsData[numericOffset + 2]) << 8)
                                       | quint32(dnsData[numericOffset + 3]);
                        dataStr = QStringLiteral("%1 %2 serial %3").arg(mname, rname, QString::number(serial));
                    } else {
                        dataStr = QStringLiteral("%1 %2").arg(mname, rname);
                    }
                    break;
                }
                case 15: {
                    if (rdlen >= 2) {
                        quint16 pref = (rdata[0] << 8) | rdata[1];
                        int nameOffset = pos + 2;
                        int tmp = 0;
                        QString exchanger = decodeDnsName(dnsData, dnsLen, nameOffset, tmp);
                        dataStr = QStringLiteral("pref %1 %2").arg(pref).arg(exchanger);
                    }
                    break;
                }
                case 16: {
                    QStringList parts;
                    int idx = 0;
                    while (idx < rdlen) {
                        quint8 txtLen = rdata[idx++];
                        if (idx + txtLen > rdlen)
                            break;
                        parts << QString::fromLatin1(reinterpret_cast<const char*>(rdata + idx), txtLen);
                        idx += txtLen;
                    }
                    dataStr = parts.join(QStringLiteral(" "));
                    break;
                }
                case 33: {
                    if (rdlen >= 6) {
                        quint16 priority = (rdata[0] << 8) | rdata[1];
                        quint16 weight = (rdata[2] << 8) | rdata[3];
                        quint16 port = (rdata[4] << 8) | rdata[5];
                        int nameOffset = pos + 6;
                        int tmp = 0;
                        QString target = decodeDnsName(dnsData, dnsLen, nameOffset, tmp);
                        dataStr = QStringLiteral("prio %1 w %2 port %3 %4")
                                      .arg(priority)
                                      .arg(weight)
                                      .arg(port)
                                      .arg(target);
                    }
                    break;
                }
                default:
                    dataStr = QStringLiteral("0x%1").arg(bytesToHex(rdata, rdlen));
                    break;
            }

            DnsRecord record;
            record.name = name;
            record.type = dnsTypeToString(type);
            record.klass = dnsClassToString(klass);
            record.ttl = ttl;
            record.data = dataStr;
            bucket.append(record);
            pos += rdlen;
        }
    };

    parseRecords(ancount, result.answers);
    parseRecords(nscount, result.authorities);
    parseRecords(arcount, result.additionals);

    result.valid = true;
    return result;
}


ParsedTls Sniffing::parseTls(const u_char *pkt, int linkType) const {
    ParsedTls result;
    auto segment = tcpSegmentView(pkt, linkType);
    if (!segment.header || segment.payloadLength < 5)
        return result;

    quint16 sport = ntohs(segment.header->th_sport);
    quint16 dport = ntohs(segment.header->th_dport);
    bool portLikely = isLikelyTlsPort(sport) || isLikelyTlsPort(dport);

    const uint8_t *data = segment.payload;
    int length = segment.payloadLength;

    quint8 contentType = data[0];
    quint16 version = (data[1] << 8) | data[2];
    quint16 recordLen = (data[3] << 8) | data[4];

    if (!portLikely && contentType != 22)
        return result;

    if (recordLen + 5 > length)
        recordLen = length - 5;

    result.recordType = tlsContentTypeName(contentType);
    result.version = tlsVersionName(version);

    if (contentType != 22 || recordLen < 4)
        return result;

    const uint8_t *handshake = data + 5;
    int remaining = qMin<int>(int(recordLen), length - 5);
    if (remaining < 4)
        return result;

    quint8 handshakeType = handshake[0];
    int handshakeLen = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
    if (handshakeLen + 4 > remaining)
        handshakeLen = remaining - 4;

    result.handshakeType = tlsHandshakeTypeName(handshakeType);
    const uint8_t *body = handshake + 4;
    int bodyLen = qMin(handshakeLen, remaining - 4);

    if (handshakeType == 1 && bodyLen >= 38) {
        result.isClientHello = true;
        int offset = 0;
        quint16 clientVersion = (body[offset] << 8) | body[offset + 1];
        offset += 2;
        result.version = tlsVersionName(clientVersion);

        if (offset + 32 > bodyLen)
            return result;
        offset += 32;

        if (offset + 1 > bodyLen)
            return result;
        quint8 sessionIdLen = body[offset];
        offset += 1;
        if (offset + sessionIdLen > bodyLen)
            return result;
        offset += sessionIdLen;

        if (offset + 2 > bodyLen)
            return result;
        quint16 cipherLen = (body[offset] << 8) | body[offset + 1];
        offset += 2;
        if (offset + cipherLen > bodyLen)
            return result;

        QStringList suites;
        for (int i = 0; i + 1 < cipherLen; i += 2) {
            quint16 cs = (body[offset + i] << 8) | body[offset + i + 1];
            suites << tlsCipherName(cs);
        }
        result.cipherSuites = suites;
        offset += cipherLen;

        if (offset + 1 > bodyLen)
            return result;
        quint8 compressionLen = body[offset];
        offset += 1;
        if (offset + compressionLen > bodyLen)
            return result;
        offset += compressionLen;

        if (offset + 2 > bodyLen) {
            result.valid = true;
            return result;
        }

        quint16 extensionsLen = (body[offset] << 8) | body[offset + 1];
        offset += 2;
        if (offset + extensionsLen > bodyLen)
            extensionsLen = bodyLen - offset;

        int extEnd = offset + extensionsLen;
        while (offset + 4 <= extEnd) {
            quint16 extType = (body[offset] << 8) | body[offset + 1];
            quint16 extSize = (body[offset + 2] << 8) | body[offset + 3];
            offset += 4;
            if (offset + extSize > extEnd)
                break;

            if (extType == 0 && extSize >= 3) {
                quint16 listLen = (body[offset] << 8) | body[offset + 1];
                int namePos = offset + 2;
                if (namePos + listLen <= offset + extSize) {
                    while (namePos + 3 <= offset + extSize) {
                        quint8 nameType = body[namePos];
                        quint16 nameLen = (body[namePos + 1] << 8) | body[namePos + 2];
                        namePos += 3;
                        if (namePos + nameLen > offset + extSize)
                            break;
                        if (nameType == 0) {
                            result.serverName = QString::fromLatin1(reinterpret_cast<const char*>(body + namePos), nameLen);
                            break;
                        }
                        namePos += nameLen;
                    }
                }
            }

            offset += extSize;
        }

        result.valid = true;
        return result;
    }

    if (handshakeType == 2 && bodyLen >= 38) {
        int offset = 0;
        quint16 serverVersion = (body[offset] << 8) | body[offset + 1];
        offset += 2;
        result.version = tlsVersionName(serverVersion);

        if (offset + 32 > bodyLen)
            return result;
        offset += 32;

        if (offset + 1 > bodyLen)
            return result;
        quint8 sessionIdLen = body[offset];
        offset += 1;
        if (offset + sessionIdLen > bodyLen)
            return result;
        offset += sessionIdLen;

        if (offset + 2 > bodyLen)
            return result;
        quint16 selected = (body[offset] << 8) | body[offset + 1];
        offset += 2;
        result.selectedCipher = tlsCipherName(selected);

        if (offset + 1 > bodyLen)
            return result;
        quint8 compression = body[offset];
        (void)compression;
        offset += 1;

        if (offset + 2 <= bodyLen) {
            quint16 extensionsLen = (body[offset] << 8) | body[offset + 1];
            offset += 2;
            if (offset + extensionsLen > bodyLen)
                extensionsLen = bodyLen - offset;
            offset += extensionsLen;
        }

        result.valid = true;
        return result;
    }

    if (portLikely)
        result.valid = true;

    return result;
}


QVector<PacketLayer> Sniffing::parseLayers(const u_char* pkt, int linkType) const {
    QVector<PacketLayer> layers;
    ProtoField field;

    if (linkType == DLT_LINUX_SLL) {
        const auto cooked = cookedHdr(pkt);
        PacketLayer cookedLayer;
        cookedLayer.name = QStringLiteral("Linux Cooked Capture");

        field.category = QStringLiteral("Pseudo Header");
        field.label    = QStringLiteral("Packet Type");
        field.value    = packetTypeToString(ntohs(cooked->packet_type));
        cookedLayer.fields.append(field);

        field.label    = QStringLiteral("ARPHRD Type");
        field.value    = QString::number(ntohs(cooked->arphrd_type));
        cookedLayer.fields.append(field);

        field.label    = QStringLiteral("Address");
        field.value    = cookedAddressToString(cooked);
        cookedLayer.fields.append(field);

        field.label    = QStringLiteral("Address Length");
        field.value    = QString::number(ntohs(cooked->addr_len));
        cookedLayer.fields.append(field);

        field.label    = QStringLiteral("Protocol");
        field.value    = QStringLiteral("0x%1")
                          .arg(ntohs(cooked->protocol), 4, 16, QLatin1Char('0'));
        cookedLayer.fields.append(field);

        layers.append(cookedLayer);
    }
    else {
        const auto eth = ethHdr(pkt);
        PacketLayer ethLayer;
        ethLayer.name = QStringLiteral("Ethernet II");

        field.category = QStringLiteral("Frame Header");
        field.label    = QStringLiteral("Src");
        field.value    = macToStr(eth->ether_shost);
        ethLayer.fields.append(field);

        field.label    = QStringLiteral("Dst");
        field.value    = macToStr(eth->ether_dhost);
        ethLayer.fields.append(field);

        field.label    = QStringLiteral("Type");
        field.value    = QStringLiteral("0x%1")
                           .arg(ntohs(eth->ether_type), 4, 16, QLatin1Char('0'));
        ethLayer.fields.append(field);

        layers.append(ethLayer);
    }

    uint16_t et = ethType(pkt, linkType);

    // --- IPv4 ---
    if (et == ETHERTYPE_IP) {
        const auto ip = ipv4Hdr(pkt, linkType);
        PacketLayer ipLayer;
        ipLayer.name = "Internet Protocol Version 4";

        field.category = "IP Header";
        field.label    = "Src";
        field.value    = QString::fromLatin1(inet_ntoa(ip->ip_src));
        ipLayer.fields.append(field);

        field.label    = "Dst";
        field.value    = QString::fromLatin1(inet_ntoa(ip->ip_dst));
        ipLayer.fields.append(field);

        field.label    = "Protocol";
        field.value    = protoName(ip->ip_p);
        ipLayer.fields.append(field);

        layers.append(ipLayer);

        // --- TCP ---
        if (ip->ip_p == IPPROTO_TCP) {
            auto vals = parseTcp(pkt, linkType);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Sequence number","ACK number","TCP header length","Flags",
                "Window size","Checksum","Urgent pointer"
            };
            PacketLayer tcpLayer;
            tcpLayer.name = "Transmission Control Protocol";

            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                // different category for flags
                if (labels[i] == "Sender IP" ||
                    labels[i] == "Target IP" ||
                    labels[i] == "Source port" ||
                    labels[i] == "Destination port")
                {
                    field.category = "Connection";
                }
                else if (labels[i] == "Sequence number" ||
                        labels[i] == "ACK number")
                {
                    field.category = "Sequence";
                }
                else {
                    field.category = "Control";
                }
                field.label    = labels[i];
                field.value    = vals[i];
                tcpLayer.fields.append(field);
            }
            layers.append(tcpLayer);

            auto http = parseHttp(pkt, linkType);
            if (http.valid) {
                PacketLayer httpLayer;
                httpLayer.name = QStringLiteral("Hypertext Transfer Protocol");

                if (http.isRequest) {
                    field.category = QStringLiteral("Request");
                    field.label = QStringLiteral("Method");
                    field.value = http.method;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Target");
                    field.value = http.target;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Version");
                    field.value = http.version;
                    httpLayer.fields.append(field);

                    if (!http.host.isEmpty()) {
                        field.label = QStringLiteral("Host");
                        field.value = http.host;
                        httpLayer.fields.append(field);
                    }
                } else {
                    field.category = QStringLiteral("Response");
                    field.label = QStringLiteral("Version");
                    field.value = http.version;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Status");
                    field.value = QString::number(http.statusCode);
                    httpLayer.fields.append(field);

                    if (!http.reason.isEmpty()) {
                        field.label = QStringLiteral("Reason");
                        field.value = http.reason;
                        httpLayer.fields.append(field);
                    }
                }

                for (const auto &hdr : http.headers) {
                    field.category = QStringLiteral("Headers");
                    field.label = hdr.name;
                    field.value = hdr.value;
                    httpLayer.fields.append(field);
                }

                layers.append(httpLayer);
            }
            else {
                auto tls = parseTls(pkt, linkType);
                if (tls.valid) {
                    PacketLayer tlsLayer;
                    tlsLayer.name = QStringLiteral("Transport Layer Security");

                    field.category = QStringLiteral("Record");
                    field.label = QStringLiteral("Content Type");
                    field.value = tls.recordType;
                    tlsLayer.fields.append(field);

                    field.label = QStringLiteral("Version");
                    field.value = tls.version;
                    tlsLayer.fields.append(field);

                    if (!tls.handshakeType.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Type");
                        field.value = tls.handshakeType;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.serverName.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Server Name");
                        field.value = tls.serverName;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.selectedCipher.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Cipher");
                        field.value = tls.selectedCipher;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.cipherSuites.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Cipher Suites");
                        field.value = tls.cipherSuites.join(QStringLiteral(", "));
                        tlsLayer.fields.append(field);
                    }

                    layers.append(tlsLayer);
                }
            }
        }
        // --- UDP ---
        else if (ip->ip_p == IPPROTO_UDP) {
            auto vals = parseUdp(pkt, linkType);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Length","Checksum"
            };
            PacketLayer udpLayer;
            udpLayer.name = "User Datagram Protocol";
            field.category = "UDP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udpLayer.fields.append(field);
            }
            layers.append(udpLayer);

            auto dns = parseDns(pkt, linkType);
            if (dns.valid) {
                PacketLayer dnsLayer;
                dnsLayer.name = QStringLiteral("Domain Name System");

                field.category = QStringLiteral("Header");
                field.label = QStringLiteral("Transaction ID");
                field.value = QStringLiteral("0x%1").arg(dns.id, 4, 16, QLatin1Char('0')).toUpper();
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Type");
                field.value = dns.isResponse ? QStringLiteral("Response") : QStringLiteral("Query");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Opcode");
                field.value = QString::number(dns.opcode);
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Authoritative");
                field.value = dns.authoritative ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Truncated");
                field.value = dns.truncated ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Recursion desired");
                field.value = dns.recursionDesired ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Recursion available");
                field.value = dns.recursionAvailable ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Authenticated data");
                field.value = dns.authenticatedData ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Checking disabled");
                field.value = dns.checkingDisabled ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                if (dns.rcode) {
                    field.label = QStringLiteral("RCode");
                    field.value = QString::number(dns.rcode);
                    dnsLayer.fields.append(field);
                }

                for (int i = 0; i < dns.questions.size(); ++i) {
                    const auto &q = dns.questions.at(i);
                    field.category = QStringLiteral("Questions");
                    field.label = QStringLiteral("Q%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 %3").arg(q.name, q.type, q.klass);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.answers.size(); ++i) {
                    const auto &r = dns.answers.at(i);
                    field.category = QStringLiteral("Answers");
                    field.label = QStringLiteral("A%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.authorities.size(); ++i) {
                    const auto &r = dns.authorities.at(i);
                    field.category = QStringLiteral("Authority");
                    field.label = QStringLiteral("NS%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.additionals.size(); ++i) {
                    const auto &r = dns.additionals.at(i);
                    field.category = QStringLiteral("Additional");
                    field.label = QStringLiteral("AD%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }

                layers.append(dnsLayer);
            }
        }
        // --- ICMPv4 ---
        else if (ip->ip_p == IPPROTO_ICMP) {
            auto vals = parseIcmp(pkt, linkType);
            static const QStringList labels = {
                "ICMPv4 Type","Code","Checksum","Identifier",
                "Sequence","Message"
            };
            PacketLayer icmpLayer;
            icmpLayer.name = "Internet Control Message Protocol";
            field.category = "ICMP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                icmpLayer.fields.append(field);
            }
            layers.append(icmpLayer);
        }
        // --- IGMP ---
        else if (ip->ip_p == IPPROTO_IGMP) {
            auto vals = parseIgmp(pkt, linkType);
            static const QStringList labels = {
                "Type","Description","Max Response Time","Checksum","Group Address"
            };
            PacketLayer igmpLayer;
            igmpLayer.name = "Internet Group Management Protocol";
            field.category = "IGMP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                igmpLayer.fields.append(field);
            }
            layers.append(igmpLayer);
        }
        // --- SCTP ---
        else if (ip->ip_p == IPPROTO_SCTP) {
            auto vals = parseSctp(pkt, linkType);
            static const QStringList labels = {
                "Source port","Destination port","Verification Tag","Checksum"
            };
            PacketLayer sctpLayer;
            sctpLayer.name = "Stream Control Transmission Protocol";
            field.category = "SCTP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                sctpLayer.fields.append(field);
            }
            layers.append(sctpLayer);
        }
        // --- UDP-Lite ---
        else if (ip->ip_p == IPPROTO_UDPLITE) {
            auto vals = parseUdplite(pkt, linkType);
            static const QStringList labels = {
                "Source port","Destination port","Checksum coverage","Checksum"
            };
            PacketLayer udpliteLayer;
            udpliteLayer.name = "UDP-Lite";
            field.category = "UDP-Lite Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udpliteLayer.fields.append(field);
            }
            layers.append(udpliteLayer);
        }
        // --- GRE ---
        else if (ip->ip_p == IPPROTO_GRE) {
            auto vals = parseGre(pkt, linkType);
            static const QStringList labels = {
                "Flags","Version","Protocol"
            };
            PacketLayer greLayer;
            greLayer.name = "Generic Routing Encapsulation";
            field.category = "GRE Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                greLayer.fields.append(field);
            }
            layers.append(greLayer);
        }
        // --- IP-in-IP ---
        else if (ip->ip_p == IPPROTO_IPIP) {
            auto vals = parseIpip(pkt, linkType);
            static const QStringList labels = {
                "Inner Src","Inner Dst","Inner Protocol","Inner Length"
            };
            PacketLayer ipipLayer;
            ipipLayer.name = "IP in IP";
            field.category = "Inner IPv4";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ipipLayer.fields.append(field);
            }
            layers.append(ipipLayer);
        }
        // --- OSPF ---
        else if (ip->ip_p == IPPROTO_OSPFIGP) {
            auto vals = parseOspf(pkt, linkType);
            static const QStringList labels = {
                "Version","Type","Length","Router ID","Area ID","Checksum","Auth Type"
            };
            PacketLayer ospfLayer;
            ospfLayer.name = "Open Shortest Path First";
            field.category = "OSPF Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ospfLayer.fields.append(field);
            }
            layers.append(ospfLayer);
        }
        // --- RSVP ---
        else if (ip->ip_p == IPPROTO_RSVP) {
            auto vals = parseRsvp(pkt, linkType);
            static const QStringList labels = {
                "Version","Message Type","Checksum","Send TTL","Length"
            };
            PacketLayer rsvpLayer;
            rsvpLayer.name = "Resource Reservation Protocol";
            field.category = "RSVP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                rsvpLayer.fields.append(field);
            }
            layers.append(rsvpLayer);
        }
        // --- PIM ---
        else if (ip->ip_p == IPPROTO_PIM) {
            auto vals = parsePim(pkt, linkType);
            static const QStringList labels = {
                "Version","Message Type","Checksum"
            };
            PacketLayer pimLayer;
            pimLayer.name = "Protocol Independent Multicast";
            field.category = "PIM Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                pimLayer.fields.append(field);
            }
            layers.append(pimLayer);
        }
        // --- EGP ---
        else if (ip->ip_p == IPPROTO_EGP) {
            auto vals = parseEgp(pkt, linkType);
            static const QStringList labels = {
                "Version","Type","Code","Status","Checksum","AS Number","Sequence"
            };
            PacketLayer egpLayer;
            egpLayer.name = "Exterior Gateway Protocol";
            field.category = "EGP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                egpLayer.fields.append(field);
            }
            layers.append(egpLayer);
        }
        // --- IPsec AH ---
        else if (ip->ip_p == IPPROTO_AH) {
            auto vals = parseAh(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Payload Length","SPI","Sequence Number"
            };
            PacketLayer ahLayer;
            ahLayer.name = "Authentication Header";
            field.category = "AH Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ahLayer.fields.append(field);
            }
            layers.append(ahLayer);
        }
        // --- IPsec ESP ---
        else if (ip->ip_p == IPPROTO_ESP) {
            auto vals = parseEsp(pkt, linkType);
            static const QStringList labels = {
                "SPI","Sequence Number"
            };
            PacketLayer espLayer;
            espLayer.name = "Encapsulating Security Payload";
            field.category = "ESP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                espLayer.fields.append(field);
            }
            layers.append(espLayer);
        }
        // --- MPLS-in-IP ---
        else if (ip->ip_p == IPPROTO_MPLS) {
            auto vals = parseMpls(pkt, linkType);
            static const QStringList labels = {
                "Label","Traffic Class","Bottom of Stack","TTL"
            };
            PacketLayer mplsLayer;
            mplsLayer.name = "Multiprotocol Label Switching";
            field.category = "MPLS Entry";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mplsLayer.fields.append(field);
            }
            layers.append(mplsLayer);
        }
    }
    // --- IPv6 ---
    else if (et == ETHERTYPE_IPV6) {
        const auto ip6 = ipv6Hdr(pkt, linkType);
        PacketLayer ip6Layer;
        ip6Layer.name = "Internet Protocol Version 6";

        char buf6[INET6_ADDRSTRLEN];
        field.category = "IP Header";
        field.label    = "Src";
        field.value    = QString::fromLatin1(
                           inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6))
                        );
        ip6Layer.fields.append(field);

        field.label    = "Dst";
        field.value    = QString::fromLatin1(
                           inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6))
                        );
        ip6Layer.fields.append(field);

        field.label    = "Next Header";
        field.value    = protoName(ip6->ip6_nxt);
        ip6Layer.fields.append(field);

        layers.append(ip6Layer);

        // --- TCP ---
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            auto vals = parseTcp(pkt, linkType);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Sequence number","ACK number","TCP header length","Flags",
                "Window size","Checksum","Urgent pointer"
            };
            PacketLayer tcp6Layer;
            tcp6Layer.name = "Transmission Control Protocol";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.category = (labels[i] == "Flags"
                                  ? "Flags"
                                  : "TCP Header");
                field.label    = labels[i];
                field.value    = vals[i];
                tcp6Layer.fields.append(field);
            }
            layers.append(tcp6Layer);

            auto http = parseHttp(pkt, linkType);
            if (http.valid) {
                PacketLayer httpLayer;
                httpLayer.name = QStringLiteral("Hypertext Transfer Protocol");

                if (http.isRequest) {
                    field.category = QStringLiteral("Request");
                    field.label = QStringLiteral("Method");
                    field.value = http.method;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Target");
                    field.value = http.target;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Version");
                    field.value = http.version;
                    httpLayer.fields.append(field);

                    if (!http.host.isEmpty()) {
                        field.label = QStringLiteral("Host");
                        field.value = http.host;
                        httpLayer.fields.append(field);
                    }
                } else {
                    field.category = QStringLiteral("Response");
                    field.label = QStringLiteral("Version");
                    field.value = http.version;
                    httpLayer.fields.append(field);

                    field.label = QStringLiteral("Status");
                    field.value = QString::number(http.statusCode);
                    httpLayer.fields.append(field);

                    if (!http.reason.isEmpty()) {
                        field.label = QStringLiteral("Reason");
                        field.value = http.reason;
                        httpLayer.fields.append(field);
                    }
                }

                for (const auto &hdr : http.headers) {
                    field.category = QStringLiteral("Headers");
                    field.label = hdr.name;
                    field.value = hdr.value;
                    httpLayer.fields.append(field);
                }

                layers.append(httpLayer);
            }
            else {
                auto tls = parseTls(pkt, linkType);
                if (tls.valid) {
                    PacketLayer tlsLayer;
                    tlsLayer.name = QStringLiteral("Transport Layer Security");

                    field.category = QStringLiteral("Record");
                    field.label = QStringLiteral("Content Type");
                    field.value = tls.recordType;
                    tlsLayer.fields.append(field);

                    field.label = QStringLiteral("Version");
                    field.value = tls.version;
                    tlsLayer.fields.append(field);

                    if (!tls.handshakeType.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Type");
                        field.value = tls.handshakeType;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.serverName.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Server Name");
                        field.value = tls.serverName;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.selectedCipher.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Cipher");
                        field.value = tls.selectedCipher;
                        tlsLayer.fields.append(field);
                    }
                    if (!tls.cipherSuites.isEmpty()) {
                        field.category = QStringLiteral("Handshake");
                        field.label = QStringLiteral("Cipher Suites");
                        field.value = tls.cipherSuites.join(QStringLiteral(", "));
                        tlsLayer.fields.append(field);
                    }

                    layers.append(tlsLayer);
                }
            }
        }
        // --- UDP ---
        else if (ip6->ip6_nxt == IPPROTO_UDP) {
            auto vals = parseUdp(pkt, linkType);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Length","Checksum"
            };
            PacketLayer udp6Layer;
            udp6Layer.name = "User Datagram Protocol";
            field.category = "UDP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udp6Layer.fields.append(field);
            }
            layers.append(udp6Layer);

            auto dns = parseDns(pkt, linkType);
            if (dns.valid) {
                PacketLayer dnsLayer;
                dnsLayer.name = QStringLiteral("Domain Name System");

                field.category = QStringLiteral("Header");
                field.label = QStringLiteral("Transaction ID");
                field.value = QStringLiteral("0x%1").arg(dns.id, 4, 16, QLatin1Char('0')).toUpper();
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Type");
                field.value = dns.isResponse ? QStringLiteral("Response") : QStringLiteral("Query");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Opcode");
                field.value = QString::number(dns.opcode);
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Authoritative");
                field.value = dns.authoritative ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Truncated");
                field.value = dns.truncated ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Recursion desired");
                field.value = dns.recursionDesired ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Recursion available");
                field.value = dns.recursionAvailable ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Authenticated data");
                field.value = dns.authenticatedData ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                field.label = QStringLiteral("Checking disabled");
                field.value = dns.checkingDisabled ? QStringLiteral("Yes") : QStringLiteral("No");
                dnsLayer.fields.append(field);

                if (dns.rcode) {
                    field.label = QStringLiteral("RCode");
                    field.value = QString::number(dns.rcode);
                    dnsLayer.fields.append(field);
                }

                for (int i = 0; i < dns.questions.size(); ++i) {
                    const auto &q = dns.questions.at(i);
                    field.category = QStringLiteral("Questions");
                    field.label = QStringLiteral("Q%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 %3").arg(q.name, q.type, q.klass);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.answers.size(); ++i) {
                    const auto &r = dns.answers.at(i);
                    field.category = QStringLiteral("Answers");
                    field.label = QStringLiteral("A%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.authorities.size(); ++i) {
                    const auto &r = dns.authorities.at(i);
                    field.category = QStringLiteral("Authority");
                    field.label = QStringLiteral("NS%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }
                for (int i = 0; i < dns.additionals.size(); ++i) {
                    const auto &r = dns.additionals.at(i);
                    field.category = QStringLiteral("Additional");
                    field.label = QStringLiteral("AD%1").arg(i + 1);
                    field.value = QStringLiteral("%1 %2 TTL %3 %4")
                        .arg(r.name, r.type)
                        .arg(r.ttl)
                        .arg(r.data);
                    dnsLayer.fields.append(field);
                }

                layers.append(dnsLayer);
            }
        }
        // --- ICMPv6 ---
        else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
            auto vals = parseIcmpv6(pkt, linkType);
            static const QStringList labels = {
                "ICMPv6 Type","Code","Checksum","Identifier","Sequence","Message"
            };
            PacketLayer icmp6Layer;
            icmp6Layer.name = "Internet Control Message Protocol v6";
            field.category = "ICMPv6 Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                icmp6Layer.fields.append(field);
            }
            layers.append(icmp6Layer);
        }
        // --- SCTP ---
        else if (ip6->ip6_nxt == IPPROTO_SCTP) {
            auto vals = parseSctp(pkt, linkType);
            static const QStringList labels = {
                "Source port","Destination port","Verification Tag","Checksum"
            };
            PacketLayer sctp6Layer;
            sctp6Layer.name = "Stream Control Transmission Protocol";
            field.category = "SCTP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                sctp6Layer.fields.append(field);
            }
            layers.append(sctp6Layer);
        }
        // --- UDP-Lite ---
        else if (ip6->ip6_nxt == IPPROTO_UDPLITE) {
            auto vals = parseUdplite(pkt, linkType);
            static const QStringList labels = {
                "Source port","Destination port","Checksum coverage","Checksum"
            };
            PacketLayer udplite6Layer;
            udplite6Layer.name = "UDP-Lite";
            field.category = "UDP-Lite Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udplite6Layer.fields.append(field);
            }
            layers.append(udplite6Layer);
        }
        // --- GRE ---
        else if (ip6->ip6_nxt == IPPROTO_GRE) {
            auto vals = parseGre(pkt, linkType);
            static const QStringList labels = {
                "Flags","Version","Protocol"
            };
            PacketLayer gre6Layer;
            gre6Layer.name = "Generic Routing Encapsulation";
            field.category = "GRE Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                gre6Layer.fields.append(field);
            }
            layers.append(gre6Layer);
        }
        // --- RSVP ---
        else if (ip6->ip6_nxt == IPPROTO_RSVP) {
            auto vals = parseRsvp(pkt, linkType);
            static const QStringList labels = {
                "Version","Message Type","Checksum","Send TTL","Length"
            };
            PacketLayer rsvp6Layer;
            rsvp6Layer.name = "Resource Reservation Protocol";
            field.category = "RSVP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                rsvp6Layer.fields.append(field);
            }
            layers.append(rsvp6Layer);
        }
        // --- PIM ---
        else if (ip6->ip6_nxt == IPPROTO_PIM) {
            auto vals = parsePim(pkt, linkType);
            static const QStringList labels = {
                "Version","Message Type","Checksum"
            };
            PacketLayer pim6Layer;
            pim6Layer.name = "Protocol Independent Multicast";
            field.category = "PIM Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                pim6Layer.fields.append(field);
            }
            layers.append(pim6Layer);
        }
        // --- IPsec AH ---
        else if (ip6->ip6_nxt == IPPROTO_AH) {
            auto vals = parseAh(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Payload Length","SPI","Sequence Number"
            };
            PacketLayer ah6Layer;
            ah6Layer.name = "Authentication Header";
            field.category = "AH Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ah6Layer.fields.append(field);
            }
            layers.append(ah6Layer);
        }
        // --- IPsec ESP ---
        else if (ip6->ip6_nxt == IPPROTO_ESP) {
            auto vals = parseEsp(pkt, linkType);
            static const QStringList labels = {
                "SPI","Sequence Number"
            };
            PacketLayer esp6Layer;
            esp6Layer.name = "Encapsulating Security Payload";
            field.category = "ESP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                esp6Layer.fields.append(field);
            }
            layers.append(esp6Layer);
        }
        // --- MPLS-in-IP ---
        else if (ip6->ip6_nxt == IPPROTO_MPLS) {
            auto vals = parseMpls(pkt, linkType);
            static const QStringList labels = {
                "Label","Traffic Class","Bottom of Stack","TTL"
            };
            PacketLayer mpls6Layer;
            mpls6Layer.name = "Multiprotocol Label Switching";
            field.category = "MPLS Entry";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mpls6Layer.fields.append(field);
            }
            layers.append(mpls6Layer);
        }
        // --- IPv6 Hop-by-Hop Options ---
        else if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
            auto vals = parseIpv6HopByHop(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Next Header Name","Header Length"
            };
            PacketLayer hopLayer;
            hopLayer.name = "IPv6 Hop-by-Hop Options";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                hopLayer.fields.append(field);
            }
            layers.append(hopLayer);
        }
        // --- IPv6 Routing Header ---
        else if (ip6->ip6_nxt == IPPROTO_ROUTING) {
            auto vals = parseIpv6Routing(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Next Header Name","Routing Type","Segments Left"
            };
            PacketLayer routingLayer;
            routingLayer.name = "IPv6 Routing Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                routingLayer.fields.append(field);
            }
            layers.append(routingLayer);
        }
        // --- IPv6 Fragment Header ---
        else if (ip6->ip6_nxt == IPPROTO_FRAGMENT) {
            auto vals = parseIpv6Fragment(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Next Header Name","Offset","More Fragments","Identification"
            };
            PacketLayer fragLayer;
            fragLayer.name = "IPv6 Fragment Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                fragLayer.fields.append(field);
            }
            layers.append(fragLayer);
        }
        // --- IPv6 Destination Options ---
        else if (ip6->ip6_nxt == IPPROTO_DSTOPTS) {
            auto vals = parseIpv6Destination(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Next Header Name","Header Length"
            };
            PacketLayer destLayer;
            destLayer.name = "IPv6 Destination Options";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                destLayer.fields.append(field);
            }
            layers.append(destLayer);
        }
        // --- IPv6 Mobility Header ---
        else if (ip6->ip6_nxt == IPPROTO_MH) {
            auto vals = parseIpv6Mobility(pkt, linkType);
            static const QStringList labels = {
                "Next Header","Next Header Name","Mobility Type","Checksum"
            };
            PacketLayer mobilityLayer;
            mobilityLayer.name = "IPv6 Mobility Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mobilityLayer.fields.append(field);
            }
            layers.append(mobilityLayer);
        }
    }
    // --- ARP ---
    else if (et == ETHERTYPE_ARP) {
        auto vals = parseArp(pkt, linkType);
        static const QStringList labels = {
            "Sender IP","Target IP",
            "HW Type","Proto Type","HLEN","PLEN","Operation",
            "Sender MAC","Target MAC"
        };
        PacketLayer arpLayer;
        arpLayer.name = "Address Resolution Protocol";
        field.category = "ARP Header";
        for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
            field.label = labels[i];
            field.value = vals[i];
            arpLayer.fields.append(field);
        }
        layers.append(arpLayer);
    }

    return layers;
}



void Sniffing::recordStreamSegment(const QByteArray &packet,
                                   int linkType,
                                   qint64 tsSec,
                                   qint64 tsUsec)
{
    if (packet.isEmpty())
        return;

    const u_char *pkt = reinterpret_cast<const u_char*>(packet.constData());
    uint16_t ethertype = ethType(pkt, linkType);

    int ipVersion = 0;
    QByteArray srcAddr;
    QByteArray dstAddr;
    quint16 srcPort = 0;
    quint16 dstPort = 0;
    quint8 protocol = 0;
    const u_char *payloadPtr = nullptr;
    int payloadLen = 0;
    bool isTcp = false;
    quint8 tcpFlags = 0;
    quint32 sequenceNumber = 0;
    quint32 acknowledgementNumber = 0;
    quint16 windowSize = 0;

    if (ethertype == ETHERTYPE_IP) {
        ipVersion = 4;
        const sniff_ip *ip = ipv4Hdr(pkt, linkType);
        if (!ip)
            return;
        protocol = ip->ip_p;
        srcAddr = QByteArray(reinterpret_cast<const char*>(&ip->ip_src), sizeof(ip->ip_src));
        dstAddr = QByteArray(reinterpret_cast<const char*>(&ip->ip_dst), sizeof(ip->ip_dst));
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        ipVersion = 6;
        const sniff_ipv6 *ip6 = ipv6Hdr(pkt, linkType);
        if (!ip6)
            return;
        protocol = ip6->ip6_nxt;
        srcAddr = QByteArray(reinterpret_cast<const char*>(&ip6->ip6_src), sizeof(ip6->ip6_src));
        dstAddr = QByteArray(reinterpret_cast<const char*>(&ip6->ip6_dst), sizeof(ip6->ip6_dst));
    }
    else {
        return;
    }

    switch (protocol) {
        case IPPROTO_TCP: {
            TcpSegmentView view = tcpSegmentView(pkt, linkType);
            if (!view.header)
                return;
            srcPort = ntohs(view.header->th_sport);
            dstPort = ntohs(view.header->th_dport);
            payloadLen = view.payloadLength;
            if (payloadLen > 0 && view.payload)
                payloadPtr = view.payload;
            isTcp = true;
            tcpFlags = view.header->th_flags;
            sequenceNumber = ntohl(view.header->th_seq);
            acknowledgementNumber = ntohl(view.header->th_ack);
            windowSize = ntohs(view.header->th_win);
            break;
        }
        case IPPROTO_UDP: {
            UdpDatagramView view = udpDatagramView(pkt, linkType);
            if (!view.header)
                return;
            srcPort = ntohs(view.header->uh_sport);
            dstPort = ntohs(view.header->uh_dport);
            payloadLen = view.payloadLength;
            if (payloadLen > 0 && view.payload)
                payloadPtr = view.payload;
            break;
        }
        default:
            return;
    }

    bool srcFirst = false;
    if (srcAddr < dstAddr) {
        srcFirst = true;
    }
    else if (srcAddr > dstAddr) {
        srcFirst = false;
    }
    else {
        srcFirst = srcPort <= dstPort;
    }

    QByteArray addrA = srcFirst ? srcAddr : dstAddr;
    QByteArray addrB = srcFirst ? dstAddr : srcAddr;
    quint16 portA = srcFirst ? srcPort : dstPort;
    quint16 portB = srcFirst ? dstPort : srcPort;
    bool fromAtoB = srcFirst;
    QString key = makeStreamKey(ipVersion, protocol, addrA, portA, addrB, portB);

    if (payloadLen < 0)
        payloadLen = 0;

    StreamSegment segment;
    segment.timestampSeconds = tsSec;
    segment.timestampMicros = tsUsec;
    segment.payloadLength = payloadLen;
    segment.frameLength = packet.size();
    segment.fromAtoB = fromAtoB;
    segment.isTcp = isTcp;
    segment.tcpFlags = tcpFlags;
    segment.sequenceNumber = sequenceNumber;
    segment.acknowledgementNumber = acknowledgementNumber;
    segment.windowSize = windowSize;
    if (payloadLen > 0 && payloadPtr)
        segment.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), payloadLen);

    QMutexLocker locker(&streamMutex);
    StreamConversation &conversation = streamConversations[key];
    const bool isNewConversation = conversation.segments.isEmpty() && conversation.packetCount == 0;
    conversation.protocol = protocol;
    conversation.ipVersion = ipVersion;

    if (isNewConversation) {
        conversation.endpointA.address = ipBytesToString(addrA, ipVersion);
        conversation.endpointA.port = portA;
        conversation.endpointB.address = ipBytesToString(addrB, ipVersion);
        conversation.endpointB.port = portB;
        conversation.initiatorIsA = fromAtoB;
        conversation.firstTimestampSec = tsSec;
        conversation.firstTimestampUsec = tsUsec;
    } else {
        if (conversation.endpointA.address.isEmpty())
            conversation.endpointA.address = ipBytesToString(addrA, ipVersion);
        if (conversation.endpointB.address.isEmpty())
            conversation.endpointB.address = ipBytesToString(addrB, ipVersion);
    }

    if (conversation.packetCount == 0 ||
        tsSec < conversation.firstTimestampSec ||
        (tsSec == conversation.firstTimestampSec && tsUsec < conversation.firstTimestampUsec)) {
        conversation.firstTimestampSec = tsSec;
        conversation.firstTimestampUsec = tsUsec;
    }
    if (conversation.packetCount == 0 ||
        tsSec > conversation.lastTimestampSec ||
        (tsSec == conversation.lastTimestampSec && tsUsec > conversation.lastTimestampUsec)) {
        conversation.lastTimestampSec = tsSec;
        conversation.lastTimestampUsec = tsUsec;
    }

    if (conversation.packetCount == 0)
        conversation.initiatorIsA = fromAtoB;

    if (fromAtoB) {
        conversation.totalBytesAToB += segment.payload.size();
        if (!segment.payload.isEmpty())
            conversation.aggregatedAToB.append(segment.payload);
    } else {
        conversation.totalBytesBToA += segment.payload.size();
        if (!segment.payload.isEmpty())
            conversation.aggregatedBToA.append(segment.payload);
    }

    conversation.segments.append(segment);
    ++conversation.packetCount;
}

QVector<Sniffing::StreamConversation> Sniffing::getStreamConversations() const
{
    QMutexLocker locker(&streamMutex);
    QVector<StreamConversation> result;
    result.reserve(streamConversations.size());
    for (auto it = streamConversations.constBegin(); it != streamConversations.constEnd(); ++it)
        result.append(it.value());

    std::sort(result.begin(), result.end(), [](const StreamConversation &lhs,
                                               const StreamConversation &rhs) {
        if (lhs.firstTimestampSec == rhs.firstTimestampSec) {
            if (lhs.firstTimestampUsec == rhs.firstTimestampUsec)
                return lhs.label() < rhs.label();
            return lhs.firstTimestampUsec < rhs.firstTimestampUsec;
        }
        return lhs.firstTimestampSec < rhs.firstTimestampSec;
    });
    return result;
}

void Sniffing::resetStreams()
{
    QMutexLocker locker(&streamMutex);
    streamConversations.clear();
}

void Sniffing::saveToPcap(const QString &filePath) {
    QMutexLocker locker(&packetMutex);
    if (packetBuffer.isEmpty())
        return;

    QSet<int> linkTypes;
    for (const auto &packet : packetBuffer)
        linkTypes.insert(packet.linkType);

    if (linkTypes.size() > 1) {
        qWarning("Cannot save PCAP: captured packets use multiple link types.");
        return;
    }

    const int linkType = *linkTypes.begin();

    pcap_t *pcap = pcap_open_dead(linkType, 65535);
    if (!pcap) {
        qWarning("Failed to initialize PCAP writer.");
        return;
    }

    pcap_dumper_t *dumper = pcap_dump_open(pcap, filePath.toUtf8().constData());
    if (!dumper) {
        qWarning("Failed to open PCAP file for writing: %s", pcap_geterr(pcap));
        pcap_close(pcap);
        return;
    }

    timeval ts{0, 0};

    for (const auto &packet : packetBuffer) {
        const QByteArray &raw = packet.data;
        pcap_pkthdr hdr;
        hdr.ts = ts;
        hdr.caplen = raw.size();
        hdr.len = raw.size();
        pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr,
                  reinterpret_cast<const u_char*>(raw.constData()));
    }

    pcap_dump_close(dumper);
    pcap_close(pcap);
}

void Sniffing::openFromPcap(const QString &filePath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filePath.toUtf8().constData(), errbuf);
    if (!handle) {
        qWarning("Failed to open pcap file: %s", errbuf);
        return;
    }

    const u_char *raw;
    struct pcap_pkthdr *header;

    {
        QMutexLocker locker(&packetMutex);
        packetBuffer.clear();
    }
    resetStreams();

    const int linkType = pcap_datalink(handle);

    while (true) {
        int res = pcap_next_ex(handle, &header, &raw);
        if (res == 1) {
            QByteArray pkt(reinterpret_cast<const char*>(raw), header->caplen);
            appendPacket(CapturedPacket{pkt, linkType});
            recordStreamSegment(pkt, linkType, header->ts.tv_sec, header->ts.tv_usec);
        }
        else if (res == -2) {
            break;
        }
        else if (res == -1) {
            qWarning("Error reading packet: %s", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
}


// here are my sniffing infos
QVector<CapturedPacket> Sniffing::packetBuffer;
QMutex Sniffing::packetMutex;
QHash<QString, Sniffing::StreamConversation> Sniffing::streamConversations;
QMutex Sniffing::streamMutex;

void Sniffing::appendPacket(const CapturedPacket &packet) {
    QMutexLocker locker(&packetMutex);
    packetBuffer.append(packet);
}

const QVector<CapturedPacket>& Sniffing::getAllPackets() {
    return packetBuffer;
}

void Sniffing::clearBuffer() {
    {
        QMutexLocker locker(&packetMutex);
        packetBuffer.clear();
    }
    resetStreams();
}
