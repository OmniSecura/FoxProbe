#ifndef SNIFFING_H
#define SNIFFING_H

#include <QString>
#include "protocols/proto_struct.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <QByteArray>
#include <QStringList>
#include <QVector>
#include <QMutex>
#include <QHash>
#include <QtGlobal>

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

struct ProtoField {
    QString category;   // "Header", "Options", "Checksum"…
    QString label;      // f.first
    QString value;      // f.second
};

struct PacketLayer {
    QString name;
    QVector<ProtoField> fields;
};

struct HttpHeader {
    QString name;
    QString value;
};

struct ParsedHttp {
    bool valid = false;
    bool isRequest = false;
    QString method;
    QString target;
    QString version;
    int statusCode = 0;
    QString reason;
    QString host;
    QVector<HttpHeader> headers;
};

struct DnsQuestion {
    QString name;
    QString type;
    QString klass;
};

struct DnsRecord {
    QString name;
    QString type;
    QString klass;
    quint32 ttl = 0;
    QString data;
};

struct ParsedDns {
    bool valid = false;
    bool isResponse = false;
    quint16 id = 0;
    quint8 opcode = 0;
    quint8 rcode = 0;
    bool authoritative = false;
    bool truncated = false;
    bool recursionDesired = false;
    bool recursionAvailable = false;
    bool authenticatedData = false;
    bool checkingDisabled = false;
    QVector<DnsQuestion> questions;
    QVector<DnsRecord> answers;
    QVector<DnsRecord> authorities;
    QVector<DnsRecord> additionals;
};

struct ParsedTls {
    bool valid = false;
    QString recordType;
    QString version;
    QString handshakeType;
    QString serverName;
    QString selectedCipher;
    QStringList cipherSuites;
    bool isClientHello = false;
};

struct CapturedPacket {
    QByteArray data;
    int linkType = DLT_EN10MB;
};

class PacketWorker;

class Sniffing {
public:
    Sniffing();
    ~Sniffing();

    struct StreamEndpoint {
        QString address;
        quint16 port = 0;
    };

    struct StreamSegment {
        qint64 timestampSeconds = 0;
        qint64 timestampMicros = 0;
        QByteArray payload;
        bool fromAtoB = true;
        int payloadLength = 0;
        int frameLength = 0;
        bool isTcp = false;
        quint8 tcpFlags = 0;
        quint32 sequenceNumber = 0;
        quint32 acknowledgementNumber = 0;
        quint16 windowSize = 0;
    };

    struct StreamConversation {
        StreamEndpoint endpointA;
        StreamEndpoint endpointB;
        quint8 protocol = 0;
        int ipVersion = 4;
        bool initiatorIsA = true;
        QVector<StreamSegment> segments;
        QByteArray aggregatedAToB;
        QByteArray aggregatedBToA;
        qint64 totalBytesAToB = 0;
        qint64 totalBytesBToA = 0;
        int packetCount = 0;
        qint64 firstTimestampSec = 0;
        qint64 firstTimestampUsec = 0;
        qint64 lastTimestampSec = 0;
        qint64 lastTimestampUsec = 0;

        QString protocolName() const;
        QString label() const;
    };

    static void packet_callback(u_char *args,
                                const struct pcap_pkthdr *header,
                                const u_char *packet);
    // === Parsers ====
    QStringList parseArp(const u_char *pkt, int linkType) const;
    QStringList parseTcp(const u_char *pkt, int linkType) const;
    QStringList parseUdp(const u_char *pkt, int linkType) const;
    QStringList parseIcmp(const u_char *pkt, int linkType) const;
    QStringList parseIcmpv6(const u_char *pkt, int linkType) const;
    QStringList parseIgmp(const u_char *pkt, int linkType) const;
    QStringList parseSctp(const u_char *pkt, int linkType) const;
    QStringList parseUdplite(const u_char *pkt, int linkType) const;
    QStringList parseGre(const u_char *pkt, int linkType) const;
    QStringList parseOspf(const u_char *pkt, int linkType) const;
    QStringList parseRsvp(const u_char *pkt, int linkType) const;
    QStringList parsePim(const u_char *pkt, int linkType) const;
    QStringList parseEgp(const u_char *pkt, int linkType) const;
    QStringList parseAh(const u_char *pkt, int linkType) const;
    QStringList parseEsp(const u_char *pkt, int linkType) const;
    QStringList parseMpls(const u_char *pkt, int linkType) const;
    QStringList parseIpip(const u_char *pkt, int linkType) const;
    QStringList parseIpv6HopByHop(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Routing(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Fragment(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Destination(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Mobility(const u_char *pkt, int linkType) const;
    ParsedHttp parseHttp(const u_char *pkt, int linkType) const;
    ParsedDns parseDns(const u_char *pkt, int linkType) const;
    ParsedTls parseTls(const u_char *pkt, int linkType) const;
    // ================

    QVector<PacketLayer> parseLayers(const u_char* pkt, int linkType) const;

    QString toHexAscii(const u_char *payload, int len) const;
    QStringList packetSummary(const u_char *packet, int total_len, int linkType) const;

    QVector<StreamConversation> getStreamConversations() const;
    void resetStreams();

    //These are for saving and opening my pcap files
    void saveToPcap(const QString &filePath);
    void openFromPcap(const QString &filePath);

    //I will use this to save my packet sniffing session later
    static QVector<CapturedPacket> packetBuffer;
    static QMutex packetMutex;
    static QHash<QString, StreamConversation> streamConversations;
    static QMutex streamMutex;
    static void recordStreamSegment(const QByteArray &packet,
                                    int linkType,
                                    qint64 tsSec,
                                    qint64 tsUsec);

    static void appendPacket(const CapturedPacket &packet);
    static const QVector<CapturedPacket>& getAllPackets();
    void clearBuffer();

};

#endif // SNIFFING_H
