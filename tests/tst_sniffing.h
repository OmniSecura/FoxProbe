#ifndef TST_SNIFFING_H
#define TST_SNIFFING_H

#include <QObject>

class SniffingTest : public QObject
{
    Q_OBJECT
private slots:
    void parseTcpIpv4();
    void parseUdpIpv4();
    void parseIcmpIpv4();
    void parseTcpIpv6();
    void parseArp();
    void parseHttpRequest();
    void parseDnsQuery();
    void parseTlsClientHello();
    void parseIcmpv6();
    void parseIgmp();
    void parseSctp();
    void parseUdplite();
    void parseGre();
};

#endif // TST_SNIFFING_H