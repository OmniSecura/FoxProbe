#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include <QObject>
#include "packets/sniffing.h"
#include <QString>
#include <QThread>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>
#include <string>
#include <QDebug>
#include <memory>
#include <pcap.h>
#include <QMutex>

class PacketWorker : public QObject {
    Q_OBJECT

public:
    PacketWorker(const QString &iface,
                 const QString &filter,
                 bool promisc);
    ~PacketWorker();
    int linkType() const { return m_linkType.load(std::memory_order_relaxed); }
    void getPacketInfo(const std::string& infos) {
        qDebug() << QString::fromStdString(infos);
    }

    
public slots:
    void process();  // capture loop
    void stop();     // signal to exit
    void updateFilter(const QString &filter); // change filter at runtime

signals:
    // rawData: packet bytes
    // infos:   [0]=timestamp, [1]=caplen, [2]=srcPort, [3]=dstPort
    void newPacket(const QByteArray &rawData,
                   QStringList infos,
                   int linkType);
    void linkTypeChanged(int linkType, bpf_u_int32 netmask);

private:
    bool installFilter(const QString &filter);
    bool applyPendingFilter();

    QString           m_iface;
    QString           m_filter;
    QString           m_pendingFilter;
    bool              m_promisc;
    std::atomic<bool> m_running;
    std::atomic<bool> m_filterUpdateRequested{false};
    QMutex            m_filterMutex;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> m_handle{nullptr, &pcap_close};
    bpf_u_int32       m_netmask = 0;
    std::atomic<int>  m_linkType{DLT_EN10MB};
};

#endif // PACKETWORKER_H
