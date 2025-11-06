#include "packetworker.h"
#include "devices/devices.h"
#include "filter/filter.h"
#include "protocols/proto_struct.h"

#include <QDebug>
#include <QMutexLocker>

PacketWorker::PacketWorker(const QString &iface,
                           const QString &filter,
                           bool promisc)
  : m_iface(iface)
  , m_filter(filter)
  , m_pendingFilter(filter)
  , m_promisc(promisc)
  , m_running(true)
  , m_netmask(0)
{}

PacketWorker::~PacketWorker() = default;

void PacketWorker::stop() {
    m_running.store(false, std::memory_order_relaxed);
    if (m_handle) {
        pcap_breakloop(m_handle.get());
    }
}

void PacketWorker::process() {
    // 1) open interface using Devices
    Devices dev;
    m_handle.reset(dev.init_packet_capture(
        m_iface.toStdString().c_str(),
        m_promisc
    ));
    if (!m_handle) {
        emit newPacket({},
                      {QStringLiteral("ERROR: %1").arg(dev.error_buffer)},
                      m_linkType.load(std::memory_order_relaxed));
        return;
    }

    m_linkType.store(pcap_datalink(m_handle.get()), std::memory_order_relaxed);

    // 2) compile & set filter via Filters
    if (!installFilter(m_filter)) {
        qWarning("Initial filter installation failed; continuing without filter updates");
    }

    emit linkTypeChanged(m_linkType.load(std::memory_order_relaxed), m_netmask);

    // 3) capture loop
    while (m_running.load(std::memory_order_relaxed)) {
        applyPendingFilter();

        int ret = pcap_dispatch(
            m_handle.get(),
            -1,
            Sniffing::packet_callback,
            reinterpret_cast<u_char*>(this)
        );
        if (ret == PCAP_ERROR_BREAK) {
            if (!m_running.load(std::memory_order_relaxed))
                break;
            // loop again to apply pending filter or resume capture
            continue;
        }
        if (ret < 0) {
            qWarning("pcap_dispatch error: %s", pcap_geterr(m_handle.get()));
            break;
        }
    }
    m_handle.reset();
}

void PacketWorker::updateFilter(const QString &filter) {
    {
        QMutexLocker locker(&m_filterMutex);
        m_pendingFilter = filter;
    }
    m_filterUpdateRequested.store(true, std::memory_order_release);
    if (m_handle) {
        pcap_breakloop(m_handle.get());
    }
}

bool PacketWorker::installFilter(const QString &filter) {
    if (!m_handle)
        return false;

    Filters flt;
    char errbuf[PCAP_ERRBUF_SIZE];
    flt.netmask_lookup(m_iface.toStdString(), errbuf);
    m_netmask = flt.get_mask();
    if (!flt.filter_processing(
            m_handle.get(),
            filter.toStdString().c_str(),
            0,
            m_netmask)) {
        return false;
    }
    return true;
}

bool PacketWorker::applyPendingFilter() {
    if (!m_filterUpdateRequested.exchange(false, std::memory_order_acq_rel))
        return false;

    QString nextFilter;
    {
        QMutexLocker locker(&m_filterMutex);
        nextFilter = m_pendingFilter;
    }

    if (!installFilter(nextFilter)) {
        qWarning("Failed to apply runtime filter: %s", qPrintable(nextFilter));
        return false;
    }

    m_filter = nextFilter;
    return true;
}
