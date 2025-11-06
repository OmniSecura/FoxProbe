#include "anomalydetector.h"

#include <QtMath>
#include <QSet>
#include <algorithm>

namespace {
constexpr double kMinVariance = 1e-4;
}

AnomalyDetector::AdaptiveMetric::AdaptiveMetric(double alpha)
    : m_alpha(alpha) {}

double AnomalyDetector::AdaptiveMetric::updateAndScore(double value, int warmup)
{
    if (!m_initialized) {
        m_initialized = true;
        m_mean = value;
        m_variance = kMinVariance;
        m_count = 1;
        return 0.0;
    }

    const double stddev = qSqrt(qMax(m_variance, kMinVariance));
    double score = 0.0;
    if (stddev > 0.0) {
        score = (value - m_mean) / stddev;
    }

    const double delta = value - m_mean;
    m_mean += m_alpha * delta;
    m_variance = (1.0 - m_alpha) * (m_variance + m_alpha * delta * delta);
    ++m_count;

    if (m_count <= warmup) {
        return 0.0;
    }

    return score;
}

void AnomalyDetector::AdaptiveMetric::reset()
{
    m_initialized = false;
    m_mean = 0.0;
    m_variance = kMinVariance;
    m_count = 0;
}

AnomalyDetector::AnomalyDetector(QObject *parent)
    : QObject(parent),
      m_packetMetric(0.15),
      m_byteMetric(0.15),
      m_connectionMetric(0.12),
      m_newConnectionMetric(0.12),
      m_entropyMetric(0.1),
      m_avgPacketMetric(0.1),
      m_threshold(2.8),
      m_warmup(6)
{
    qRegisterMetaType<AnomalyDetector::Event>("AnomalyDetector::Event");
}

void AnomalyDetector::observe(const FeatureSnapshot &snapshot)
{
    QVariantMap details;
    details.insert(QStringLiteral("packetsPerSecond"), snapshot.packets);
    details.insert(QStringLiteral("bytesPerSecond"), snapshot.bytes);
    details.insert(QStringLiteral("avgPacketSize"), snapshot.avgPacketSize);
    details.insert(QStringLiteral("uniqueConnections"), snapshot.uniqueConnections);
    details.insert(QStringLiteral("newConnections"), snapshot.newConnections);
    details.insert(QStringLiteral("protocolEntropy"), snapshot.protocolEntropy);
    details.insert(QStringLiteral("protocolCount"), snapshot.protocolCount);
    if (!snapshot.newProtocols.isEmpty()) {
        details.insert(QStringLiteral("newProtocols"), snapshot.newProtocols);
    }
    if (!snapshot.protocolCounts.isEmpty()) {
        QVariantMap protoMap;
        for (auto it = snapshot.protocolCounts.constBegin();
             it != snapshot.protocolCounts.constEnd(); ++it) {
            protoMap.insert(it.key(), it.value());
        }
        details.insert(QStringLiteral("protocolCounts"), protoMap);
    }

    QStringList reasons;
    QList<double> contributions;
    QStringList tags;
    QVariantList ddosTargets;
    QVariantList aggressiveSources;
    QSet<int> uniqueRows;
    QVector<int> collectedRows;

    auto appendRows = [&](const QVector<int> &rows) {
        for (int row : rows) {
            if (!uniqueRows.contains(row)) {
                uniqueRows.insert(row);
                collectedRows.append(row);
            }
        }
    };

    auto addReason = [&](const QString &text,
                         double contribution,
                         const QString &tag,
                         const QVector<int> &rows) {
        reasons << text;
        contributions.append(contribution);
        if (!tag.isEmpty() && !tags.contains(tag)) {
            tags << tag;
        }
        appendRows(rows);
    };

    auto considerMetric = [&](AdaptiveMetric &metric,
                              double value,
                              const QString &label,
                              const QString &tag) {
        const double score = qAbs(metric.updateAndScore(value, m_warmup));
        if (score > m_threshold) {
            const QString reason = QStringLiteral("%1 (%2σ)").arg(label).arg(score, 0, 'f', 2);
            addReason(reason, score, tag, snapshot.packetRows);
        }
    };

    considerMetric(m_packetMetric, snapshot.packets, tr("Packet rate spike"), QStringLiteral("packet-rate"));
    considerMetric(m_byteMetric, snapshot.bytes, tr("Byte throughput surge"), QStringLiteral("byte-throughput"));
    considerMetric(m_connectionMetric,
                   snapshot.uniqueConnections,
                   tr("Connection fan-out"),
                   QStringLiteral("connection-fanout"));
    considerMetric(m_newConnectionMetric,
                   snapshot.newConnections,
                   tr("Burst of new connections"),
                   QStringLiteral("new-connections"));
    considerMetric(m_entropyMetric,
                   snapshot.protocolEntropy,
                   tr("Protocol mix shift"),
                   QStringLiteral("protocol-entropy"));
    considerMetric(m_avgPacketMetric,
                   snapshot.avgPacketSize,
                   tr("Packet size swing"),
                   QStringLiteral("packet-size"));

    if (!snapshot.newProtocols.isEmpty()) {
        const QString label = tr("New protocol(s): %1").arg(snapshot.newProtocols.join(QStringLiteral(", ")));
        addReason(label,
                  m_threshold + 0.4 * snapshot.newProtocols.size(),
                  QStringLiteral("new-protocol"),
                  snapshot.packetRows);
    }

    const double totalPackets = snapshot.packets;
    const QStringList dominant = describeDominantProtocols(snapshot.protocolCounts, totalPackets);
    if (!dominant.isEmpty()) {
        addReason(tr("Traffic dominated by %1").arg(dominant.join(QStringLiteral(", "))),
                  m_threshold + 0.2 * dominant.size(),
                  QStringLiteral("protocol-dominance"),
                  snapshot.packetRows);
    }

    if (snapshot.uniqueConnections > 0) {
        const double churn = snapshot.uniqueConnections == 0
            ? 0.0
            : static_cast<double>(snapshot.newConnections)
              / static_cast<double>(snapshot.uniqueConnections);
        details.insert(QStringLiteral("connectionChurn"), churn);
        if (snapshot.newConnections > 5 && churn > 0.6) {
            addReason(tr("High connection churn (%1 new/%2 total)")
                          .arg(snapshot.newConnections)
                          .arg(snapshot.uniqueConnections),
                      m_threshold + churn,
                      QStringLiteral("connection-churn"),
                      snapshot.packetRows);
        }
    }

    // DDoS / flood heuristics
    if (!snapshot.destinationFanIn.isEmpty() && totalPackets > 0.0) {
        for (auto it = snapshot.destinationFanIn.constBegin(); it != snapshot.destinationFanIn.constEnd(); ++it) {
            const QString &destination = it.key();
            const int uniqueSources = it.value();
            const int destPackets = snapshot.destinationPackets.value(destination);
            if (destPackets <= 0) {
                continue;
            }
            const double share = destPackets / qMax(totalPackets, 1.0);
            if (uniqueSources >= 8 && destPackets >= 40 && share >= 0.35) {
                const QString text = tr("Potential DDoS against %1 (%2 sources, %3 packets)")
                                         .arg(destination)
                                         .arg(uniqueSources)
                                         .arg(destPackets);
                addReason(text,
                          m_threshold + share * 2.5,
                          QStringLiteral("ddos-target"),
                          snapshot.rowsByDestination.value(destination));
                QVariantMap record;
                record.insert(QStringLiteral("destination"), destination);
                record.insert(QStringLiteral("uniqueSources"), uniqueSources);
                record.insert(QStringLiteral("packets"), destPackets);
                record.insert(QStringLiteral("share"), share);
                ddosTargets.append(record);
            }
        }
    }

    if (!snapshot.sourceFanOut.isEmpty() && totalPackets > 0.0) {
        for (auto it = snapshot.sourceFanOut.constBegin(); it != snapshot.sourceFanOut.constEnd(); ++it) {
            const QString &source = it.key();
            const int uniqueDestinations = it.value();
            const int srcPackets = snapshot.sourcePackets.value(source);
            if (srcPackets <= 0) {
                continue;
            }
            const double share = srcPackets / qMax(totalPackets, 1.0);
            if (uniqueDestinations >= 15 && srcPackets >= 60 && share >= 0.25) {
                const QString text = tr("Single-source flood from %1 (%2 destinations, %3 packets)")
                                         .arg(source)
                                         .arg(uniqueDestinations)
                                         .arg(srcPackets);
                addReason(text,
                          m_threshold + share * 2.0,
                          QStringLiteral("ddos-source"),
                          snapshot.rowsBySource.value(source));
                QVariantMap record;
                record.insert(QStringLiteral("source"), source);
                record.insert(QStringLiteral("uniqueDestinations"), uniqueDestinations);
                record.insert(QStringLiteral("packets"), srcPackets);
                record.insert(QStringLiteral("share"), share);
                aggressiveSources.append(record);
            } else if (uniqueDestinations >= 8 && srcPackets >= 40) {
                const QString text = tr("Possible scan from %1 (%2 destinations)")
                                         .arg(source)
                                         .arg(uniqueDestinations);
                addReason(text,
                          m_threshold + uniqueDestinations / 10.0,
                          QStringLiteral("scan"),
                          snapshot.rowsBySource.value(source));
                QVariantMap record;
                record.insert(QStringLiteral("source"), source);
                record.insert(QStringLiteral("uniqueDestinations"), uniqueDestinations);
                record.insert(QStringLiteral("packets"), srcPackets);
                record.insert(QStringLiteral("share"), share);
                aggressiveSources.append(record);
            }
        }
    }

    if (!snapshot.sourcePackets.isEmpty() && totalPackets > 0.0) {
        QString heavySource;
        int heavyPackets = 0;
        for (auto it = snapshot.sourcePackets.constBegin(); it != snapshot.sourcePackets.constEnd(); ++it) {
            if (it.value() > heavyPackets) {
                heavyPackets = it.value();
                heavySource = it.key();
            }
        }
        const double share = heavyPackets / qMax(totalPackets, 1.0);
        if (!heavySource.isEmpty() && share >= 0.55 && heavyPackets >= 30) {
            const QString text = tr("Dominant source %1 (%2% of packets)")
                                     .arg(heavySource)
                                     .arg(share * 100.0, 0, 'f', 1);
            addReason(text,
                      m_threshold + share * 1.5,
                      QStringLiteral("top-source"),
                      snapshot.rowsBySource.value(heavySource));
        }
    }

    if (!ddosTargets.isEmpty()) {
        details.insert(QStringLiteral("ddosTargets"), ddosTargets);
    }
    if (!aggressiveSources.isEmpty()) {
        details.insert(QStringLiteral("aggressiveSources"), aggressiveSources);
    }

    if (reasons.isEmpty()) {
        return;
    }

    double score = 0.0;
    for (double c : contributions) {
        score = qMax(score, c);
    }

    if (!tags.isEmpty()) {
        details.insert(QStringLiteral("tags"), tags);
    }

    Event event;
    event.second = snapshot.second;
    event.score = score;
    event.reasons = reasons;
    event.tags = tags;
    event.details = details;
    event.packetRows = collectedRows;
    event.summary = tr("Anomaly at %1s: %2")
                        .arg(snapshot.second)
                        .arg(reasons.join(QStringLiteral("; ")));

    emit anomalyDetected(event);
}

QStringList AnomalyDetector::describeDominantProtocols(const QMap<QString, int> &protocolCounts,
                                                       double totalPackets) const
{
    if (protocolCounts.isEmpty() || totalPackets <= 0.0) {
        return {};
    }

    QList<QPair<QString, double>> shares;
    shares.reserve(protocolCounts.size());
    for (auto it = protocolCounts.constBegin(); it != protocolCounts.constEnd(); ++it) {
        const double share = static_cast<double>(it.value()) / totalPackets;
        shares.append(qMakePair(it.key(), share));
    }

    std::sort(shares.begin(), shares.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });

    QStringList dominant;
    for (const auto &entry : shares) {
        if (entry.second < 0.65) {
            break;
        }
        const QString description = QStringLiteral("%1 %2%")
                                        .arg(entry.first)
                                        .arg(entry.second * 100.0, 0, 'f', 1);
        dominant.append(description);
    }
    return dominant;
}
