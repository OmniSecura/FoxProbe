#include "statistics.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

#include "../appsettings.h"

#include <algorithm>
#include <cmath>
#include <QString>

namespace {
QString connectionKey(const QPair<QString, QString> &connection)
{
    return connection.first + QLatin1Char('|') + connection.second;
}
}

Statistics::Statistics(const QDateTime &sessionStart, QObject *parent)
    : QObject(parent),
      m_sessionStart(sessionStart),
      m_sessionEnd(sessionStart),
      m_anomalyDetector(std::make_unique<AnomalyDetector>())
{
    connect(m_anomalyDetector.get(), &AnomalyDetector::anomalyDetected,
            this, &Statistics::onAnomalyEvent);
}

Statistics::~Statistics()
{
    finalizePendingSecond();
}

void Statistics::recordPacket(const QDateTime &timestamp,
                              const QString &protocol,
                              const QString &src,
                              const QString &dst,
                              quint64 packetSize,
                              int packetRow)
{
    const int sec = static_cast<int>(m_sessionStart.secsTo(timestamp));
    if (sec < 0) {
        return;
    }

    if (timestamp > m_sessionEnd) {
        m_sessionEnd = timestamp;
    }

    if (m_activeSecond == -1) {
        m_activeSecond = sec;
    } else if (sec > m_activeSecond) {
        finalizeSecond(m_activeSecond);
        m_activeSecond = sec;
    }

    statsProtocolPerSecond[sec][protocol] += 1;
    statsConnectionsPerSecond[sec].insert(qMakePair(src, dst));
    statsBytesPerSecond[sec] += packetSize;
    statsPacketsPerSecond[sec] += 1;
    statsSourcePacketsPerSecond[sec][src] += 1;
    statsDestinationPacketsPerSecond[sec][dst] += 1;
    statsSourceFanOutPerSecond[sec][src].insert(dst);
    statsDestinationFanInPerSecond[sec][dst].insert(src);

    if (packetRow >= 0) {
        statsPacketRowsPerSecond[sec].append(packetRow);
        statsRowsBySourcePerSecond[sec][src].append(packetRow);
        statsRowsByDestinationPerSecond[sec][dst].append(packetRow);
    }
}

bool Statistics::SaveStatsToJson(const QString &dirPath, bool finalizePending)
{
    if (finalizePending) {
        finalizePendingSecond();
    }

    if (statsProtocolPerSecond.isEmpty()) {
        return true;
    }

    QDir dir;
    if (!dir.mkpath(dirPath)) {
        qWarning() << "Failed to create statistics directory" << dirPath;
        return false;
    }
    QString startStr = m_sessionStart.toString(Qt::ISODate);
    QString endStr   = m_sessionEnd.toString(Qt::ISODate);
    startStr.replace(":", "-");
    endStr.replace(":", "-");
    const QString filePath = QDir(dirPath).filePath(startStr + "-" + endStr + ".json");

    const QString previousFile = m_lastFilePath;

    QJsonObject sessionObj;
    sessionObj.insert("sessionStart", m_sessionStart.toString(Qt::ISODate));
    sessionObj.insert("sessionEnd",   m_sessionEnd.toString(Qt::ISODate));

    QJsonArray perSecondArray;
    QList<int> seconds = statsProtocolPerSecond.keys();
    std::sort(seconds.begin(), seconds.end());
    for (int sec : seconds) {
        QJsonObject secondObj;
        secondObj.insert("second", sec);

        QJsonObject protoCountsObj;
        const auto protoCounts = statsProtocolPerSecond.value(sec);
        for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it) {
            protoCountsObj.insert(it.key(), it.value());
        }
        secondObj.insert("protocolCounts", protoCountsObj);

        QJsonArray connArray;
        const auto connections = statsConnectionsPerSecond.value(sec);
        for (const auto &p : connections) {
            QJsonObject c;
            c.insert("src", p.first);
            c.insert("dst", p.second);
            connArray.append(c);
        }
        secondObj.insert("connections", connArray);

        const quint64 packets = statsPacketsPerSecond.value(sec, 0ULL);
        const quint64 bytes   = statsBytesPerSecond.value(sec, 0ULL);
        const double avgPacketSize = packets > 0
            ? static_cast<double>(bytes) / static_cast<double>(packets)
            : 0.0;
        secondObj.insert("avgPacketSize", avgPacketSize);
        secondObj.insert("pps", static_cast<double>(packets));
        secondObj.insert("bps", static_cast<double>(bytes));

        perSecondArray.append(secondObj);
    }
    sessionObj.insert("perSecond", perSecondArray);

    QJsonDocument newDoc(sessionObj);
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "Unable to open statistics file for writing" << filePath;
        return false;
    }

    const QByteArray payload = newDoc.toJson();
    const qint64 written = file.write(payload);
    if (written != payload.size()) {
        qWarning() << "Short write while saving statistics" << filePath
                   << "expected" << payload.size() << "bytes" << "wrote" << written;
        file.close();
        file.remove();
        return false;
    }

    if (!file.flush()) {
        qWarning() << "Failed to flush statistics file" << filePath;
        file.close();
        file.remove();
        return false;
    }

    file.close();

    if (!previousFile.isEmpty() && previousFile != filePath) {
        QFile::remove(previousFile);
    }
    m_lastFilePath = filePath;
    return true;
}

QString Statistics::lastFilePath() const
{
    return m_lastFilePath;
}

void Statistics::finalizePendingData()
{
    finalizePendingSecond();
}

const QVector<AnomalyDetector::Event> &Statistics::anomalies() const
{
    return m_anomalies;
}

QString Statistics::defaultSessionsDir()
{
    AppSettings settings;
    QString directory = settings.sessionsDirectory();
    if (directory.isEmpty()) {
        directory = QCoreApplication::applicationDirPath()
                    + QStringLiteral("/src/statistics/sessions");
    }
    QDir().mkpath(directory);
    return directory;
}

void Statistics::finalizeSecond(int second)
{
    if (!m_anomalyDetector || second < 0) {
        return;
    }

    const auto protoCounts = statsProtocolPerSecond.value(second);
    const auto connections = statsConnectionsPerSecond.value(second);
    const quint64 packets = statsPacketsPerSecond.value(second, 0ULL);
    const quint64 bytes = statsBytesPerSecond.value(second, 0ULL);
    const auto sourceCounts = statsSourcePacketsPerSecond.value(second);
    const auto destinationCounts = statsDestinationPacketsPerSecond.value(second);
    const auto fanOutMap = statsSourceFanOutPerSecond.value(second);
    const auto fanInMap = statsDestinationFanInPerSecond.value(second);
    const auto packetRows = statsPacketRowsPerSecond.value(second);
    const auto rowsBySource = statsRowsBySourcePerSecond.value(second);
    const auto rowsByDestination = statsRowsByDestinationPerSecond.value(second);
    const double avgPacketSize = packets > 0
        ? static_cast<double>(bytes) / static_cast<double>(packets)
        : 0.0;

    int newConnections = 0;
    for (const auto &conn : connections) {
        const QString key = connectionKey(conn);
        if (!m_recentConnectionUsage.contains(key)) {
            ++newConnections;
        }
    }

    QStringList newProtocols;
    for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it) {
        if (!m_recentProtocolUsage.contains(it.key())) {
            newProtocols.append(it.key());
        }
    }

    double entropy = 0.0;
    if (packets > 0) {
        const double totalPackets = static_cast<double>(packets);
        for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it) {
            const double probability = static_cast<double>(it.value()) / totalPackets;
            if (probability > 0.0) {
                entropy -= probability * std::log2(probability);
            }
        }
    }

    AnomalyDetector::FeatureSnapshot snapshot;
    snapshot.second = second;
    snapshot.packets = static_cast<double>(packets);
    snapshot.bytes = static_cast<double>(bytes);
    snapshot.avgPacketSize = avgPacketSize;
    snapshot.uniqueConnections = connections.size();
    snapshot.newConnections = newConnections;
    snapshot.protocolEntropy = entropy;
    snapshot.protocolCount = protoCounts.size();
    snapshot.newProtocols = newProtocols;
    snapshot.protocolCounts = protoCounts;
    snapshot.sourcePackets = sourceCounts;
    snapshot.destinationPackets = destinationCounts;

    QMap<QString, int> fanOutCounts;
    for (auto it = fanOutMap.constBegin(); it != fanOutMap.constEnd(); ++it) {
        fanOutCounts.insert(it.key(), it.value().size());
    }
    snapshot.sourceFanOut = fanOutCounts;

    QMap<QString, int> fanInCounts;
    for (auto it = fanInMap.constBegin(); it != fanInMap.constEnd(); ++it) {
        fanInCounts.insert(it.key(), it.value().size());
    }
    snapshot.destinationFanIn = fanInCounts;

    snapshot.packetRows = packetRows;
    snapshot.rowsBySource = rowsBySource;
    snapshot.rowsByDestination = rowsByDestination;

    m_anomalyDetector->observe(snapshot);

    m_recentHistorySeconds.enqueue(second);
    for (const auto &conn : connections) {
        const QString key = connectionKey(conn);
        m_recentConnectionUsage[key] += 1;
    }
    for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it) {
        m_recentProtocolUsage[it.key()] += 1;
    }
    pruneHistory();
}

void Statistics::finalizePendingSecond()
{
    if (m_activeSecond >= 0) {
        finalizeSecond(m_activeSecond);
        m_activeSecond = -1;
    }
}

void Statistics::pruneHistory()
{
    while (m_recentHistorySeconds.size() > m_historyWindow) {
        const int oldSecond = m_recentHistorySeconds.dequeue();

        const auto oldConnections = statsConnectionsPerSecond.value(oldSecond);
        for (const auto &conn : oldConnections) {
            const QString key = connectionKey(conn);
            auto it = m_recentConnectionUsage.find(key);
            if (it != m_recentConnectionUsage.end()) {
                if (--(it.value()) <= 0) {
                    m_recentConnectionUsage.erase(it);
                }
            }
        }

        const auto oldProtoCounts = statsProtocolPerSecond.value(oldSecond);
        for (auto it = oldProtoCounts.constBegin(); it != oldProtoCounts.constEnd(); ++it) {
            auto usageIt = m_recentProtocolUsage.find(it.key());
            if (usageIt != m_recentProtocolUsage.end()) {
                if (--(usageIt.value()) <= 0) {
                    m_recentProtocolUsage.erase(usageIt);
                }
            }
        }
    }
}

void Statistics::onAnomalyEvent(const AnomalyDetector::Event &event)
{
    m_anomalies.append(event);
    emit anomalyDetected(event);
}
