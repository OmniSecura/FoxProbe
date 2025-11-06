#ifndef STATISTICS_H
#define STATISTICS_H

#include <QObject>
#include <QDateTime>
#include <QHash>
#include <QMap>
#include <QPair>
#include <QQueue>
#include <QSet>
#include <QStringList>
#include <QVariantMap>
#include <QVector>
#include <memory>

#include "charts/ChartConfig.h"
#include "anomalydetector.h"

class Statistics : public QObject {
    Q_OBJECT
public:
    explicit Statistics(const QDateTime &sessionStart, QObject *parent = nullptr);
    ~Statistics();

    void recordPacket(const QDateTime &timestamp,
                      const QString &protocol,
                      const QString &src,
                      const QString &dst,
                      quint64 packetSize,
                      int packetRow);

    bool SaveStatsToJson(const QString &dirPath, bool finalizePending = false);
    QString lastFilePath() const;
    void finalizePendingData();

    const QVector<AnomalyDetector::Event> &anomalies() const;

    static QString defaultSessionsDir();

signals:
    void anomalyDetected(const AnomalyDetector::Event &event);

private:
    void finalizeSecond(int second);
    void finalizePendingSecond();
    void pruneHistory();
    void onAnomalyEvent(const AnomalyDetector::Event &event);

    QDateTime m_sessionStart;
    QDateTime m_sessionEnd;
    QMap<int, QMap<QString,int>> statsProtocolPerSecond;
    QMap<int, QSet<QPair<QString,QString>>> statsConnectionsPerSecond;
    QMap<int, quint64> statsBytesPerSecond;
    QMap<int, quint64> statsPacketsPerSecond;
    QMap<int, QMap<QString,int>> statsSourcePacketsPerSecond;
    QMap<int, QMap<QString,int>> statsDestinationPacketsPerSecond;
    QMap<int, QMap<QString,QSet<QString>>> statsSourceFanOutPerSecond;
    QMap<int, QMap<QString,QSet<QString>>> statsDestinationFanInPerSecond;
    QMap<int, QVector<int>> statsPacketRowsPerSecond;
    QMap<int, QMap<QString, QVector<int>>> statsRowsBySourcePerSecond;
    QMap<int, QMap<QString, QVector<int>>> statsRowsByDestinationPerSecond;
    QString m_lastFilePath;

    std::unique_ptr<AnomalyDetector> m_anomalyDetector;
    int m_activeSecond = -1;
    QQueue<int> m_recentHistorySeconds;
    QHash<QString, int> m_recentConnectionUsage;
    QHash<QString, int> m_recentProtocolUsage;
    int m_historyWindow = 30;
    QVector<AnomalyDetector::Event> m_anomalies;
};

#endif // STATISTICS_H
