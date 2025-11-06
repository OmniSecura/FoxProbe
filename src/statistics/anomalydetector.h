#ifndef ANOMALYDETECTOR_H
#define ANOMALYDETECTOR_H

#include <QObject>
#include <QMap>
#include <QMetaType>
#include <QStringList>
#include <QVariantMap>
#include <QVector>

class AnomalyDetector : public QObject {
    Q_OBJECT
public:
    struct FeatureSnapshot {
        int second = 0;
        double packets = 0.0;
        double bytes = 0.0;
        double avgPacketSize = 0.0;
        int uniqueConnections = 0;
        int newConnections = 0;
        double protocolEntropy = 0.0;
        int protocolCount = 0;
        QStringList newProtocols;
        QMap<QString, int> protocolCounts;
        QMap<QString, int> sourcePackets;
        QMap<QString, int> destinationPackets;
        QMap<QString, int> destinationFanIn;
        QMap<QString, int> sourceFanOut;
        QMap<QString, QVector<int>> rowsBySource;
        QMap<QString, QVector<int>> rowsByDestination;
        QVector<int> packetRows;
    };

    struct Event {
        int second = 0;
        double score = 0.0;
        QString summary;
        QStringList reasons;
        QStringList tags;
        QVariantMap details;
        QVector<int> packetRows;
    };

    explicit AnomalyDetector(QObject *parent = nullptr);

    void observe(const FeatureSnapshot &snapshot);

signals:
    void anomalyDetected(const AnomalyDetector::Event &event);

private:
    class AdaptiveMetric {
    public:
        explicit AdaptiveMetric(double alpha = 0.2);

        double updateAndScore(double value, int warmup);
        void reset();

    private:
        double m_alpha;
        bool m_initialized = false;
        double m_mean = 0.0;
        double m_variance = 1.0;
        int m_count = 0;
    };

    AdaptiveMetric m_packetMetric;
    AdaptiveMetric m_byteMetric;
    AdaptiveMetric m_connectionMetric;
    AdaptiveMetric m_newConnectionMetric;
    AdaptiveMetric m_entropyMetric;
    AdaptiveMetric m_avgPacketMetric;

    double m_threshold;
    int m_warmup;

    QStringList describeDominantProtocols(const QMap<QString, int> &protocolCounts,
                                          double totalPackets) const;
};

Q_DECLARE_METATYPE(AnomalyDetector::Event)

#endif // ANOMALYDETECTOR_H
