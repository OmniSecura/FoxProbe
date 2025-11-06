#ifndef LINECHART_H
#define LINECHART_H

#include "ChartConfig.h"
using Mode = chart::Mode;

class LineChart : public QWidget {
    Q_OBJECT

public:
    // enum Mode { AllTime, CurrentSession, BySession };
    enum Metric { PacketsPerSecond, BytesPerSecond, BitsPerSecond, AvgPacketSize };
    enum Resolution { Seconds = 0, Minutes = 1, Hours = 2 };

    explicit LineChart(QWidget *parent = nullptr);

    void setMode(Mode mode);
    void setSessionIndex(int idx);
    void setMetric(Metric metric);
    void setResolution(Resolution res);

    QStringList availableSessionLabels() const;
    QStringList availableMetrics() const;

    QVector<QPointF> currentData() const { return m_points; }

protected:
    void paintEvent(QPaintEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    struct SessionData {
        QDateTime start;
        QDateTime end;
        QMap<int, qint64> bytesPerSecond;
        QMap<int, qint64> packetsPerSecond;
    };

    QVector<SessionData>   m_sessions;
    Mode                   m_mode             = Mode::AllTime;
    int                    m_selectedSession = -1;
    Metric                 m_metric          = PacketsPerSecond;
    Resolution             m_resolution      = Seconds;     
    QFileSystemWatcher     m_watcher;
    QString                m_sessionsDir;
    double                 m_zoom            = 1.0;

    QVector<QPointF>       m_points;
    double                 m_maxX            = 0;
    double                 m_maxY            = 0;

    void loadJson(const QString &dir);
    void rebuildData();
};

#endif // LINECHART_H
