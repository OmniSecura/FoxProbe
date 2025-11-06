#ifndef BARCHART_H
#define BARCHART_H

#include "ChartConfig.h"
using Mode = chart::Mode;

class BarChart : public QWidget {
    Q_OBJECT

public:
    // enum Mode { AllTime, CurrentSession, BySession };
    enum SortMode { Alphabetical, ByValue };

    explicit BarChart(QWidget *parent = nullptr);

    void setMode(Mode mode);
    void setSessionIndex(int idx);
    void setProtocolFilter(const QStringList &protocols);
    void setSortMode(SortMode sort);

    QStringList availableSessionLabels() const;
    QStringList availableProtocols() const;
    QMap<QString, qint64> currentPlot() const { return m_currentPlot; }

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *evt) override;
    void wheelEvent(QWheelEvent *event) override;

private:
    struct SessionData {
        QDateTime sessionStart;
        QDateTime sessionEnd;
        QMap<QString, qint64> protocolCounts;
    };

    QVector<SessionData>   m_sessions;
    Mode                   m_mode             = Mode::AllTime;
    int                    m_selectedSession  = -1;
    QStringList            m_protocolFilter;
    QMap<QString, qint64>  m_currentPlot;
    qint64                 m_totalCount      = 0;

    SortMode               m_sortMode         = ByValue;
    double                 m_zoom             = 1.0;
    QVector<QString>       m_barKeys;
    QVector<QRectF>        m_barRects;
    int                    m_hoverIndex       = -1;

    QFileSystemWatcher     m_watcher;
    QString                m_sessionsDir;

    void loadJson(const QString &dir);
    void rebuildAggregation();
    void rebuildKeysAndRects(const QRectF &area);
};

#endif // BARCHART_H
