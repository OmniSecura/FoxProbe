#ifndef TST_STATISTICS_H
#define TST_STATISTICS_H

#include <QObject>

class StatisticsTest : public QObject
{
    Q_OBJECT
private slots:
    void aggregatesAndSaves();
    void emitsAnomalies();
    void loadSessionRoundTrip();
};

#endif // TST_STATISTICS_H