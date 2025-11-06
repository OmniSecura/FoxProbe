
#ifndef TST_APPSETTINGS_H
#define TST_APPSETTINGS_H

#include <QObject>

class AppSettingsTest : public QObject
{
    Q_OBJECT

private slots:
    void defaults();
    void roundTrip();
};

#endif // TST_APPSETTINGS_H
