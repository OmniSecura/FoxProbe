#ifndef GEOLOCATION_H
#define GEOLOCATION_H

#include <QString>
#include <QVector>
#include <QPair>
#include <QStringList>
#include <algorithm>
#include <QCoreApplication>
#include <maxminddb.h>

struct GeoStruct {
   QString name;
   QVector<QPair<QString, QString>> fields;  // { label, value }
};

class GeoLocation {
public:
   GeoLocation();
   ~GeoLocation();

   QVector<GeoStruct> GeoVector(const QString& src, const QString& dst);

private:
   MMDB_s mmdb;
   bool dbOpened = false;
};

#endif // GEOLOCATION_H
