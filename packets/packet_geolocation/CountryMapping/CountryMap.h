#ifndef COUNTRYMAP_H
#define COUNTRYMAP_H
#include <QHash>
#include <QString>

namespace CountryMap {
    const QHash<QString, QString>& nameToIso();
}
#endif //COUNTRYMAP_H