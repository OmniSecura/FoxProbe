#include "geolocation.h"

static QString dbPath()
{
    return QCoreApplication::applicationDirPath() + "/packets/packet_geolocation/GeoLite2-City.mmdb";
}

GeoLocation::GeoLocation()
{
    if (MMDB_open(dbPath().toUtf8().constData(), MMDB_MODE_MMAP, &mmdb) == MMDB_SUCCESS)
        dbOpened = true;
}

GeoLocation::~GeoLocation()
{
    if (dbOpened)
        MMDB_close(&mmdb);
}

QVector<GeoStruct> GeoLocation::GeoVector(const QString& src, const QString& dst) {
    static const QStringList labels = {
        "Country", "City", "Region",
        "Postal Code", "Latitude", "Longitude"
    };

    auto lookup = [&](const QString& ip) -> QStringList {
        QString rawIp = ip;
        if (rawIp.startsWith('[')) {
            // [addr]:port
            int end = rawIp.indexOf(']');
            if (end > 0) rawIp = rawIp.mid(1, end - 1);
        } else if (rawIp.contains('.') && rawIp.count(':') == 1) {
            // IPv4:port
            rawIp = rawIp.section(':', 0, 0);
        }
        // Delete zone in IPv6 (ex. fe80::1%eth0)
        if (rawIp.contains('%')) {
            rawIp = rawIp.section('%', 0, 0);
        }

        QStringList res(6, "-");
        if (!dbOpened)
            return res;
        
        int gai_err = 0, mmdb_err = 0;
        MMDB_lookup_result_s lr = MMDB_lookup_string(
            &mmdb,
            rawIp.toUtf8().constData(),
            &gai_err,
            &mmdb_err
        );
        if (gai_err || mmdb_err != MMDB_SUCCESS || !lr.found_entry) {
            return res;
        }
        MMDB_entry_data_s entry;
        if (MMDB_get_value(&lr.entry, &entry, "country","names","en",NULL) == MMDB_SUCCESS && entry.has_data)
            res[0] = QString::fromUtf8(entry.utf8_string, entry.data_size);
        if (MMDB_get_value(&lr.entry, &entry, "city","names","en",NULL) == MMDB_SUCCESS && entry.has_data)
            res[1] = QString::fromUtf8(entry.utf8_string, entry.data_size);
        if (MMDB_get_value(&lr.entry, &entry, "subdivisions","0","names","en",NULL) == MMDB_SUCCESS && entry.has_data)
            res[2] = QString::fromUtf8(entry.utf8_string, entry.data_size);
        if (MMDB_get_value(&lr.entry, &entry, "postal","code",NULL) == MMDB_SUCCESS && entry.has_data)
            res[3] = QString::fromUtf8(entry.utf8_string, entry.data_size);
        if (MMDB_get_value(&lr.entry, &entry, "location","latitude",NULL) == MMDB_SUCCESS && entry.has_data)
            res[4] = QString::number(entry.double_value);
        if (MMDB_get_value(&lr.entry, &entry, "location","longitude",NULL) == MMDB_SUCCESS && entry.has_data)
            res[5] = QString::number(entry.double_value);
        return res;
    };

    QVector<GeoStruct> out;
    const QPair<QString,QString> ips[2] = {
        { "Source IP", src },
        { "Destination IP", dst }
    };

    for (const auto &p : ips) {
        QStringList vals = lookup(p.second);
        bool anyValid = std::any_of(vals.begin(), vals.end(),
                                    [](const QString &v){ return v != "-"; });
        if (!anyValid) continue;

        GeoStruct g;
        g.name = QString("%1: %2").arg(p.first, p.second);
        for (int i = 0; i < labels.size(); ++i)
            g.fields.append({ labels[i], vals.value(i) });
        out.append(std::move(g));
    }
    return out;
}
