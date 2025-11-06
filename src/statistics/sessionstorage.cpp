#include "sessionstorage.h"

#include "statistics.h"
#include "../../packets/sniffing.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <algorithm>

namespace SessionStorage {

namespace {

QString baseNameFor(const QString &path)
{
    QFileInfo info(path);
    return info.completeBaseName();
}

}

QString sessionsDirectory()
{
    return Statistics::defaultSessionsDir();
}

QVector<SessionRecord> listSessions()
{
    QVector<SessionRecord> records;
    const QString dirPath = sessionsDirectory();
    QDir dir(dirPath);
    if (!dir.exists()) {
        return records;
    }

    const QStringList files = dir.entryList({"*.json"}, QDir::Files, QDir::Name);
    records.reserve(files.size());

    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject()) {
            continue;
        }

        const QJsonObject obj = doc.object();
        SessionRecord record;
        record.jsonPath = dir.filePath(fileName);
        record.pcapPath = dir.filePath(baseNameFor(fileName) + ".pcap");
        record.startTime = QDateTime::fromString(obj.value("sessionStart").toString(), Qt::ISODate);
        record.endTime = QDateTime::fromString(obj.value("sessionEnd").toString(), Qt::ISODate);

        const QJsonArray perSecond = obj.value("perSecond").toArray();
        QSet<QString> protocols;
        qint64 totalBytes = 0;
        int totalPackets = 0;
        for (const QJsonValue &value : perSecond) {
            const QJsonObject secondObj = value.toObject();
            const QJsonObject protoCounts = secondObj.value("protocolCounts").toObject();
            for (auto it = protoCounts.begin(); it != protoCounts.end(); ++it) {
                totalPackets += it.value().toInt();
                protocols.insert(it.key());
            }
            totalBytes += static_cast<qint64>(secondObj.value("bps").toDouble());
        }

        record.totalPackets = totalPackets;
        record.totalBytes = totalBytes;
        QStringList protocolList = protocols.values();
        std::sort(protocolList.begin(), protocolList.end());
        record.protocols = protocolList;
        record.hasPcap = QFileInfo::exists(record.pcapPath);
        if (record.startTime.isValid() && record.endTime.isValid()) {
            record.displayName = QStringLiteral("%1 → %2")
                .arg(record.startTime.toString(Qt::ISODate))
                .arg(record.endTime.toString(Qt::ISODate));
        } else {
            record.displayName = fileName;
        }

        records.append(record);
    }

    std::sort(records.begin(), records.end(), [](const SessionRecord &a, const SessionRecord &b) {
        return a.startTime < b.startTime;
    });

    return records;
}

std::optional<LoadedSession> loadSession(const SessionRecord &record)
{
    if (!QFileInfo::exists(record.jsonPath) || !record.hasPcap) {
        return std::nullopt;
    }

    QFile jsonFile(record.jsonPath);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        return std::nullopt;
    }

    LoadedSession session;
    session.record = record;
    session.statsDocument = QJsonDocument::fromJson(jsonFile.readAll());
    jsonFile.close();
    if (session.statsDocument.isNull()) {
        return std::nullopt;
    }

    Sniffing sniffer;
    sniffer.openFromPcap(record.pcapPath);
    session.packets = Sniffing::getAllPackets();
    sniffer.clearBuffer();

    return session;
}

} // namespace SessionStorage