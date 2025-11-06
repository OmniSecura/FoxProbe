#ifndef SESSIONSTORAGE_H
#define SESSIONSTORAGE_H

#include <QDateTime>
#include <QJsonDocument>
#include <QVector>
#include <QString>
#include <QStringList>
#include <optional>

#include "../../packets/sniffing.h"

namespace SessionStorage {

struct SessionRecord {
    QString displayName;
    QString jsonPath;
    QString pcapPath;
    QDateTime startTime;
    QDateTime endTime;
    int totalPackets = 0;
    qint64 totalBytes = 0;
    QStringList protocols;
    bool hasPcap = false;
};

struct LoadedSession {
    SessionRecord record;
    QJsonDocument statsDocument;
    QVector<CapturedPacket> packets;
};

QString sessionsDirectory();
QVector<SessionRecord> listSessions();
std::optional<LoadedSession> loadSession(const SessionRecord &record);

} // namespace SessionStorage

#endif // SESSIONSTORAGE_H
