#include "tst_statistics.h"

#include <QDate>
#include <QDateTime>
#include <QTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include "../src/statistics/statistics.h"
#include "../src/statistics/sessionstorage.h"
#include "../src/statistics/anomalydetector.h"

void StatisticsTest::aggregatesAndSaves()
{
    const QDateTime start(QDate(2024, 1, 1), QTime(0, 0, 0), Qt::UTC);
    Statistics stats(start);

    stats.recordPacket(start,
                       QStringLiteral("TCP"),
                       QStringLiteral("10.0.0.1"),
                       QStringLiteral("10.0.0.2"),
                       100,
                       0);
    stats.recordPacket(start,
                       QStringLiteral("UDP"),
                       QStringLiteral("10.0.0.3"),
                       QStringLiteral("10.0.0.4"),
                       50,
                       1);

    const QDateTime secondOne = start.addSecs(1);
    stats.recordPacket(secondOne,
                       QStringLiteral("TCP"),
                       QStringLiteral("10.0.0.1"),
                       QStringLiteral("10.0.0.2"),
                       80,
                       2);

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    QVERIFY(stats.SaveStatsToJson(dir.path(), true));

    QString startStr = start.toString(Qt::ISODate);
    QString endStr = secondOne.toString(Qt::ISODate);
    startStr.replace(":", "-");
    endStr.replace(":", "-");
    const QString jsonPath = dir.filePath(startStr + QLatin1Char('-') + endStr + QStringLiteral(".json"));

    QFile file(jsonPath);
    QVERIFY2(file.exists(), qPrintable(QStringLiteral("Expected statistics file %1").arg(jsonPath)));
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    QVERIFY(doc.isObject());

    const QJsonObject root = doc.object();
    QCOMPARE(root.value(QStringLiteral("sessionStart")).toString(), start.toString(Qt::ISODate));
    QCOMPARE(root.value(QStringLiteral("sessionEnd")).toString(), secondOne.toString(Qt::ISODate));

    const QJsonArray perSecond = root.value(QStringLiteral("perSecond")).toArray();
    QCOMPARE(perSecond.size(), 2);

    const QJsonObject first = perSecond.at(0).toObject();
    QCOMPARE(first.value(QStringLiteral("second")).toInt(), 0);
    QCOMPARE(first.value(QStringLiteral("pps")).toDouble(), 2.0);
    QCOMPARE(first.value(QStringLiteral("bps")).toDouble(), 150.0);

    const QJsonObject protoCounts = first.value(QStringLiteral("protocolCounts")).toObject();
    QCOMPARE(protoCounts.value(QStringLiteral("TCP")).toInt(), 1);
    QCOMPARE(protoCounts.value(QStringLiteral("UDP")).toInt(), 1);

    const QJsonObject second = perSecond.at(1).toObject();
    QCOMPARE(second.value(QStringLiteral("second")).toInt(), 1);
    QCOMPARE(second.value(QStringLiteral("pps")).toDouble(), 1.0);
    QCOMPARE(second.value(QStringLiteral("bps")).toDouble(), 80.0);
}

void StatisticsTest::emitsAnomalies()
{
    const QDateTime start(QDate(2024, 1, 1), QTime(0, 0, 0), Qt::UTC);
    Statistics stats(start);
    QSignalSpy spy(&stats, &Statistics::anomalyDetected);

    for (int i = 0; i < 6; ++i) {
        const QDateTime timestamp = start.addSecs(i);
        stats.recordPacket(timestamp,
                           QStringLiteral("TCP"),
                           QStringLiteral("192.0.2.1"),
                           QStringLiteral("198.51.100.2"),
                           64,
                           i);
    }

    const QDateTime spikeSecond = start.addSecs(6);
    for (int i = 0; i < 200; ++i) {
        stats.recordPacket(spikeSecond,
                           QStringLiteral("TCP"),
                           QStringLiteral("192.0.2.1"),
                           QStringLiteral("198.51.100.2"),
                           1500,
                           i);
    }

    stats.recordPacket(start.addSecs(7),
                       QStringLiteral("TCP"),
                       QStringLiteral("192.0.2.1"),
                       QStringLiteral("198.51.100.2"),
                       64,
                       0);
    stats.finalizePendingData();

    QVERIFY(spy.count() > 0);
    const QVariant firstEventVariant = spy.takeFirst().at(0);
    QVERIFY(firstEventVariant.canConvert<AnomalyDetector::Event>());
    const auto event = qvariant_cast<AnomalyDetector::Event>(firstEventVariant);
    QVERIFY(!event.summary.isEmpty());
    QVERIFY(!event.reasons.isEmpty());
    QVERIFY(event.score > 0.0);
}

void StatisticsTest::loadSessionRoundTrip()
{
    const QDateTime start(QDate(2024, 1, 1), QTime(0, 0, 0), Qt::UTC);
    const QDateTime end = start.addSecs(1);
    Statistics stats(start);

    stats.recordPacket(start,
                       QStringLiteral("TCP"),
                       QStringLiteral("203.0.113.10"),
                       QStringLiteral("203.0.113.20"),
                       128,
                       0);
    stats.recordPacket(end,
                       QStringLiteral("UDP"),
                       QStringLiteral("203.0.113.10"),
                       QStringLiteral("203.0.113.21"),
                       256,
                       1);

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    QVERIFY(stats.SaveStatsToJson(dir.path(), true));

    QString startStr = start.toString(Qt::ISODate);
    QString endStr = end.toString(Qt::ISODate);
    startStr.replace(":", "-");
    endStr.replace(":", "-");
    const QString jsonPath = dir.filePath(startStr + QLatin1Char('-') + endStr + QStringLiteral(".json"));
    QFileInfo jsonInfo(jsonPath);
    QVERIFY(jsonInfo.exists());

    const QString pcapPath = dir.filePath(jsonInfo.completeBaseName() + QStringLiteral(".pcap"));
    QVERIFY(QFile::copy(QStringLiteral("../test.pcap"), pcapPath));

    SessionStorage::SessionRecord record;
    record.jsonPath = jsonPath;
    record.pcapPath = pcapPath;
    record.hasPcap = true;
    record.startTime = start;
    record.endTime = end;

    auto loaded = SessionStorage::loadSession(record);
    QVERIFY(loaded.has_value());
    QVERIFY(loaded->statsDocument.isObject());
    QVERIFY(!loaded->packets.isEmpty());
}