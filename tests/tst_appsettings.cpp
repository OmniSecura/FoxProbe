#include <QtTest/QtTest>
#include <QTemporaryDir>

#include "appsettings.h"
#include "tst_appsettings.h"

void AppSettingsTest::defaults() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    const QString filePath = dir.filePath("settings.ini");
    QSettings settings(filePath, QSettings::IniFormat);
    AppSettings app(settings);

    QCOMPARE(app.defaultInterface(), QString());
    QCOMPARE(app.defaultFilter(), QString());
    QVERIFY(!app.autoStartCapture());
    QVERIFY(app.promiscuousMode());
}

void AppSettingsTest::roundTrip() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    const QString filePath = dir.filePath("settings.ini");
    QSettings settings(filePath, QSettings::IniFormat);
    AppSettings app(settings);

    app.setDefaultInterface("eth0");
    app.setDefaultFilter("tcp port 80");
    app.setAutoStartCapture(true);
    app.setPromiscuousMode(false);
    app.setReportsDirectory("/tmp/reports");
    app.setTheme("Dark");

    QCOMPARE(app.defaultInterface(), QStringLiteral("eth0"));
    QCOMPARE(app.defaultFilter(), QStringLiteral("tcp port 80"));
    QVERIFY(app.autoStartCapture());
    QVERIFY(!app.promiscuousMode());
    QCOMPARE(app.reportsDirectory(), QStringLiteral("/tmp/reports"));
    QCOMPARE(app.theme(), QStringLiteral("Dark"));
}
