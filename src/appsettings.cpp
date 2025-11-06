#include "appsettings.h"

#include <QtGlobal>
#include <QCoreApplication>
#include <QDir>

namespace {
constexpr const char *kOrganization = "Engineering";
constexpr const char *kApplication  = "FoxProbe";
constexpr const char *kDefaultInterfaceKey = "Preferences/DefaultInterface";
constexpr const char *kLastInterfaceKey    = "State/LastInterface";
constexpr const char *kAutoStartKey        = "Preferences/AutoStartCapture";
constexpr const char *kThemeKey            = "Theme";
constexpr const char *kReportsDirKey       = "Preferences/ReportsDirectory";
constexpr const char *kPromiscuousKey      = "Preferences/Promiscuous";
constexpr const char *kDefaultFilterKey    = "Preferences/DefaultFilter";
constexpr const char *kAnomaliesDirKey     = "Preferences/AnomaliesDirectory";
constexpr const char *kSessionsDirKey      = "Preferences/SessionsDirectory";
}

AppSettings::AppSettings()
    : ownedSettings(std::make_unique<QSettings>(kOrganization, kApplication)),
      settingsPtr(ownedSettings.get())
{
}

AppSettings::AppSettings(QSettings &settings)
    : settingsPtr(&settings)
{
}

QString AppSettings::defaultInterface() const {
    return settings().value(kDefaultInterfaceKey).toString();
}

void AppSettings::setDefaultInterface(const QString &iface) {
    settings().setValue(kDefaultInterfaceKey, iface);
}

QString AppSettings::lastUsedInterface() const {
    return settings().value(kLastInterfaceKey).toString();
}

void AppSettings::setLastUsedInterface(const QString &iface) {
    settings().setValue(kLastInterfaceKey, iface);
}

bool AppSettings::autoStartCapture() const {
    return settings().value(kAutoStartKey, false).toBool();
}

void AppSettings::setAutoStartCapture(bool enabled) {
    settings().setValue(kAutoStartKey, enabled);
}

QString AppSettings::theme() const {
    return settings().value(kThemeKey, QStringLiteral("Light")).toString();
}

void AppSettings::setTheme(const QString &theme) {
    settings().setValue(kThemeKey, theme);
}

QString AppSettings::reportsDirectory() const {
    QDir dir(QDir::currentPath());
    const QString fallback = dir.filePath(QStringLiteral("reporting"));
    const QString configured = settings().value(kReportsDirKey).toString();
    return configured.isEmpty() ? fallback : configured;
}

void AppSettings::setReportsDirectory(const QString &path) {
    settings().setValue(kReportsDirKey, path);
}

QString AppSettings::anomaliesDirectory() const {
    const QString fallback = reportsDirectory() + QStringLiteral("/anomalies");
    const QString configured = settings().value(kAnomaliesDirKey).toString();
    return configured.isEmpty() ? fallback : configured;
}

void AppSettings::setAnomaliesDirectory(const QString &path) {
    settings().setValue(kAnomaliesDirKey, path);
}

QString AppSettings::sessionsDirectory() const {
    const QString fallback = QCoreApplication::applicationDirPath()
                             + QStringLiteral("/src/statistics/sessions");
    const QString configured = settings().value(kSessionsDirKey).toString();
    return configured.isEmpty() ? fallback : configured;
}

void AppSettings::setSessionsDirectory(const QString &path) {
    settings().setValue(kSessionsDirKey, path);
}

bool AppSettings::promiscuousMode() const {
    return settings().value(kPromiscuousKey, true).toBool();
}

void AppSettings::setPromiscuousMode(bool enabled) {
    settings().setValue(kPromiscuousKey, enabled);
}

QString AppSettings::defaultFilter() const {
    return settings().value(kDefaultFilterKey).toString();
}

void AppSettings::setDefaultFilter(const QString &filter) {
    settings().setValue(kDefaultFilterKey, filter);
}

QSettings &AppSettings::settings() const {
    Q_ASSERT(settingsPtr);
    return *settingsPtr;
}
