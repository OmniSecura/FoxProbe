#ifndef APPSETTINGS_H
#define APPSETTINGS_H

#include <QSettings>
#include <QString>
#include <memory>

class AppSettings {
public:
    AppSettings();
    explicit AppSettings(QSettings &settings);

    QString defaultInterface() const;
    void setDefaultInterface(const QString &iface);

    QString lastUsedInterface() const;
    void setLastUsedInterface(const QString &iface);

    bool autoStartCapture() const;
    void setAutoStartCapture(bool enabled);

    QString theme() const;
    void setTheme(const QString &theme);

    QString reportsDirectory() const;
    void setReportsDirectory(const QString &path);

    QString anomaliesDirectory() const;
    void setAnomaliesDirectory(const QString &path);

    QString sessionsDirectory() const;
    void setSessionsDirectory(const QString &path);

    bool promiscuousMode() const;
    void setPromiscuousMode(bool enabled);

    QString defaultFilter() const;
    void setDefaultFilter(const QString &filter);

private:
    QSettings &settings() const;

    std::unique_ptr<QSettings> ownedSettings;
    QSettings *settingsPtr = nullptr;
};

#endif // APPSETTINGS_H
