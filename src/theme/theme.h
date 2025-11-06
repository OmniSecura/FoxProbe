#ifndef THEME_H
#define THEME_H

#include <QString>
#include <QStringList>
#include <QPalette>
#include <QColor>
#include <QSettings>
#include <QInputDialog>
#include <QColorDialog>
#include <QApplication>
#include <QStyleFactory>
#include <QJsonDocument>
#include <QJsonObject>
#include <QWidget>


namespace Theme {

    void loadTheme();
    void toggleTheme();         // going either way from light/dark to dark/light and saves it in config
    QString toggleActionText(); // RETURNS DARK/LIGHT MOE
    bool isDarkMode();

    void applyTheme(const QString &name);
    QPalette paletteForName(const QString &name);

    void saveCustomPalette(const QString &name,
                        const QColor &window,
                        const QColor &bg,
                        const QColor &text,
                        const QColor &button,
                        const QColor &buttonText,
                        const QColor &alternateBase = QColor(),
                        const QColor &highlight = QColor(),
                        const QColor &highlightedText = QColor());

    QColor barColor();

    QStringList availableContexts();
    QString contextLabel(const QString &contextKey);
    QString defaultContextKey();
    QString mainWindowContextKey();
    QString statisticsContextKey();
    QString geoOverviewContextKey();
    QString sessionManagerContextKey();

    QPalette paletteForContext(const QString &contextKey);
    void saveContextPalette(const QString &contextKey, const QPalette &palette);
    void clearContextPalette(const QString &contextKey);
    void applyTo(QWidget *widget, const QString &contextKey);
}

#endif // THEME_H
