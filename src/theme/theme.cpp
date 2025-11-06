#include "theme.h"

#include <QObject>
#include <QVector>

namespace Theme {
static bool g_dark = false;
static bool g_paletteInitialized = false;
static QPalette g_themePalette;
static QPalette g_effectivePalette;

namespace {

void syncWindowTextWithText(QPalette &palette)
{
    const QColor textColor = palette.color(QPalette::Text);
    if (textColor.isValid()) {
        palette.setColor(QPalette::WindowText, textColor);
    }
}

struct ContextInfo {
    QString key;
    QString label;
};

const QVector<ContextInfo> &contextTable()
{
    static const QVector<ContextInfo> contexts = {
        { QStringLiteral("default"),          QObject::tr("All windows (default)") },
        { QStringLiteral("MainWindow"),       QObject::tr("Main window") },
        { QStringLiteral("Statistics"),       QObject::tr("Statistics window") },
        { QStringLiteral("GeoOverview"),      QObject::tr("Geo overview window") },
        { QStringLiteral("SessionManager"),   QObject::tr("Session manager window") }
    };
    return contexts;
}

QString settingsKeyForContext(const QString &context)
{
    return QStringLiteral("ContextPalettes/%1").arg(context);
}

QPalette applyOverride(const QPalette &base, const QString &context)
{
    QSettings s("Engineering", "FoxProbe");
    const QByteArray raw = s.value(settingsKeyForContext(context)).toByteArray();
    if (raw.isEmpty()) {
        return base;
    }

    const QJsonObject o = QJsonDocument::fromJson(raw).object();
    QPalette p = base;
    auto setColor = [&](QPalette::ColorRole role, const char *name) {
        if (o.contains(QLatin1String(name))) {
            const QColor c(o.value(QLatin1String(name)).toString());
            if (c.isValid()) {
                p.setColor(role, c);
            }
        }
    };
    setColor(QPalette::Window,          "Window");
    setColor(QPalette::Base,            "Base");
    setColor(QPalette::AlternateBase,   "AlternateBase");
    setColor(QPalette::Text,            "Text");
    setColor(QPalette::Button,          "Button");
    setColor(QPalette::ButtonText,      "ButtonText");
    setColor(QPalette::Highlight,       "Highlight");
    setColor(QPalette::HighlightedText, "HighlightedText");
    syncWindowTextWithText(p);
    return p;
}

} // namespace

// built-ins
static QPalette buildGreenish() {
    QPalette p;
    p.setColor(QPalette::Window,    QColor(220,255,220));
    p.setColor(QPalette::Base,      QColor(245,255,245));
    p.setColor(QPalette::Text,      QColor(20,80,20));
    p.setColor(QPalette::Button,    QColor(200,240,200));
    p.setColor(QPalette::ButtonText,QColor(10,60,10));
    syncWindowTextWithText(p);
    return p;
}

static QPalette buildBlackOrange() {
    QPalette p;
    p.setColor(QPalette::Window,    QColor(30,30,30));
    p.setColor(QPalette::Base,      QColor(45,45,45));
    p.setColor(QPalette::Text,      QColor(255,165,0));
    p.setColor(QPalette::Button,    QColor(50,50,50));
    p.setColor(QPalette::ButtonText,QColor(255,140,0));
    syncWindowTextWithText(p);
    return p;
}

static QPalette loadPalette(const QString &key) {
    QSettings s("Engineering","FoxProbe");
    auto raw = s.value(key).toByteArray();
    QJsonObject o = QJsonDocument::fromJson(raw).object();
    QPalette p;
    if (o.contains("Window"))     p.setColor(QPalette::Window,    QColor(o["Window"].toString()));
    if (o.contains("Base"))       p.setColor(QPalette::Base,      QColor(o["Base"].toString()));
    if (o.contains("Text"))       p.setColor(QPalette::Text,      QColor(o["Text"].toString()));
    if (o.contains("Button"))     p.setColor(QPalette::Button,    QColor(o["Button"].toString()));
    if (o.contains("ButtonText")) p.setColor(QPalette::ButtonText,QColor(o["ButtonText"].toString()));
    if (o.contains("AlternateBase"))
        p.setColor(QPalette::AlternateBase, QColor(o["AlternateBase"].toString()));
    if (o.contains("Highlight"))
        p.setColor(QPalette::Highlight, QColor(o["Highlight"].toString()));
    if (o.contains("HighlightedText"))
        p.setColor(QPalette::HighlightedText, QColor(o["HighlightedText"].toString()));
    syncWindowTextWithText(p);
    return p;
}

void loadTheme() {
    QSettings s("Engineering","FoxProbe");
    QString t = s.value("Theme","Light").toString();
    g_dark = (t == "Dark");

    qApp->setStyle(QStyleFactory::create("Fusion"));
    QPalette p;
     if (t == "Light" || t == "Dark") {
        if (g_dark) {
            // === DARK ===
            p.setColor(QPalette::Window,          QColor(30,30,60));
            p.setColor(QPalette::WindowText,      QColor(210,210,230));
            p.setColor(QPalette::Base,            QColor(35,35,75));
            p.setColor(QPalette::AlternateBase,   QColor(45,45,95));
            p.setColor(QPalette::ToolTipBase,     QColor(210,210,230));
            p.setColor(QPalette::ToolTipText,     QColor(30,30,60));
            p.setColor(QPalette::Text,            QColor(230,230,250));
            p.setColor(QPalette::Button,          QColor(50,50,90));
            p.setColor(QPalette::ButtonText,      QColor(210,210,230));
            p.setColor(QPalette::Highlight,       QColor(70,130,180));
            p.setColor(QPalette::HighlightedText, Qt::white);
            p.setColor(QPalette::Link,            QColor(100,180,255));
        } else {
            // === LIGHT ===
            p.setColor(QPalette::Window,          QColor(245,245,255));
            p.setColor(QPalette::WindowText,      QColor(30,30,60));
            p.setColor(QPalette::Base,            QColor(255,255,255));
            p.setColor(QPalette::AlternateBase,   QColor(230,240,255));
            p.setColor(QPalette::ToolTipBase,     QColor(30,30,60));
            p.setColor(QPalette::ToolTipText,     QColor(245,245,255));
            p.setColor(QPalette::Text,            QColor(30,30,60));
            p.setColor(QPalette::Button,          QColor(225,235,255));
            p.setColor(QPalette::ButtonText,      QColor(30,30,60));
            p.setColor(QPalette::Highlight,       QColor(100,150,240));
            p.setColor(QPalette::HighlightedText, Qt::white);
            p.setColor(QPalette::Link,            QColor(0,102,204));
        }
        } else if (t == "Greenish") {
            p = buildGreenish();
        } else if (t == "Black+Orange") {
            p = buildBlackOrange();
        } else {
            p = loadPalette(QString("CustomThemes/%1").arg(t));
        }

    syncWindowTextWithText(p);
    g_themePalette = p;
    g_effectivePalette = applyOverride(g_themePalette, defaultContextKey());
    qApp->setPalette(g_effectivePalette);
    g_paletteInitialized = true;
}

void toggleTheme() {
    QSettings s("Engineering","FoxProbe");
    s.setValue("Theme", g_dark ? "Light" : "Dark");
    loadTheme();
}

QString toggleActionText() {
    return g_dark ? QStringLiteral("Light Mode")
                  : QStringLiteral("Dark Mode");
}

bool isDarkMode() {
    return g_dark;
}

void applyTheme(const QString &name) {
    QSettings s("Engineering","FoxProbe");
    qApp->setStyle(QStyleFactory::create("Fusion"));

    if (name == "Light" || name == "Dark") {
        s.setValue("Theme", name);
        loadTheme();
        return;
    }

    QPalette p;
    if (name == "Greenish")         p = buildGreenish();
    else if (name == "Black+Orange")p = buildBlackOrange();
    else                            p = loadPalette(QString("CustomThemes/%1").arg(name));

    g_themePalette = p;
    g_effectivePalette = applyOverride(g_themePalette, defaultContextKey());
    qApp->setPalette(g_effectivePalette);
    s.setValue("Theme", name);
    g_paletteInitialized = true;
}

QPalette paletteForName(const QString &name) {
    if (name == "Light" || name == "Dark") {
        QSettings s("Engineering","FoxProbe");
        QString old = s.value("Theme").toString();
        s.setValue("Theme", name);
        loadTheme();
        QPalette p = qApp->palette();
        s.setValue("Theme", old);
        loadTheme();
        return p;
    }
    if (name == "Greenish")         return buildGreenish();
    if (name == "Black+Orange")     return buildBlackOrange();
    return loadPalette(QString("CustomThemes/%1").arg(name));
}

void saveCustomPalette(const QString &name,
                       const QColor &window,
                       const QColor &bg,
                       const QColor &text,
                       const QColor &button,
                       const QColor &buttonText,
                       const QColor &alternateBase,
                       const QColor &highlight,
                       const QColor &highlightedText)
{
    QJsonObject o;
    o["Window"]     = window.name();
    o["Base"]     = bg.name();
    o["Text"]       = text.name();
    o["Button"]     = button.name();
    o["ButtonText"] = buttonText.name();
    if (alternateBase.isValid())
        o["AlternateBase"] = alternateBase.name();
    if (highlight.isValid())
        o["Highlight"] = highlight.name();
    if (highlightedText.isValid())
        o["HighlightedText"] = highlightedText.name();
    QSettings s("Engineering","FoxProbe");
    s.setValue(QString("CustomThemes/%1").arg(name),
               QJsonDocument(o).toJson(QJsonDocument::Compact));
}

QColor barColor() {
    return qApp->palette().color(QPalette::Text);
}

QStringList availableContexts()
{
    QStringList keys;
    for (const auto &info : contextTable()) {
        keys << info.key;
    }
    return keys;
}

QString contextLabel(const QString &contextKey)
{
    for (const auto &info : contextTable()) {
        if (info.key == contextKey) {
            return info.label;
        }
    }
    return contextKey;
}

QString defaultContextKey()
{
    return QStringLiteral("default");
}

QString mainWindowContextKey()
{
    return QStringLiteral("MainWindow");
}

QString statisticsContextKey()
{
    return QStringLiteral("Statistics");
}

QString geoOverviewContextKey()
{
    return QStringLiteral("GeoOverview");
}

QString sessionManagerContextKey()
{
    return QStringLiteral("SessionManager");
}

QPalette paletteForContext(const QString &contextKey)
{
    if (!g_paletteInitialized) {
        loadTheme();
    }

    if (contextKey == defaultContextKey()) {
        return g_effectivePalette;
    }
    return applyOverride(g_effectivePalette, contextKey);
}

void saveContextPalette(const QString &contextKey, const QPalette &palette)
{
    QJsonObject o;
    auto store = [&](const char *name, QPalette::ColorRole role) {
        o[QLatin1String(name)] = palette.color(role).name();
    };
    store("Window",          QPalette::Window);
    store("Base",            QPalette::Base);
    store("AlternateBase",   QPalette::AlternateBase);
    store("Text",            QPalette::Text);
    store("Button",          QPalette::Button);
    store("ButtonText",      QPalette::ButtonText);
    store("Highlight",       QPalette::Highlight);
    store("HighlightedText", QPalette::HighlightedText);

    QSettings s("Engineering", "FoxProbe");
    s.setValue(settingsKeyForContext(contextKey),
               QJsonDocument(o).toJson(QJsonDocument::Compact));
    if (contextKey == defaultContextKey()) {
        g_effectivePalette = applyOverride(g_themePalette, defaultContextKey());
        qApp->setPalette(g_effectivePalette);
        g_paletteInitialized = true;
    }
}

void clearContextPalette(const QString &contextKey)
{
    QSettings s("Engineering", "FoxProbe");
    s.remove(settingsKeyForContext(contextKey));
    if (contextKey == defaultContextKey()) {
        g_effectivePalette = applyOverride(g_themePalette, defaultContextKey());
        qApp->setPalette(g_effectivePalette);
        g_paletteInitialized = true;
    }
}

void applyTo(QWidget *widget, const QString &contextKey)
{
    if (!widget) {
        return;
    }
    widget->setPalette(paletteForContext(contextKey));
    widget->setAutoFillBackground(true);
}

} // namespace Theme
