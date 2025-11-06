#include "geooverviewdialog.h"
#include "../theme/theme.h"

#include "../../packets/packet_geolocation/GeoMap.h"
#include "../../packets/packet_geolocation/geolocation.h"
#include "../../packets/packet_geolocation/CountryMapping/CountryMap.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTimeEdit>
#include <QDir>
#include <QFile>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QLocale>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include <QSlider>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <utility>
 

namespace {
QString formatCountryLabel(const QString &country, const QString &fallback)
{
    if (!country.trimmed().isEmpty())
        return country;
    return fallback;
}
}

GeoOverviewDialog::GeoOverviewDialog(GeoLocation *geo, QWidget *parent)
    : QDialog(parent),
      m_geo(geo)
{
    setWindowTitle(tr("GeoOverview"));
    resize(1000, 720);

    m_sessionsDir = QCoreApplication::applicationDirPath() + "/src/statistics/sessions";

auto *mainLayout = new QVBoxLayout(this);

auto *filterWidget = new QWidget(this);
auto *filterLayout = new QGridLayout(filterWidget);
filterLayout->setContentsMargins(0, 0, 0, 0);
filterLayout->setHorizontalSpacing(8);
filterLayout->setVerticalSpacing(4);

// --- IP address + input + dropdown ---
auto *ipLabel = new QLabel(tr("IP address"), filterWidget);
m_ipInput = new QLineEdit(filterWidget);
m_ipInput->setPlaceholderText(tr("e.g. 192.0.2.1"));

m_ipDropdown = new QComboBox(filterWidget);
m_ipDropdown->setSizeAdjustPolicy(QComboBox::AdjustToContents);
m_ipDropdown->setMinimumWidth(180); 

filterLayout->addWidget(ipLabel,     0, 0);
filterLayout->addWidget(m_ipInput,   0, 1);
filterLayout->addWidget(m_ipDropdown,0, 3);   

// --- From datetime ---
m_startToggle = new QCheckBox(tr("From"), filterWidget);
m_startEdit = new QDateTimeEdit(QDateTime::currentDateTime(), filterWidget);
m_startEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
m_startEdit->setCalendarPopup(true);
m_startEdit->setEnabled(false);

filterLayout->addWidget(m_startToggle, 1, 0);
filterLayout->addWidget(m_startEdit,   1, 1);

// --- To datetime ---
m_endToggle = new QCheckBox(tr("To"), filterWidget);
m_endEdit = new QDateTimeEdit(QDateTime::currentDateTime(), filterWidget);
m_endEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
m_endEdit->setCalendarPopup(true);
m_endEdit->setEnabled(false);

filterLayout->addWidget(m_endToggle, 1, 2);   
filterLayout->addWidget(m_endEdit,   1, 3);   

// --- Search button ---
m_searchButton = new QPushButton(tr("Load timeline"), filterWidget);
filterLayout->addWidget(m_searchButton, 0, 4, 2, 1);

// --- Column stretch ---
filterLayout->setColumnStretch(1, 1);
filterLayout->setColumnStretch(2, 0);
filterLayout->setColumnStretch(3, 1);
filterLayout->setColumnStretch(4, 0);

mainLayout->addWidget(filterWidget);


    const QString mapPath = QCoreApplication::applicationDirPath() + "/resources/WorldMap.svg";
    m_map = new GeoMapWidget(mapPath, this);
    m_map->setMinimumHeight(360);

    connect(m_map, &GeoMapWidget::flightAnimationFinished,
            this, &GeoOverviewDialog::handleFlightFinished);

    auto *splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(m_map);

    QWidget *lowerPanel = new QWidget;
    auto *lowerLayout = new QVBoxLayout(lowerPanel);
    lowerLayout->setContentsMargins(0, 0, 0, 0);

    auto *controlsLayout = new QHBoxLayout;
    m_prevButton = new QPushButton(tr("⏮"));
    m_playButton = new QPushButton(tr("Play"));
    m_nextButton = new QPushButton(tr("⏭"));
    m_slider = new QSlider(Qt::Horizontal);

    m_prevButton->setToolTip(tr("Previous event"));
    m_nextButton->setToolTip(tr("Next event"));
    m_playButton->setToolTip(tr("Play / Pause"));

    controlsLayout->addWidget(m_prevButton);
    controlsLayout->addWidget(m_playButton);
    controlsLayout->addWidget(m_nextButton);
    controlsLayout->addWidget(m_slider, 1);

    lowerLayout->addLayout(controlsLayout);

    m_infoLabel = new QLabel;
    m_infoLabel->setWordWrap(true);
    m_detailLabel = new QLabel;
    m_detailLabel->setWordWrap(true);
    m_detailLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));

    lowerLayout->addWidget(m_infoLabel);
    lowerLayout->addWidget(m_detailLabel);

    m_eventList = new QListWidget;
    m_eventList->setSelectionMode(QAbstractItemView::SingleSelection);
    lowerLayout->addWidget(m_eventList, 1);

    splitter->addWidget(lowerPanel);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    mainLayout->addWidget(splitter);

    connect(m_slider, &QSlider::valueChanged,
            this, &GeoOverviewDialog::onSliderValueChanged);
    connect(m_eventList, &QListWidget::currentRowChanged,
            this, &GeoOverviewDialog::onEventSelectionChanged);
    connect(m_playButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::togglePlayback);
    connect(m_nextButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::playNext);
    connect(m_prevButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::playPrevious);
    connect(m_searchButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::performSearch);
    connect(m_ipInput, &QLineEdit::returnPressed,
            this, &GeoOverviewDialog::performSearch);
    connect(m_ipDropdown, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int index) {
                if (m_isUpdatingDropdown)
                    return;
                const QString ip = m_ipDropdown->itemData(index).toString();
                if (ip.isEmpty())
                    return;
                m_ipInput->setText(ip);
                performSearch();
            });
    connect(m_startToggle, &QCheckBox::toggled,
            this, &GeoOverviewDialog::handleStartFilterToggled);
    connect(m_endToggle, &QCheckBox::toggled,
            this, &GeoOverviewDialog::handleEndFilterToggled);

    populateIpDropdown();
    showEmptyState(tr("Awaiting selection"),
                   tr("Provide an IP address and optionally a time range, then load the timeline."));
    updateControlsState();

    Theme::applyTo(this, Theme::geoOverviewContextKey());
}

void GeoOverviewDialog::handleStartFilterToggled(bool checked)
{
    m_startEdit->setEnabled(checked);
    if (checked && !m_startEdit->dateTime().isValid())
        m_startEdit->setDateTime(QDateTime::currentDateTime());
}

void GeoOverviewDialog::handleEndFilterToggled(bool checked)
{
    m_endEdit->setEnabled(checked);
    if (checked && !m_endEdit->dateTime().isValid())
        m_endEdit->setDateTime(QDateTime::currentDateTime());
}

void GeoOverviewDialog::performSearch()
{
    if (m_isPlaying) {
        m_isPlaying = false;
        m_map->stopFlightAnimation();
    }

    const QString ip = m_ipInput->text().trimmed();
    syncIpDropdownSelection(ip);
    std::optional<QDateTime> start;
    std::optional<QDateTime> end;

    if (m_startToggle->isChecked())
        start = m_startEdit->dateTime();
    if (m_endToggle->isChecked())
        end = m_endEdit->dateTime();

    if (start && end && *start > *end)
        std::swap(start, end);

    loadEventsForIp(ip, start, end);
    updateControlsState();

    if (!m_events.isEmpty()) {
        setCurrentEvent(0, false);
    } else {
        if (ip.isEmpty()) {
            showEmptyState(tr("No IP selected"),
                           tr("Enter an IP address to explore its history."));
        } else {
            QString detail;
            if (start && end) {
                detail = tr("No statistics found for %1 between %2 and %3.")
                             .arg(ip,
                                  QLocale::system().toString(*start, QLocale::ShortFormat),
                                  QLocale::system().toString(*end,   QLocale::ShortFormat));
            } else if (start) {
                detail = tr("No statistics found for %1 after %2.")
                             .arg(ip,
                                  QLocale::system().toString(*start, QLocale::ShortFormat));
            } else if (end) {
                detail = tr("No statistics found for %1 before %2.")
                             .arg(ip,
                                  QLocale::system().toString(*end, QLocale::ShortFormat));
            } else {
                detail = tr("No statistics found for %1 in the stored sessions.")
                             .arg(ip);
            }
            showEmptyState(tr("No timeline data"), detail);
        }
    }
}

void GeoOverviewDialog::showEmptyState(const QString &title, const QString &details)
{
    if (m_map) {
        m_map->highlightCountries({});
        m_map->clearOverlay();
    }

    if (m_infoLabel)
        m_infoLabel->setText(title);
    if (m_detailLabel)
        m_detailLabel->setText(details);
}

void GeoOverviewDialog::populateIpDropdown()
{
    if (!m_ipDropdown)
        return;

    const QString preferred = m_ipInput ? m_ipInput->text().trimmed() : QString();

    m_isUpdatingDropdown = true;
    QSignalBlocker blocker(m_ipDropdown);

    m_ipDropdown->clear();
    m_ipDropdown->addItem(tr("Select stored IP"), QString());

    QDir dir(m_sessionsDir);
    const QStringList files = dir.entryList({"*.json"}, QDir::Files, QDir::Name);

    QSet<QString> uniqueIps;
    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly))
            continue;

        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject())
            continue;

        const QJsonObject obj = doc.object();
        const QJsonArray perSecond = obj.value("perSecond").toArray();
        for (const QJsonValue &secondValue : perSecond) {
            const QJsonObject secondObj = secondValue.toObject();
            const QJsonArray connections = secondObj.value("connections").toArray();
            for (const QJsonValue &connValue : connections) {
                const QJsonObject connObj = connValue.toObject();
                const QString src = connObj.value("src").toString().trimmed();
                const QString dst = connObj.value("dst").toString().trimmed();
                if (!src.isEmpty())
                    uniqueIps.insert(src);
                if (!dst.isEmpty())
                    uniqueIps.insert(dst);
            }
        }
    }

    QStringList ipList = uniqueIps.values();
    std::sort(ipList.begin(), ipList.end(), [](const QString &lhs, const QString &rhs) {
        return lhs.localeAwareCompare(rhs) < 0;
    });

    for (const QString &storedIp : ipList)
        m_ipDropdown->addItem(storedIp, storedIp);

    if (!preferred.isEmpty()) {
        const int index = m_ipDropdown->findData(preferred);
        if (index >= 0)
            m_ipDropdown->setCurrentIndex(index);
        else
            m_ipDropdown->setCurrentIndex(0);
    } else {
        m_ipDropdown->setCurrentIndex(0);
    }

    m_isUpdatingDropdown = false;
}

void GeoOverviewDialog::syncIpDropdownSelection(const QString &ip)
{
    if (!m_ipDropdown)
        return;

    m_isUpdatingDropdown = true;
    QSignalBlocker blocker(m_ipDropdown);

    if (ip.isEmpty()) {
        m_ipDropdown->setCurrentIndex(0);
    } else {
        const int index = m_ipDropdown->findData(ip);
        if (index >= 0)
            m_ipDropdown->setCurrentIndex(index);
    }

    m_isUpdatingDropdown = false;
}

void GeoOverviewDialog::loadEventsForIp(const QString &ip,
                                        const std::optional<QDateTime> &start,
                                        const std::optional<QDateTime> &end)
{
    m_eventList->clear();
    m_events.clear();
    m_currentIndex = -1;

    if (ip.isEmpty()) {
        auto *placeholder = new QListWidgetItem(tr("Enter an IP address to load events."));
        placeholder->setFlags(Qt::NoItemFlags);
        m_eventList->addItem(placeholder);
        return;
    }

    QDir dir(m_sessionsDir);
    QStringList files = dir.entryList({"*.json"}, QDir::Files, QDir::Name);

    if (files.isEmpty()) {
        auto *placeholder = new QListWidgetItem(tr("No statistics files available."));
        placeholder->setFlags(Qt::NoItemFlags);
        m_eventList->addItem(placeholder);
        return;
    }

    QVector<FlightEvent> collected;
    collected.reserve(256);

    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly))
            continue;

        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject())
            continue;

        const QJsonObject obj = doc.object();
        const QDateTime sessionStart = QDateTime::fromString(obj.value("sessionStart").toString(), Qt::ISODate);
        const QJsonArray perSecond = obj.value("perSecond").toArray();

        for (const QJsonValue &secondValue : perSecond) {
            const QJsonObject secondObj = secondValue.toObject();
            const int sec = secondObj.value("second").toInt();
            QDateTime timestamp = sessionStart.isValid()
                                ? sessionStart.addSecs(sec)
                                : QDateTime();

            if (timestamp.isValid()) {
                if (start && timestamp < *start)
                    continue;
                if (end && timestamp > *end)
                    continue;
            } else {
                if (start || end)
                    continue;
            }

            const QJsonArray connections = secondObj.value("connections").toArray();
            QVector<QJsonObject> matches;
            matches.reserve(connections.size());
            for (const QJsonValue &connValue : connections) {
                const QJsonObject connObj = connValue.toObject();
                const QString src = connObj.value("src").toString();
                const QString dst = connObj.value("dst").toString();
                if (src == ip || dst == ip)
                    matches.append(connObj);
            }

            if (matches.isEmpty())
                continue;

            const double pps = secondObj.value("pps").toDouble();
            const double bps = secondObj.value("bps").toDouble();
            const double avgPacketSize = secondObj.value("avgPacketSize").toDouble();
            const QJsonObject protocols = secondObj.value("protocolCounts").toObject();

            for (const QJsonObject &connObj : matches) {
                FlightEvent event;
                event.timestamp = timestamp;
                event.srcIp = connObj.value("src").toString();
                event.dstIp = connObj.value("dst").toString();
                event.selectedIp = ip;
                event.counterpartIp = (event.srcIp == ip) ? event.dstIp : event.srcIp;
                event.direction = (event.srcIp == ip)
                    ? tr("Outgoing to %1").arg(event.counterpartIp)
                    : tr("Incoming from %1").arg(event.counterpartIp);
                event.packetsPerSecond = pps;
                event.bytesPerSecond = bps;
                event.avgPacketSize = avgPacketSize;
                for (auto it = protocols.constBegin(); it != protocols.constEnd(); ++it)
                    event.protocolCounts.insert(it.key(), it.value().toDouble());
                event.connectionsThisSecond = matches.size();

                enrichWithGeo(event);
                collected.push_back(event);
            }
        }
    }

    if (collected.isEmpty()) {
        auto *placeholder = new QListWidgetItem(tr("No statistics found for %1.").arg(ip));
        placeholder->setFlags(Qt::NoItemFlags);
        m_eventList->addItem(placeholder);
        return;
    }

    std::sort(collected.begin(), collected.end(), [](const FlightEvent &a, const FlightEvent &b) {
        if (a.timestamp == b.timestamp)
            return a.counterpartIp < b.counterpartIp;
        if (!a.timestamp.isValid() || !b.timestamp.isValid())
            return a.timestamp.isValid();
        return a.timestamp < b.timestamp;
    });

    m_events = collected;
    for (int i = 0; i < m_events.size(); ++i)
        m_events[i].sequenceNumber = i + 1;

    for (const FlightEvent &event : m_events) {
        const QString timeStampText = event.timestamp.isValid()
            ? QLocale::system().toString(event.timestamp, QLocale::ShortFormat)
            : tr("Unknown time");
        QString display = tr("%1. %2 • %3")
            .arg(event.sequenceNumber)
            .arg(timeStampText)
            .arg(event.direction);
        auto *item = new QListWidgetItem(display);
        item->setToolTip(tr("%1 → %2\nConnections this second: %3")
                         .arg(event.srcIp,
                              event.dstIp,
                              QString::number(event.connectionsThisSecond)));
        m_eventList->addItem(item);
    }
}

void GeoOverviewDialog::enrichWithGeo(FlightEvent &event)
{
    if (!m_geo)
        return;

    const QVector<GeoStruct> geoInfo = m_geo->GeoVector(event.srcIp, event.dstIp);
    const QLocale locale = QLocale::c();

    for (const GeoStruct &gs : geoInfo) {
        const bool isSource = gs.name.startsWith(QStringLiteral("Source IP"));
        const bool isDestination = gs.name.startsWith(QStringLiteral("Destination IP"));

        QString country;
        double latitude = std::numeric_limits<double>::quiet_NaN();
        double longitude = std::numeric_limits<double>::quiet_NaN();

        for (const auto &field : gs.fields) {
            if (field.first == QStringLiteral("Country")) {
                country = field.second;
            } else if (field.first == QStringLiteral("Latitude")) {
                bool latOk = false;
                latitude = locale.toDouble(field.second, &latOk);
                if (!latOk)
                    latitude = field.second.toDouble(&latOk);
                if (!latOk)
                    latitude = std::numeric_limits<double>::quiet_NaN();
            } else if (field.first == QStringLiteral("Longitude")) {
                bool lonOk = false;
                longitude = locale.toDouble(field.second, &lonOk);
                if (!lonOk)
                    longitude = field.second.toDouble(&lonOk);
                if (!lonOk)
                    longitude = std::numeric_limits<double>::quiet_NaN();
            }
        }

        auto maybeIso = CountryMap::nameToIso().find(country);
        if (maybeIso != CountryMap::nameToIso().end())
            event.isoCodes << *maybeIso;

        if (isSource) {
            event.srcCountry = country;
            event.srcLat = latitude;
            event.srcLon = longitude;
        } else if (isDestination) {
            event.dstCountry = country;
            event.dstLat = latitude;
            event.dstLon = longitude;
        }
    }

    event.isoCodes.removeDuplicates();
    event.hasCoordinates = std::isfinite(event.srcLat) && std::isfinite(event.srcLon)
                        && std::isfinite(event.dstLat) && std::isfinite(event.dstLon);
}

void GeoOverviewDialog::updateControlsState()
{
    const bool hasEvents = !m_events.isEmpty();
    m_slider->setEnabled(hasEvents);
    m_playButton->setEnabled(hasEvents);
    m_prevButton->setEnabled(hasEvents);
    m_nextButton->setEnabled(hasEvents);

    if (hasEvents) {
        m_slider->setRange(0, m_events.size() - 1);
    } else {
        m_slider->setRange(0, 0);
        m_slider->setValue(0);
    }

    m_playButton->setText(m_isPlaying ? tr("Pause") : tr("Play"));
}

void GeoOverviewDialog::setCurrentEvent(int index, bool userInitiated)
{
    if (m_events.isEmpty())
        return;

    if (index < 0)
        index = 0;
    if (index >= m_events.size())
        index = m_events.size() - 1;

    if (userInitiated && m_isPlaying) {
        m_isPlaying = false;
        m_map->stopFlightAnimation();
    }

    m_currentIndex = index;

    {
        QSignalBlocker blockSlider(m_slider);
        m_slider->setValue(index);
    }
    {
        QSignalBlocker blockList(m_eventList);
        m_eventList->setCurrentRow(index);
    }

    updateMapForEvent(m_events.at(index));
    updateControlsState();
}

void GeoOverviewDialog::updateMapForEvent(const FlightEvent &event)
{
    if (!m_map)
        return;

    if (!event.isoCodes.isEmpty())
        m_map->highlightCountries(event.isoCodes);
    else
        m_map->highlightCountries({});

    const QString srcLabel = formatCountryLabel(event.srcCountry, event.srcIp);
    const QString dstLabel = formatCountryLabel(event.dstCountry, event.dstIp);

    QString headline = tr("%1. %2")
        .arg(event.sequenceNumber)
        .arg(event.direction);

    if (event.timestamp.isValid()) {
        headline.append(tr(" • %1")
                        .arg(QLocale::system().toString(event.timestamp, QLocale::LongFormat)));
    }

    QStringList detailLines;
    detailLines << tr("Route: %1 → %2").arg(srcLabel, dstLabel);
    detailLines << tr("IPs: %1 → %2").arg(event.srcIp, event.dstIp);
    detailLines << tr("Connections this second: %1")
                   .arg(event.connectionsThisSecond);
    detailLines << tr("Packets/s: %1 • Bytes/s: %2 • Avg pkt: %3 B")
                   .arg(QString::number(event.packetsPerSecond, 'f', 0),
                        QString::number(event.bytesPerSecond, 'f', 0),
                        QString::number(event.avgPacketSize, 'f', 1));

    if (!event.protocolCounts.isEmpty()) {
        QStringList protoParts;
        for (auto it = event.protocolCounts.constBegin();
             it != event.protocolCounts.constEnd(); ++it) {
            protoParts << tr("%1: %2").arg(it.key())
                                        .arg(QString::number(it.value(), 'f', 0));
        }
        detailLines << tr("Protocols this second: %1").arg(protoParts.join(QLatin1String(", ")));
    }

    m_infoLabel->setText(headline);
    m_detailLabel->setText(detailLines.join(QLatin1Char('\n')));

    if (event.hasCoordinates) {
        const QString flightLabel = tr("%1 → %2").arg(srcLabel, dstLabel);
        m_map->displayFlightPath(event.srcLat, event.srcLon,
                                 event.dstLat, event.dstLon,
                                 flightLabel);
    } else {
        m_map->clearOverlay();
        m_map->stopFlightAnimation();
        if (m_isPlaying) {
            QTimer::singleShot(600, this, &GeoOverviewDialog::handleFlightFinished);
        }
    }
}

void GeoOverviewDialog::onSliderValueChanged(int value)
{
    setCurrentEvent(value, true);
}

void GeoOverviewDialog::onEventSelectionChanged(int row)
{
    if (row < 0)
        return;
    setCurrentEvent(row, true);
}

void GeoOverviewDialog::togglePlayback()
{
    if (m_events.isEmpty())
        return;

    m_isPlaying = !m_isPlaying;
    m_playButton->setText(m_isPlaying ? tr("Pause") : tr("Play"));

    if (m_isPlaying) {
        int targetIndex = m_currentIndex;
        if (targetIndex < 0)
            targetIndex = 0;
        setCurrentEvent(targetIndex, false);
    } else {
        m_map->stopFlightAnimation();
    }
}

void GeoOverviewDialog::playNext()
{
    if (m_events.isEmpty())
        return;

    if (m_isPlaying) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        m_map->stopFlightAnimation();
    }

    int nextIndex = m_currentIndex + 1;
    if (nextIndex >= m_events.size())
        nextIndex = 0;
    setCurrentEvent(nextIndex, true);
}

void GeoOverviewDialog::playPrevious()
{
    if (m_events.isEmpty())
        return;

    if (m_isPlaying) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        m_map->stopFlightAnimation();
    }

    int prevIndex = m_currentIndex - 1;
    if (prevIndex < 0)
        prevIndex = m_events.size() - 1;
    setCurrentEvent(prevIndex, true);
}

void GeoOverviewDialog::handleFlightFinished()
{
    if (!m_isPlaying || m_events.isEmpty())
        return;

    int nextIndex = m_currentIndex + 1;
    if (nextIndex >= m_events.size())
        nextIndex = 0;

    if (nextIndex == m_currentIndex) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        return;
    }

    setCurrentEvent(nextIndex, false);
}
