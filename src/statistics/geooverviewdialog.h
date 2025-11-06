#ifndef GEOOVERVIEWDIALOG_H
#define GEOOVERVIEWDIALOG_H

#include <QDialog>
#include <QDateTime>
#include <QMap>
#include <QStringList>
#include <QVector>
#include <limits>
#include <optional>

class GeoMapWidget;
class GeoLocation;
class QListWidget;
class QComboBox;
class QSlider;
class QPushButton;
class QLabel;
class QLineEdit;
class QCheckBox;
class QDateTimeEdit;

class GeoOverviewDialog : public QDialog {
    Q_OBJECT
public:
    GeoOverviewDialog(GeoLocation *geo, QWidget *parent = nullptr);

private slots:
    void onSliderValueChanged(int value);
    void onEventSelectionChanged(int row);
    void togglePlayback();
    void playNext();
    void playPrevious();
    void handleFlightFinished();
    void performSearch();
    void handleStartFilterToggled(bool checked);
    void handleEndFilterToggled(bool checked);
    void populateIpDropdown();
    void syncIpDropdownSelection(const QString &ip);

private:
    struct FlightEvent {
        int sequenceNumber = 0;
        QDateTime timestamp;
        QString srcIp;
        QString dstIp;
        QString selectedIp;
        QString counterpartIp;
        QString direction;
        QString srcCountry;
        QString dstCountry;
        QStringList isoCodes;
        double srcLat = std::numeric_limits<double>::quiet_NaN();
        double srcLon = std::numeric_limits<double>::quiet_NaN();
        double dstLat = std::numeric_limits<double>::quiet_NaN();
        double dstLon = std::numeric_limits<double>::quiet_NaN();
        bool hasCoordinates = false;
        double packetsPerSecond = 0.0;
        double bytesPerSecond = 0.0;
        double avgPacketSize = 0.0;
        QMap<QString, double> protocolCounts;
        int connectionsThisSecond = 0;
    };

    void loadEventsForIp(const QString &ip,
                         const std::optional<QDateTime> &start,
                         const std::optional<QDateTime> &end);
    void enrichWithGeo(FlightEvent &event);
    void setCurrentEvent(int index, bool userInitiated);
    void updateMapForEvent(const FlightEvent &event);
    void updateControlsState();
    void showEmptyState(const QString &title, const QString &details);

    GeoLocation *m_geo = nullptr;
    GeoMapWidget *m_map = nullptr;
    QListWidget *m_eventList = nullptr;
    QSlider *m_slider = nullptr;
    QPushButton *m_playButton = nullptr;
    QPushButton *m_nextButton = nullptr;
    QPushButton *m_prevButton = nullptr;
    QLabel *m_infoLabel = nullptr;
    QLabel *m_detailLabel = nullptr;
    QLineEdit *m_ipInput = nullptr;
    QComboBox *m_ipDropdown = nullptr;
    QCheckBox *m_startToggle = nullptr;
    QCheckBox *m_endToggle = nullptr;
    QDateTimeEdit *m_startEdit = nullptr;
    QDateTimeEdit *m_endEdit = nullptr;
    QPushButton *m_searchButton = nullptr;

    QString m_sessionsDir;

    QVector<FlightEvent> m_events;
    int m_currentIndex = -1;
    bool m_isPlaying = false;
    bool m_isUpdatingDropdown = false;
};

#endif // GEOOVERVIEWDIALOG_H
