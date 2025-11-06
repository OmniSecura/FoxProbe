#ifndef REPORTBUILDERWINDOW_H
#define REPORTBUILDERWINDOW_H

#include <QMainWindow>
#include <QColor>
#include <QDateTime>
#include <QDate>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QPair>
#include <QStringList>
#include <QVector>

class QListWidget;
class QListWidgetItem;
class QStackedWidget;
class QTextEdit;
class QLineEdit;
class QSpinBox;
class QComboBox;
class QCheckBox;
class QPushButton;
class QPlainTextEdit;
class QLabel;
class QTextBrowser;
class QGroupBox;
class QDateEdit;
class QVBoxLayout;

class GeoLocation;
class Statistics;
struct PacketAnnotation;
class AppSettings;

class ReportBuilderWindow : public QMainWindow
{
    Q_OBJECT
public:
    struct AnnotationRecord {
        QString filePath;
        QString title;
        QString description;
        QString threatLevel;
        QString recommendedAction;
        QStringList tags;
        QDateTime createdAt;
        QJsonDocument document;
    };

    struct ReportSection {
        enum class Kind {
            Heading,
            Text,
            Annotation,
            Statistics,
            Anomalies,
            GeoOverview
        };

        Kind kind = Kind::Text;
        QString title;
        QString body;
        int headingLevel = 1;
        QString annotationFile;
        bool includePacketTable = true;
        bool includeTags = true;
        bool includeColors = true;
        QColor accentColor;
        QStringList statSessionFiles;
        int statRangeStart = 0;
        int statRangeEnd = -1;
        QStringList statChartKinds;
        QStringList storedAnomalyIds;
        int pageNumber = 0;
    };

    struct StatisticsSessionInfo {
        QString filePath;
        QString displayLabel;
        int maxSecond = 0;
        QDateTime startTime;
        QDateTime endTime;
    };

    struct StoredAnomaly {
        QString id;
        QString summary;
        QStringList reasons;
        QStringList tags;
        double score = 0.0;
        int second = 0;
        QDateTime capturedAt;
    };

    struct AggregatedStats {
        QStringList sessionsUsed;
        QMap<QString, double> protocolTotals;
        QVector<QPair<int, double>> packetsPerSecond;
        QVector<QPair<int, double>> bytesPerSecond;
        double totalPackets = 0.0;
        double totalBytes = 0.0;
        int requestedStart = 0;
        int requestedEnd = -1;
        int rangeStart = 0;
        int rangeEnd = -1;
        QMap<QString, double> connectionCounts;
        QMap<QString, double> sourceCounts;
        QMap<QString, double> destinationCounts;
        bool hasSamples = false;
        QString error;
    };

    explicit ReportBuilderWindow(const QVector<PacketAnnotation> &annotations,
                                 Statistics *statistics,
                                 GeoLocation *geo,
                                 AppSettings *settings,
                                 QWidget *parent = nullptr);

private slots:
    void addHeadingSection();
    void addTextSection();
    void addAnnotationSection();
    void addStatisticsSection();
    void addAnomalySection();
    void addGeoSection();
    void removeSelectedSection();
    void moveSectionUp();
    void moveSectionDown();
    void handleSectionSelectionChanged();

    void saveReportToFile();
    void loadReportFromFile();
    void saveTemplate();
    void loadTemplate();
    void exportToPdf();
    void saveDraft();
    void loadDraft();

    void regenerateCurrentSection();

private:
    struct EditorWidgets {
        QWidget *page = nullptr;
        QLineEdit *titleEdit = nullptr;
        QSpinBox *levelSpin = nullptr;
        QTextEdit *bodyEdit = nullptr;
        QComboBox *annotationCombo = nullptr;
        QCheckBox *packetTableCheck = nullptr;
        QCheckBox *tagCheck = nullptr;
        QCheckBox *colorCheck = nullptr;
        QPushButton *regenerateButton = nullptr;
        QLabel *metaLabel = nullptr;
        QListWidget *statsSessionList = nullptr;
        QSpinBox *statsRangeStart = nullptr;
        QSpinBox *statsRangeEnd = nullptr;
        QLabel *statsRangeHint = nullptr;
        QListWidget *statsChartList = nullptr;
        QListWidget *anomalyLibrary = nullptr;
        QPushButton *refreshLibraryButton = nullptr;
        QPushButton *importLibraryButton = nullptr;
        QPushButton *exportLibraryButton = nullptr;
        QSpinBox *pageSpin = nullptr;
    };

    struct ReportHeader {
        QString organization;
        QString title;
        QString logoPath;
        QString periodPreset;
        QDate periodStart;
        QDate periodEnd;
    };

    struct HeaderWidgets {
        QGroupBox *group = nullptr;
        QLineEdit *organizationEdit = nullptr;
        QLineEdit *titleEdit = nullptr;
        QComboBox *periodPresetCombo = nullptr;
        QDateEdit *periodStartEdit = nullptr;
        QDateEdit *periodEndEdit = nullptr;
        QLabel *periodSummaryLabel = nullptr;
        QLineEdit *logoPathEdit = nullptr;
        QPushButton *logoBrowseButton = nullptr;
        QPushButton *logoClearButton = nullptr;
    };

    void buildUi();
    void refreshSectionList();
    void selectSection(int index);
    void syncEditorWithSection(int index);
    void connectEditorSignals(const EditorWidgets &editor, ReportSection::Kind kind);
    void updatePreview();

    void setupHeaderControls(QWidget *parent, QVBoxLayout *layout);
    void resetHeaderToDefaults();
    void syncHeaderEditors();
    void updateHeaderPeriodSummary();
    void applyHeaderPreset();
    void ensureHeaderOrder();
    QString headerPeriodText() const;
    QString headerPresetLabel(const QString &preset) const;
    bool matchesPreset(const QString &preset, const QDate &start, const QDate &end) const;
    QString headerHtml() const;
    QString headerLogoImgTag() const;

    EditorWidgets createHeadingEditor();
    EditorWidgets createTextEditor();
    EditorWidgets createAnnotationEditor();
    EditorWidgets createAutoSectionEditor(const QString &title);
    void addPagePlacementControls(EditorWidgets &editor, QVBoxLayout *layout);
    void setupStatisticsEditor();
    void setupAnomaliesEditor();
    void refreshStatisticsSessionList();
    void updateStatisticsRangeLimits();
    void refreshStatisticsChartsSelection();
    void refreshAnomalyLibrary();
    void persistCurrentAnomalies();
    void sortStoredAnomalies();
    void importAnomaliesFromFile(const QString &filePath);
    bool writeAnomaliesToFile(const QString &filePath) const;

    QString statisticsSummaryText(const ReportSection &section) const;
    QString anomaliesSummaryText(const ReportSection &section) const;
    QString geoOverviewSummaryText() const;

    QString annotationHtml(const ReportSection &section) const;
    QString sectionToHtml(const ReportSection &section) const;
    QString renderFullDocument() const;

    void ensureReportingDirectory() const;
    QString reportingDirectory() const;
    QString draftsDirectory() const;
    QString templatesDirectory() const;
    QString anomaliesDirectory() const;
    QString anomaliesFilePath() const;

    void loadAvailableAnnotations();
    void refreshAnnotationCombo(QComboBox *combo) const;

    void loadStatisticsSessions();
    void loadStoredAnomalies();
    void saveStoredAnomalies() const;
    StoredAnomaly storedAnomalyFromJson(const QJsonObject &obj) const;
    QJsonObject storedAnomalyToJson(const StoredAnomaly &anomaly) const;

    QJsonObject sectionToJson(const ReportSection &section) const;
    ReportSection sectionFromJson(const QJsonObject &obj) const;
    QJsonObject headerToJson() const;
    void loadHeaderFromJson(const QJsonObject &obj);

    void regenerateAutoSections();
    QStringList statisticsChartOptions() const;
    QString chartLabelForKey(const QString &key) const;
    AggregatedStats aggregateStatistics(const ReportSection &section) const;
    QString renderStatisticsChartsHtml(const ReportSection &section, const AggregatedStats &data) const;
    QString renderSingleChart(const QString &key,
                              const AggregatedStats &data) const;

    QVector<ReportSection> m_sections;
    QVector<AnnotationRecord> m_annotations;
    QVector<StatisticsSessionInfo> m_statisticsSessions;
    QVector<StoredAnomaly> m_storedAnomalies;

    QListWidget *m_sectionList = nullptr;
    QStackedWidget *m_editorStack = nullptr;
    QWidget *m_emptyPage = nullptr;
    EditorWidgets m_headingEditor;
    EditorWidgets m_textEditor;
    EditorWidgets m_annotationEditor;
    EditorWidgets m_statisticsEditor;
    EditorWidgets m_anomaliesEditor;
    EditorWidgets m_geoEditor;
    QTextBrowser *m_preview = nullptr;

    ReportHeader m_header;
    HeaderWidgets m_headerWidgets;
    mutable QString m_cachedLogoDataUrl;
    mutable QString m_cachedLogoPath;

    Statistics *m_statistics = nullptr;
    GeoLocation *m_geo = nullptr;
    AppSettings *m_settings = nullptr;
};

#endif // REPORTBUILDERWINDOW_H
