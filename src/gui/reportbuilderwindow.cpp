#include "reportbuilderwindow.h"

#include "../mainwindow.h"
#include "../statistics/statistics.h"
#include "../statistics/anomalydetector.h"
#include "../appsettings.h"
#include "../../packets/packet_geolocation/geolocation.h"

#include <QAction>
#include <QBuffer>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QGroupBox>
#include <QDate>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QImage>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMainWindow>
#include <QMarginsF>
#include <QMessageBox>
#include <QDateEdit>
#include <QHash>
#include <QPainter>
#include <QPainterPath>
#include <QPrinter>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QScrollArea>
#include <QFrame>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTextEdit>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QStandardPaths>
#include <QSignalBlocker>
#include <QLocale>
#include <QFileInfo>
#include <algorithm>
#include <cmath>
#include <limits>

namespace {
QString sectionKindLabel(ReportBuilderWindow::ReportSection::Kind kind)
{
    switch (kind) {
    case ReportBuilderWindow::ReportSection::Kind::Heading:
        return QObject::tr("Heading");
    case ReportBuilderWindow::ReportSection::Kind::Text:
        return QObject::tr("Text");
    case ReportBuilderWindow::ReportSection::Kind::Annotation:
        return QObject::tr("Packet Sequence");
    case ReportBuilderWindow::ReportSection::Kind::Statistics:
        return QObject::tr("Statistics");
    case ReportBuilderWindow::ReportSection::Kind::Anomalies:
        return QObject::tr("Anomalies");
    case ReportBuilderWindow::ReportSection::Kind::GeoOverview:
        return QObject::tr("GeoOverview");
    }
    return QObject::tr("Section");
}

QString cleanFileTitle(const QString &path)
{
    return QFileInfo(path).baseName();
}

QString anomalyEventId(const AnomalyDetector::Event &event)
{
    const QString key = QStringLiteral("%1|%2|%3")
                            .arg(event.second)
                            .arg(event.summary)
                            .arg(QString::number(event.score, 'f', 4));
    return QString::number(qHash(key));
}
}

ReportBuilderWindow::ReportBuilderWindow(const QVector<PacketAnnotation> &annotations,
                                         Statistics *statistics,
                                         GeoLocation *geo,
                                         AppSettings *settings,
                                         QWidget *parent)
    : QMainWindow(parent),
      m_statistics(statistics),
      m_geo(geo),
      m_settings(settings)
{
    setWindowTitle(tr("Report Builder"));
    const QSize fixedSize(1720, 900);
    setFixedSize(fixedSize);

    resetHeaderToDefaults();

    ensureReportingDirectory();
    loadAvailableAnnotations();
    loadStatisticsSessions();
    loadStoredAnomalies();
    persistCurrentAnomalies();
    if (!QFile::exists(anomaliesFilePath()))
        saveStoredAnomalies();

    Q_UNUSED(annotations);

    buildUi();
    regenerateAutoSections();
    refreshSectionList();
}

void ReportBuilderWindow::buildUi()
{
    auto *sectionBar = addToolBar(tr("Sections"));
    sectionBar->setMovable(false);

    sectionBar->addAction(tr("Add Heading"), this, &ReportBuilderWindow::addHeadingSection);
    sectionBar->addAction(tr("Add Text"), this, &ReportBuilderWindow::addTextSection);
    sectionBar->addAction(tr("Add Packet Report"), this, &ReportBuilderWindow::addAnnotationSection);
    sectionBar->addSeparator();
    sectionBar->addAction(tr("Add Statistics"), this, &ReportBuilderWindow::addStatisticsSection);
    sectionBar->addAction(tr("Add Anomalies"), this, &ReportBuilderWindow::addAnomalySection);
    sectionBar->addAction(tr("Add GeoOverview"), this, &ReportBuilderWindow::addGeoSection);

    auto *fileBar = addToolBar(tr("Report"));
    fileBar->setMovable(false);
    fileBar->addAction(tr("Save Draft"), this, &ReportBuilderWindow::saveDraft);
    fileBar->addAction(tr("Load Draft"), this, &ReportBuilderWindow::loadDraft);
    fileBar->addAction(tr("Save Report"), this, &ReportBuilderWindow::saveReportToFile);
    fileBar->addAction(tr("Load Report"), this, &ReportBuilderWindow::loadReportFromFile);
    fileBar->addAction(tr("Save Template"), this, &ReportBuilderWindow::saveTemplate);
    fileBar->addAction(tr("Load Template"), this, &ReportBuilderWindow::loadTemplate);
    fileBar->addAction(tr("Export PDF"), this, &ReportBuilderWindow::exportToPdf);

    auto *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    auto *splitter = new QSplitter(Qt::Horizontal, central);
    splitter->setChildrenCollapsible(false);

    auto *leftWidget = new QWidget(splitter);
    leftWidget->setMinimumWidth(760);
    auto *leftLayout = new QVBoxLayout(leftWidget);
    leftLayout->setContentsMargins(12, 12, 12, 12);
    leftLayout->setSpacing(8);

    setupHeaderControls(leftWidget, leftLayout);

    auto *sectionLabel = new QLabel(tr("Sections"), leftWidget);
    sectionLabel->setStyleSheet(QStringLiteral("font-weight:600; letter-spacing:0.3px;"));
    leftLayout->addWidget(sectionLabel);

    m_sectionList = new QListWidget(leftWidget);
    m_sectionList->setSelectionMode(QAbstractItemView::SingleSelection);
    leftLayout->addWidget(m_sectionList);

    auto *listButtons = new QHBoxLayout;
    auto *removeBtn = new QPushButton(tr("Remove"), leftWidget);
    auto *upBtn = new QPushButton(tr("Move Up"), leftWidget);
    auto *downBtn = new QPushButton(tr("Move Down"), leftWidget);
    listButtons->addWidget(removeBtn);
    listButtons->addWidget(upBtn);
    listButtons->addWidget(downBtn);
    leftLayout->addLayout(listButtons);

    connect(removeBtn, &QPushButton::clicked, this, &ReportBuilderWindow::removeSelectedSection);
    connect(upBtn, &QPushButton::clicked, this, &ReportBuilderWindow::moveSectionUp);
    connect(downBtn, &QPushButton::clicked, this, &ReportBuilderWindow::moveSectionDown);

    m_editorStack = new QStackedWidget(leftWidget);
    m_editorStack->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);

    m_emptyPage = new QWidget(this);
    auto *emptyLayout = new QVBoxLayout(m_emptyPage);
    emptyLayout->setContentsMargins(32, 32, 32, 32);
    emptyLayout->addStretch();
    auto *placeholder = new QLabel(tr("Add sections on the left to start building a report."), m_emptyPage);
    placeholder->setWordWrap(true);
    placeholder->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(placeholder);
    emptyLayout->addStretch();

    m_headingEditor = createHeadingEditor();
    m_textEditor = createTextEditor();
    m_annotationEditor = createAnnotationEditor();
    m_statisticsEditor = createAutoSectionEditor(tr("Statistics"));
    m_anomaliesEditor = createAutoSectionEditor(tr("Anomalies"));
    m_geoEditor = createAutoSectionEditor(tr("GeoOverview"));

    setupStatisticsEditor();
    setupAnomaliesEditor();

    m_editorStack->addWidget(m_emptyPage);
    m_editorStack->addWidget(m_headingEditor.page);
    m_editorStack->addWidget(m_textEditor.page);
    m_editorStack->addWidget(m_annotationEditor.page);
    m_editorStack->addWidget(m_statisticsEditor.page);
    m_editorStack->addWidget(m_anomaliesEditor.page);
    m_editorStack->addWidget(m_geoEditor.page);

    auto *editorContainer = new QWidget(leftWidget);
    auto *editorLayout = new QVBoxLayout(editorContainer);
    editorLayout->setContentsMargins(0, 0, 0, 0);
    editorLayout->setSpacing(0);
    editorLayout->addWidget(m_editorStack);
    editorLayout->addStretch();

    auto *editorScroll = new QScrollArea(leftWidget);
    editorScroll->setFrameShape(QFrame::NoFrame);
    editorScroll->setWidgetResizable(true);
    editorScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    editorScroll->setWidget(editorContainer);

    leftLayout->addWidget(editorScroll, 1);

    m_preview = new QTextBrowser(splitter);
    m_preview->setOpenLinks(false);
    m_preview->setOpenExternalLinks(false);
    m_preview->setReadOnly(true);
    m_preview->setStyleSheet(QStringLiteral("QTextBrowser{border:none;padding:16px;background:#fdfdfd;}"));
    m_preview->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    m_preview->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    if (m_preview->document())
        m_preview->document()->setDocumentMargin(24.0);

    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({780, 940});

    mainLayout->addWidget(splitter);
    setCentralWidget(central);

    connect(m_sectionList, &QListWidget::currentRowChanged,
            this, &ReportBuilderWindow::handleSectionSelectionChanged);

    connectEditorSignals(m_headingEditor, ReportSection::Kind::Heading);
    connectEditorSignals(m_textEditor, ReportSection::Kind::Text);
    connectEditorSignals(m_annotationEditor, ReportSection::Kind::Annotation);
    connectEditorSignals(m_statisticsEditor, ReportSection::Kind::Statistics);
    connectEditorSignals(m_anomaliesEditor, ReportSection::Kind::Anomalies);
    connectEditorSignals(m_geoEditor, ReportSection::Kind::GeoOverview);
}

void ReportBuilderWindow::setupHeaderControls(QWidget *parent, QVBoxLayout *layout)
{
    if (!layout)
        return;

    m_headerWidgets.group = new QGroupBox(tr("Report header"), parent);
    auto *groupLayout = new QVBoxLayout(m_headerWidgets.group);
    groupLayout->setContentsMargins(12, 12, 12, 12);
    groupLayout->setSpacing(8);

    groupLayout->addWidget(new QLabel(tr("Organization"), m_headerWidgets.group));
    m_headerWidgets.organizationEdit = new QLineEdit(m_headerWidgets.group);
    m_headerWidgets.organizationEdit->setPlaceholderText(tr("Company or team name"));
    groupLayout->addWidget(m_headerWidgets.organizationEdit);

    groupLayout->addWidget(new QLabel(tr("Title"), m_headerWidgets.group));
    m_headerWidgets.titleEdit = new QLineEdit(m_headerWidgets.group);
    m_headerWidgets.titleEdit->setPlaceholderText(tr("Report headline"));
    groupLayout->addWidget(m_headerWidgets.titleEdit);

    auto *periodRow = new QHBoxLayout;
    periodRow->setSpacing(6);
    m_headerWidgets.periodPresetCombo = new QComboBox(m_headerWidgets.group);
    m_headerWidgets.periodPresetCombo->addItem(tr("Daily"), QStringLiteral("daily"));
    m_headerWidgets.periodPresetCombo->addItem(tr("Weekly"), QStringLiteral("weekly"));
    m_headerWidgets.periodPresetCombo->addItem(tr("Monthly"), QStringLiteral("monthly"));
    m_headerWidgets.periodPresetCombo->addItem(tr("Custom"), QStringLiteral("custom"));
    periodRow->addWidget(m_headerWidgets.periodPresetCombo, 1);

    const QString dateFormat = QLocale().dateFormat(QLocale::ShortFormat);
    m_headerWidgets.periodStartEdit = new QDateEdit(m_headerWidgets.group);
    m_headerWidgets.periodStartEdit->setCalendarPopup(true);
    m_headerWidgets.periodStartEdit->setDisplayFormat(dateFormat);
    periodRow->addWidget(m_headerWidgets.periodStartEdit, 1);

    m_headerWidgets.periodEndEdit = new QDateEdit(m_headerWidgets.group);
    m_headerWidgets.periodEndEdit->setCalendarPopup(true);
    m_headerWidgets.periodEndEdit->setDisplayFormat(dateFormat);
    periodRow->addWidget(m_headerWidgets.periodEndEdit, 1);
    groupLayout->addLayout(periodRow);

    m_headerWidgets.periodSummaryLabel = new QLabel(m_headerWidgets.group);
    m_headerWidgets.periodSummaryLabel->setWordWrap(true);
    m_headerWidgets.periodSummaryLabel->setStyleSheet(QStringLiteral("color:#364152;"));
    groupLayout->addWidget(m_headerWidgets.periodSummaryLabel);

    groupLayout->addWidget(new QLabel(tr("Logo"), m_headerWidgets.group));
    auto *logoRow = new QHBoxLayout;
    logoRow->setSpacing(6);
    m_headerWidgets.logoPathEdit = new QLineEdit(m_headerWidgets.group);
    m_headerWidgets.logoPathEdit->setReadOnly(true);
    m_headerWidgets.logoPathEdit->setPlaceholderText(tr("No logo selected"));
    logoRow->addWidget(m_headerWidgets.logoPathEdit, 1);
    m_headerWidgets.logoBrowseButton = new QPushButton(tr("Browse…"), m_headerWidgets.group);
    logoRow->addWidget(m_headerWidgets.logoBrowseButton);
    m_headerWidgets.logoClearButton = new QPushButton(tr("Clear"), m_headerWidgets.group);
    logoRow->addWidget(m_headerWidgets.logoClearButton);
    groupLayout->addLayout(logoRow);

    layout->addWidget(m_headerWidgets.group);

    connect(m_headerWidgets.organizationEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_header.organization = text;
        updatePreview();
    });

    connect(m_headerWidgets.titleEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_header.title = text;
        updatePreview();
    });

    connect(m_headerWidgets.periodPresetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            [this]() {
                if (!m_headerWidgets.periodPresetCombo)
                    return;
                m_header.periodPreset = m_headerWidgets.periodPresetCombo->currentData().toString();
                applyHeaderPreset();
                syncHeaderEditors();
                updatePreview();
            });

    connect(m_headerWidgets.periodStartEdit, &QDateEdit::dateChanged, this, [this](const QDate &date) {
        m_header.periodStart = date;
        if (m_header.periodPreset == QStringLiteral("monthly"))
            m_header.periodStart = QDate(date.year(), date.month(), 1);
        if (m_header.periodPreset != QStringLiteral("custom"))
            applyHeaderPreset();
        else
            ensureHeaderOrder();
        syncHeaderEditors();
        updatePreview();
    });

    connect(m_headerWidgets.periodEndEdit, &QDateEdit::dateChanged, this, [this](const QDate &date) {
        m_header.periodEnd = date;
        ensureHeaderOrder();
        if (m_header.periodPreset != QStringLiteral("custom") &&
            !matchesPreset(m_header.periodPreset, m_header.periodStart, m_header.periodEnd)) {
            m_header.periodPreset = QStringLiteral("custom");
        }
        syncHeaderEditors();
        updatePreview();
    });

    connect(m_headerWidgets.logoBrowseButton, &QPushButton::clicked, this, [this]() {
        const QString filePath = QFileDialog::getOpenFileName(this,
                                                              tr("Select logo"),
                                                              QDir::homePath(),
                                                              tr("Images (*.png *.jpg *.jpeg *.bmp *.gif *.svg)"));
        if (filePath.isEmpty())
            return;
        QImage image(filePath);
        if (image.isNull()) {
            QMessageBox::warning(this, tr("Logo"), tr("Unable to load image %1").arg(filePath));
            return;
        }
        m_header.logoPath = filePath;
        m_cachedLogoPath.clear();
        m_cachedLogoDataUrl.clear();
        syncHeaderEditors();
        updatePreview();
        statusBar()->showMessage(tr("Logo updated"), 3000);
    });

    connect(m_headerWidgets.logoClearButton, &QPushButton::clicked, this, [this]() {
        if (m_header.logoPath.isEmpty())
            return;
        m_header.logoPath.clear();
        m_cachedLogoPath.clear();
        m_cachedLogoDataUrl.clear();
        syncHeaderEditors();
        updatePreview();
    });

    syncHeaderEditors();
}

void ReportBuilderWindow::resetHeaderToDefaults()
{
    m_header.organization = tr("Security Operations Center");
    m_header.title = tr("Network Monitoring Report");
    m_header.periodPreset = QStringLiteral("weekly");
    m_header.periodStart = QDate::currentDate().addDays(-6);
    m_header.periodEnd = QDate::currentDate();
    if (!m_header.periodStart.isValid())
        m_header.periodStart = QDate::currentDate();
    if (!m_header.periodEnd.isValid())
        m_header.periodEnd = m_header.periodStart;
    m_header.logoPath.clear();
    m_cachedLogoDataUrl.clear();
    m_cachedLogoPath.clear();
    applyHeaderPreset();
}

void ReportBuilderWindow::syncHeaderEditors()
{
    if (!m_headerWidgets.group)
        return;

    if (m_headerWidgets.organizationEdit) {
        const QSignalBlocker blocker(m_headerWidgets.organizationEdit);
        m_headerWidgets.organizationEdit->setText(m_header.organization);
    }
    if (m_headerWidgets.titleEdit) {
        const QSignalBlocker blocker(m_headerWidgets.titleEdit);
        m_headerWidgets.titleEdit->setText(m_header.title);
    }
    if (m_headerWidgets.periodPresetCombo) {
        const QSignalBlocker blocker(m_headerWidgets.periodPresetCombo);
        int found = -1;
        for (int i = 0; i < m_headerWidgets.periodPresetCombo->count(); ++i) {
            if (m_headerWidgets.periodPresetCombo->itemData(i).toString() == m_header.periodPreset) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            m_header.periodPreset = QStringLiteral("custom");
            found = m_headerWidgets.periodPresetCombo->findData(m_header.periodPreset);
        }
        if (found >= 0)
            m_headerWidgets.periodPresetCombo->setCurrentIndex(found);
    }
    if (m_headerWidgets.periodStartEdit) {
        const QSignalBlocker blocker(m_headerWidgets.periodStartEdit);
        if (!m_header.periodStart.isValid())
            m_header.periodStart = QDate::currentDate();
        m_headerWidgets.periodStartEdit->setDate(m_header.periodStart);
    }
    if (m_headerWidgets.periodEndEdit) {
        const QSignalBlocker blocker(m_headerWidgets.periodEndEdit);
        if (!m_header.periodEnd.isValid())
            m_header.periodEnd = m_header.periodStart;
        m_headerWidgets.periodEndEdit->setDate(m_header.periodEnd);
    }
    if (m_headerWidgets.logoPathEdit) {
        const QSignalBlocker blocker(m_headerWidgets.logoPathEdit);
        m_headerWidgets.logoPathEdit->setText(m_header.logoPath);
        if (!m_header.logoPath.isEmpty())
            m_headerWidgets.logoPathEdit->setToolTip(m_header.logoPath);
        else
            m_headerWidgets.logoPathEdit->setToolTip(QString());
    }
    if (m_headerWidgets.logoClearButton)
        m_headerWidgets.logoClearButton->setEnabled(!m_header.logoPath.isEmpty());
    updateHeaderPeriodSummary();
}

void ReportBuilderWindow::updateHeaderPeriodSummary()
{
    if (!m_headerWidgets.periodSummaryLabel)
        return;
    const QString summary = headerPeriodText();
    if (summary.isEmpty())
        m_headerWidgets.periodSummaryLabel->setText(tr("Select a preset and window for this report."));
    else
        m_headerWidgets.periodSummaryLabel->setText(summary);
}

void ReportBuilderWindow::applyHeaderPreset()
{
    if (!m_header.periodStart.isValid())
        m_header.periodStart = QDate::currentDate();
    if (!m_header.periodEnd.isValid())
        m_header.periodEnd = m_header.periodStart;

    if (m_header.periodPreset == QStringLiteral("daily")) {
        m_header.periodEnd = m_header.periodStart;
    } else if (m_header.periodPreset == QStringLiteral("weekly")) {
        m_header.periodEnd = m_header.periodStart.addDays(6);
    } else if (m_header.periodPreset == QStringLiteral("monthly")) {
        m_header.periodStart = QDate(m_header.periodStart.year(), m_header.periodStart.month(), 1);
        m_header.periodEnd = m_header.periodStart.addMonths(1).addDays(-1);
    }
    ensureHeaderOrder();
}

void ReportBuilderWindow::ensureHeaderOrder()
{
    if (m_header.periodStart.isValid() && m_header.periodEnd.isValid() && m_header.periodEnd < m_header.periodStart)
        m_header.periodEnd = m_header.periodStart;
}

QString ReportBuilderWindow::headerPeriodText() const
{
    const QString presetLabel = headerPresetLabel(m_header.periodPreset);
    const QLocale locale;
    if (m_header.periodStart.isValid() && m_header.periodEnd.isValid()) {
        if (m_header.periodStart == m_header.periodEnd)
            return tr("%1 coverage: %2")
                .arg(presetLabel,
                     locale.toString(m_header.periodStart, QLocale::ShortFormat));
        return tr("%1 coverage: %2 → %3")
            .arg(presetLabel,
                 locale.toString(m_header.periodStart, QLocale::ShortFormat),
                 locale.toString(m_header.periodEnd, QLocale::ShortFormat));
    }
    if (m_header.periodStart.isValid())
        return tr("%1 coverage starting %2")
            .arg(presetLabel,
                 locale.toString(m_header.periodStart, QLocale::ShortFormat));
    if (m_header.periodEnd.isValid())
        return tr("%1 coverage through %2")
            .arg(presetLabel,
                 locale.toString(m_header.periodEnd, QLocale::ShortFormat));
    return QString();
}

QString ReportBuilderWindow::headerPresetLabel(const QString &preset) const
{
    if (preset == QStringLiteral("daily"))
        return tr("Daily");
    if (preset == QStringLiteral("weekly"))
        return tr("Weekly");
    if (preset == QStringLiteral("monthly"))
        return tr("Monthly");
    return tr("Custom");
}

bool ReportBuilderWindow::matchesPreset(const QString &preset, const QDate &start, const QDate &end) const
{
    if (!start.isValid() || !end.isValid())
        return false;
    if (preset == QStringLiteral("daily"))
        return start == end;
    if (preset == QStringLiteral("weekly"))
        return start.addDays(6) == end;
    if (preset == QStringLiteral("monthly")) {
        const QDate first(start.year(), start.month(), 1);
        const QDate last = first.addMonths(1).addDays(-1);
        return start == first && end == last;
    }
    return true;
}

QString ReportBuilderWindow::headerHtml() const
{
    const QString period = headerPeriodText();
    const QString logo = headerLogoImgTag();
    if (m_header.organization.isEmpty() && m_header.title.isEmpty() && period.isEmpty() && logo.isEmpty())
        return QString();

    QString html;
    html += QStringLiteral("<div class=\"report-header\">");
    html += QStringLiteral("<div class=\"header-text\">");
    if (!m_header.organization.isEmpty())
        html += QStringLiteral("<div class=\"header-organization\">%1</div>")
                    .arg(m_header.organization.toHtmlEscaped());
    if (!m_header.title.isEmpty())
        html += QStringLiteral("<div class=\"header-title\">%1</div>")
                    .arg(m_header.title.toHtmlEscaped());
    if (!period.isEmpty())
        html += QStringLiteral("<div class=\"header-period\">%1</div>")
                    .arg(period.toHtmlEscaped());
    html += QStringLiteral("</div>");
    if (!logo.isEmpty())
        html += QStringLiteral("<div class=\"header-logo-wrap\">%1</div>").arg(logo);
    html += QStringLiteral("</div>");
    return html;
}

QString ReportBuilderWindow::headerLogoImgTag() const
{
    if (m_header.logoPath.isEmpty())
        return QString();
    if (m_cachedLogoPath != m_header.logoPath) {
        QImage image(m_header.logoPath);
        if (image.isNull()) {
            m_cachedLogoPath = m_header.logoPath;
            m_cachedLogoDataUrl.clear();
            return QString();
        }
        QByteArray bufferArray;
        QBuffer buffer(&bufferArray);
        buffer.open(QIODevice::WriteOnly);
        image.save(&buffer, "PNG");
        m_cachedLogoDataUrl = QStringLiteral("data:image/png;base64,%1")
                                  .arg(QString::fromLatin1(bufferArray.toBase64()));
        m_cachedLogoPath = m_header.logoPath;
    }
    if (m_cachedLogoDataUrl.isEmpty())
        return QString();
    return QStringLiteral("<img class=\"header-logo\" src=\"%1\" alt=\"Logo\"/>")
        .arg(m_cachedLogoDataUrl);
}

void ReportBuilderWindow::addPagePlacementControls(EditorWidgets &editor, QVBoxLayout *layout)
{
    if (!layout || !editor.page)
        return;
    auto *label = new QLabel(tr("Page placement"), editor.page);
    label->setToolTip(tr("Choose the report page for this section. Set to Automatic to follow the natural order."));
    layout->addWidget(label);
    editor.pageSpin = new QSpinBox(editor.page);
    editor.pageSpin->setRange(0, 999);
    editor.pageSpin->setSpecialValueText(tr("Automatic"));
    editor.pageSpin->setToolTip(tr("Select a target page or leave Automatic to append sequentially."));
    layout->addWidget(editor.pageSpin);
}

ReportBuilderWindow::EditorWidgets ReportBuilderWindow::createHeadingEditor()
{
    EditorWidgets editor;
    editor.page = new QWidget(this);
    auto *layout = new QVBoxLayout(editor.page);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    editor.titleEdit = new QLineEdit(editor.page);
    editor.titleEdit->setPlaceholderText(tr("Heading text"));
    layout->addWidget(new QLabel(tr("Heading"), editor.page));
    layout->addWidget(editor.titleEdit);

    editor.levelSpin = new QSpinBox(editor.page);
    editor.levelSpin->setRange(1, 4);
    editor.levelSpin->setValue(1);
    layout->addWidget(new QLabel(tr("Level"), editor.page));
    layout->addWidget(editor.levelSpin);

    addPagePlacementControls(editor, layout);

    editor.metaLabel = new QLabel(tr("Use headings to define report chapters."), editor.page);
    editor.metaLabel->setWordWrap(true);
    layout->addWidget(editor.metaLabel);

    layout->addStretch();
    return editor;
}

ReportBuilderWindow::EditorWidgets ReportBuilderWindow::createTextEditor()
{
    EditorWidgets editor;
    editor.page = new QWidget(this);
    auto *layout = new QVBoxLayout(editor.page);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    editor.titleEdit = new QLineEdit(editor.page);
    editor.titleEdit->setPlaceholderText(tr("Optional section heading"));
    layout->addWidget(new QLabel(tr("Title"), editor.page));
    layout->addWidget(editor.titleEdit);

    addPagePlacementControls(editor, layout);

    editor.bodyEdit = new QTextEdit(editor.page);
    editor.bodyEdit->setPlaceholderText(tr("Write narrative text for this section…"));
    editor.bodyEdit->setAcceptRichText(false);
    editor.bodyEdit->setTabChangesFocus(true);
    layout->addWidget(new QLabel(tr("Body"), editor.page));
    layout->addWidget(editor.bodyEdit, 1);

    editor.metaLabel = new QLabel(tr("Use markdown-like plain text. Paragraphs and bullet lists are supported when exported."), editor.page);
    editor.metaLabel->setWordWrap(true);
    layout->addWidget(editor.metaLabel);

    return editor;
}

ReportBuilderWindow::EditorWidgets ReportBuilderWindow::createAnnotationEditor()
{
    EditorWidgets editor;
    editor.page = new QWidget(this);
    auto *layout = new QVBoxLayout(editor.page);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    editor.titleEdit = new QLineEdit(editor.page);
    editor.titleEdit->setPlaceholderText(tr("Section title"));
    layout->addWidget(new QLabel(tr("Title"), editor.page));
    layout->addWidget(editor.titleEdit);

    addPagePlacementControls(editor, layout);

    editor.annotationCombo = new QComboBox(editor.page);
    layout->addWidget(new QLabel(tr("Packet annotation"), editor.page));
    layout->addWidget(editor.annotationCombo);
    refreshAnnotationCombo(editor.annotationCombo);

    editor.packetTableCheck = new QCheckBox(tr("Include packet table"), editor.page);
    editor.packetTableCheck->setChecked(true);
    editor.tagCheck = new QCheckBox(tr("Include tags"), editor.page);
    editor.tagCheck->setChecked(true);
    editor.colorCheck = new QCheckBox(tr("Show highlight colors"), editor.page);
    editor.colorCheck->setChecked(true);
    layout->addWidget(editor.packetTableCheck);
    layout->addWidget(editor.tagCheck);
    layout->addWidget(editor.colorCheck);

    editor.metaLabel = new QLabel(tr("Packet annotations originate from the packet table reporting workflow."), editor.page);
    editor.metaLabel->setWordWrap(true);
    layout->addWidget(editor.metaLabel);

    layout->addStretch();
    return editor;
}

ReportBuilderWindow::EditorWidgets ReportBuilderWindow::createAutoSectionEditor(const QString &title)
{
    EditorWidgets editor;
    editor.page = new QWidget(this);
    auto *layout = new QVBoxLayout(editor.page);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    editor.titleEdit = new QLineEdit(editor.page);
    editor.titleEdit->setPlaceholderText(tr("Section title"));
    layout->addWidget(new QLabel(tr("Title"), editor.page));
    layout->addWidget(editor.titleEdit);

    addPagePlacementControls(editor, layout);

    editor.bodyEdit = new QTextEdit(editor.page);
    editor.bodyEdit->setAcceptRichText(false);
    editor.bodyEdit->setPlaceholderText(tr("Summary text"));
    layout->addWidget(new QLabel(tr("Summary"), editor.page));
    layout->addWidget(editor.bodyEdit, 1);

    editor.regenerateButton = new QPushButton(tr("Regenerate %1").arg(title), editor.page);
    layout->addWidget(editor.regenerateButton);

    editor.metaLabel = new QLabel(editor.page);
    editor.metaLabel->setWordWrap(true);
    layout->addWidget(editor.metaLabel);

    layout->addStretch();

    return editor;
}

void ReportBuilderWindow::setupStatisticsEditor()
{
    auto *layout = qobject_cast<QVBoxLayout *>(m_statisticsEditor.page->layout());
    if (!layout)
        return;

    int insertIndex = layout->indexOf(m_statisticsEditor.regenerateButton);
    if (insertIndex < 0)
        insertIndex = layout->count();

    auto *sessionsGroup = new QGroupBox(tr("Statistics sessions"), m_statisticsEditor.page);
    auto *sessionsLayout = new QVBoxLayout(sessionsGroup);
    sessionsLayout->setSpacing(8);
    sessionsLayout->setContentsMargins(12, 12, 12, 12);

    auto *sessionsHint = new QLabel(tr("Select one or more saved captures to combine."), sessionsGroup);
    sessionsHint->setWordWrap(true);
    sessionsLayout->addWidget(sessionsHint);

    m_statisticsEditor.statsSessionList = new QListWidget(sessionsGroup);
    m_statisticsEditor.statsSessionList->setSelectionMode(QAbstractItemView::NoSelection);
    m_statisticsEditor.statsSessionList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_statisticsEditor.statsSessionList->setMinimumHeight(150);
    m_statisticsEditor.statsSessionList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    sessionsLayout->addWidget(m_statisticsEditor.statsSessionList);

    auto *rangeGrid = new QGridLayout;
    rangeGrid->setContentsMargins(0, 0, 0, 0);
    rangeGrid->setHorizontalSpacing(8);
    rangeGrid->setVerticalSpacing(6);

    rangeGrid->addWidget(new QLabel(tr("From second"), sessionsGroup), 0, 0);
    m_statisticsEditor.statsRangeStart = new QSpinBox(sessionsGroup);
    m_statisticsEditor.statsRangeStart->setRange(0, 0);
    m_statisticsEditor.statsRangeStart->setValue(0);
    m_statisticsEditor.statsRangeStart->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    rangeGrid->addWidget(m_statisticsEditor.statsRangeStart, 0, 1);

    rangeGrid->addWidget(new QLabel(tr("To second"), sessionsGroup), 1, 0);
    m_statisticsEditor.statsRangeEnd = new QSpinBox(sessionsGroup);
    m_statisticsEditor.statsRangeEnd->setRange(-1, 0);
    m_statisticsEditor.statsRangeEnd->setSpecialValueText(tr("End of capture"));
    m_statisticsEditor.statsRangeEnd->setValue(-1);
    m_statisticsEditor.statsRangeEnd->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    rangeGrid->addWidget(m_statisticsEditor.statsRangeEnd, 1, 1);
    rangeGrid->setColumnStretch(1, 1);

    sessionsLayout->addLayout(rangeGrid);

    m_statisticsEditor.statsRangeHint = new QLabel(sessionsGroup);
    m_statisticsEditor.statsRangeHint->setWordWrap(true);
    sessionsLayout->addWidget(m_statisticsEditor.statsRangeHint);

    layout->insertWidget(insertIndex++, sessionsGroup);

    auto *chartsGroup = new QGroupBox(tr("Charts to include"), m_statisticsEditor.page);
    auto *chartsLayout = new QVBoxLayout(chartsGroup);
    chartsLayout->setSpacing(8);
    chartsLayout->setContentsMargins(12, 12, 12, 12);

    auto *chartsHint = new QLabel(tr("Toggle charts that should render in the summary."), chartsGroup);
    chartsHint->setWordWrap(true);
    chartsLayout->addWidget(chartsHint);

    m_statisticsEditor.statsChartList = new QListWidget(chartsGroup);
    m_statisticsEditor.statsChartList->setSelectionMode(QAbstractItemView::NoSelection);
    m_statisticsEditor.statsChartList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_statisticsEditor.statsChartList->setMinimumHeight(140);
    m_statisticsEditor.statsChartList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    chartsLayout->addWidget(m_statisticsEditor.statsChartList);

    layout->insertWidget(insertIndex++, chartsGroup);

    if (m_statisticsEditor.metaLabel)
        m_statisticsEditor.metaLabel->setText(tr("Combine multiple statistics sessions, clamp the time window, and embed matching charts."));

    refreshStatisticsSessionList();
    refreshStatisticsChartsSelection();
    updateStatisticsRangeLimits();

    connect(m_statisticsEditor.statsSessionList, &QListWidget::itemChanged,
            this, [this](QListWidgetItem *) {
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx < 0 || idx >= m_sections.size())
                    return;
                ReportSection &section = m_sections[idx];
                if (section.kind != ReportSection::Kind::Statistics)
                    return;
                QStringList selected;
                for (int i = 0; i < m_statisticsEditor.statsSessionList->count(); ++i) {
                    QListWidgetItem *item = m_statisticsEditor.statsSessionList->item(i);
                    if (item->checkState() == Qt::Checked)
                        selected.append(item->data(Qt::UserRole).toString());
                }
                section.statSessionFiles = selected;
                section.body = statisticsSummaryText(section);
                updateStatisticsRangeLimits();
                syncEditorWithSection(idx);
                updatePreview();
            });

    connect(m_statisticsEditor.statsRangeStart, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this](int value) {
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx < 0 || idx >= m_sections.size())
                    return;
                ReportSection &section = m_sections[idx];
                if (section.kind != ReportSection::Kind::Statistics)
                    return;
                section.statRangeStart = value;
                section.body = statisticsSummaryText(section);
                updateStatisticsRangeLimits();
                syncEditorWithSection(idx);
                updatePreview();
            });

    connect(m_statisticsEditor.statsRangeEnd, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this](int value) {
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx < 0 || idx >= m_sections.size())
                    return;
                ReportSection &section = m_sections[idx];
                if (section.kind != ReportSection::Kind::Statistics)
                    return;
                section.statRangeEnd = value;
                section.body = statisticsSummaryText(section);
                updateStatisticsRangeLimits();
                syncEditorWithSection(idx);
                updatePreview();
            });

    connect(m_statisticsEditor.statsChartList, &QListWidget::itemChanged,
            this, [this](QListWidgetItem *) {
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx < 0 || idx >= m_sections.size())
                    return;
                ReportSection &section = m_sections[idx];
                if (section.kind != ReportSection::Kind::Statistics)
                    return;
                QStringList charts;
                for (int i = 0; i < m_statisticsEditor.statsChartList->count(); ++i) {
                    QListWidgetItem *item = m_statisticsEditor.statsChartList->item(i);
                    if (item->checkState() == Qt::Checked)
                        charts.append(item->data(Qt::UserRole).toString());
                }
                section.statChartKinds = charts;
                updatePreview();
            });
}

void ReportBuilderWindow::setupAnomaliesEditor()
{
    auto *layout = qobject_cast<QVBoxLayout *>(m_anomaliesEditor.page->layout());
    if (!layout)
        return;

    int insertIndex = layout->indexOf(m_anomaliesEditor.regenerateButton);
    if (insertIndex < 0)
        insertIndex = layout->count();

    auto *libraryGroup = new QGroupBox(tr("Saved anomalies"), m_anomaliesEditor.page);
    auto *libraryLayout = new QVBoxLayout(libraryGroup);
    libraryLayout->setSpacing(8);
    libraryLayout->setContentsMargins(12, 12, 12, 12);

    m_anomaliesEditor.anomalyLibrary = new QListWidget(libraryGroup);
    m_anomaliesEditor.anomalyLibrary->setSelectionMode(QAbstractItemView::NoSelection);
    m_anomaliesEditor.anomalyLibrary->setMinimumHeight(150);
    m_anomaliesEditor.anomalyLibrary->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    libraryLayout->addWidget(m_anomaliesEditor.anomalyLibrary);

    auto *buttonGrid = new QGridLayout;
    buttonGrid->setContentsMargins(0, 0, 0, 0);
    buttonGrid->setHorizontalSpacing(8);
    buttonGrid->setVerticalSpacing(6);

    m_anomaliesEditor.refreshLibraryButton = new QPushButton(tr("Reload library"), libraryGroup);
    m_anomaliesEditor.refreshLibraryButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    buttonGrid->addWidget(m_anomaliesEditor.refreshLibraryButton, 0, 0, 1, 2);

    m_anomaliesEditor.importLibraryButton = new QPushButton(tr("Import…"), libraryGroup);
    m_anomaliesEditor.importLibraryButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    buttonGrid->addWidget(m_anomaliesEditor.importLibraryButton, 1, 0);

    m_anomaliesEditor.exportLibraryButton = new QPushButton(tr("Export…"), libraryGroup);
    m_anomaliesEditor.exportLibraryButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    buttonGrid->addWidget(m_anomaliesEditor.exportLibraryButton, 1, 1);

    buttonGrid->setColumnStretch(0, 1);
    buttonGrid->setColumnStretch(1, 1);

    libraryLayout->addLayout(buttonGrid);

    layout->insertWidget(insertIndex++, libraryGroup);

    if (m_anomaliesEditor.metaLabel)
        m_anomaliesEditor.metaLabel->setText(tr("Include live or previously stored anomaly events."));

    refreshAnomalyLibrary();

    connect(m_anomaliesEditor.anomalyLibrary, &QListWidget::itemChanged,
            this, [this](QListWidgetItem *) {
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx < 0 || idx >= m_sections.size())
                    return;
                ReportSection &section = m_sections[idx];
                if (section.kind != ReportSection::Kind::Anomalies)
                    return;
                QStringList selectedIds;
                for (int i = 0; i < m_anomaliesEditor.anomalyLibrary->count(); ++i) {
                    QListWidgetItem *item = m_anomaliesEditor.anomalyLibrary->item(i);
                    if (item->checkState() == Qt::Checked)
                        selectedIds.append(item->data(Qt::UserRole).toString());
                }
                section.storedAnomalyIds = selectedIds;
                section.body = anomaliesSummaryText(section);
                syncEditorWithSection(idx);
                updatePreview();
            });

    connect(m_anomaliesEditor.refreshLibraryButton, &QPushButton::clicked,
            this, [this]() {
                loadStoredAnomalies();
                persistCurrentAnomalies();
                refreshAnomalyLibrary();
                const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
                if (idx >= 0 && idx < m_sections.size() && m_sections[idx].kind == ReportSection::Kind::Anomalies) {
                    m_sections[idx].body = anomaliesSummaryText(m_sections[idx]);
                    syncEditorWithSection(idx);
                    updatePreview();
                }
            });

    if (m_anomaliesEditor.importLibraryButton) {
        connect(m_anomaliesEditor.importLibraryButton, &QPushButton::clicked, this, [this]() {
            const QString filePath = QFileDialog::getOpenFileName(this,
                                                                  tr("Import anomalies"),
                                                                  anomaliesDirectory(),
                                                                  tr("JSON (*.json)"));
            if (filePath.isEmpty())
                return;
            importAnomaliesFromFile(filePath);
        });
    }

    if (m_anomaliesEditor.exportLibraryButton) {
        connect(m_anomaliesEditor.exportLibraryButton, &QPushButton::clicked, this, [this]() {
            QString filePath = QFileDialog::getSaveFileName(this,
                                                           tr("Export anomalies"),
                                                           anomaliesDirectory(),
                                                           tr("JSON (*.json)"));
            if (filePath.isEmpty())
                return;
            if (!filePath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
                filePath.append(QStringLiteral(".json"));
            if (!writeAnomaliesToFile(filePath)) {
                QMessageBox::warning(this, tr("Export anomalies"),
                                     tr("Unable to write anomalies to %1").arg(filePath));
                return;
            }
            statusBar()->showMessage(tr("Anomalies exported to %1").arg(filePath), 6000);
        });
    }
}

void ReportBuilderWindow::refreshStatisticsSessionList()
{
    if (!m_statisticsEditor.statsSessionList)
        return;
    const QSignalBlocker blocker(m_statisticsEditor.statsSessionList);
    m_statisticsEditor.statsSessionList->clear();
    for (const auto &info : m_statisticsSessions) {
        auto *item = new QListWidgetItem(info.displayLabel, m_statisticsEditor.statsSessionList);
        item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
        item->setData(Qt::UserRole, info.filePath);
        item->setCheckState(Qt::Unchecked);
    }
    m_statisticsEditor.statsSessionList->setEnabled(!m_statisticsSessions.isEmpty());
}

void ReportBuilderWindow::refreshStatisticsChartsSelection()
{
    if (!m_statisticsEditor.statsChartList)
        return;
    const QSignalBlocker blocker(m_statisticsEditor.statsChartList);
    m_statisticsEditor.statsChartList->clear();
    for (const QString &key : statisticsChartOptions()) {
        auto *item = new QListWidgetItem(chartLabelForKey(key), m_statisticsEditor.statsChartList);
        item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
        item->setData(Qt::UserRole, key);
        item->setCheckState(Qt::Unchecked);
    }
}

void ReportBuilderWindow::updateStatisticsRangeLimits()
{
    if (!m_statisticsEditor.statsRangeStart || !m_statisticsEditor.statsRangeEnd)
        return;

    QStringList selectedFiles;
    const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
    if (idx >= 0 && idx < m_sections.size() && m_sections[idx].kind == ReportSection::Kind::Statistics)
        selectedFiles = m_sections[idx].statSessionFiles;

    int maxCommon = -1;
    for (const QString &file : selectedFiles) {
        auto it = std::find_if(m_statisticsSessions.cbegin(), m_statisticsSessions.cend(),
                               [&file](const StatisticsSessionInfo &info) {
                                   return info.filePath == file;
                               });
        if (it == m_statisticsSessions.cend())
            continue;
        if (maxCommon < 0)
            maxCommon = it->maxSecond;
        else
            maxCommon = std::min(maxCommon, it->maxSecond);
    }

    const bool hasSelection = !selectedFiles.isEmpty() && maxCommon >= 0;
    {
        const QSignalBlocker startBlocker(m_statisticsEditor.statsRangeStart);
        const QSignalBlocker endBlocker(m_statisticsEditor.statsRangeEnd);
        bool rangeAdjusted = false;
        if (hasSelection) {
            m_statisticsEditor.statsRangeStart->setEnabled(true);
            m_statisticsEditor.statsRangeEnd->setEnabled(true);
            m_statisticsEditor.statsRangeStart->setRange(0, maxCommon);
            m_statisticsEditor.statsRangeEnd->setRange(-1, maxCommon);

            if (idx >= 0 && idx < m_sections.size() && m_sections[idx].kind == ReportSection::Kind::Statistics) {
                ReportSection &section = m_sections[idx];
                if (section.statRangeStart < 0 || section.statRangeStart > maxCommon) {
                    section.statRangeStart = 0;
                    rangeAdjusted = true;
                }
                if (section.statRangeEnd > maxCommon) {
                    section.statRangeEnd = maxCommon;
                    rangeAdjusted = true;
                }
                m_statisticsEditor.statsRangeStart->setValue(section.statRangeStart);
                m_statisticsEditor.statsRangeEnd->setValue(section.statRangeEnd);
            } else {
                m_statisticsEditor.statsRangeStart->setValue(0);
                m_statisticsEditor.statsRangeEnd->setValue(-1);
            }
            if (rangeAdjusted && idx >= 0 && idx < m_sections.size() && m_sections[idx].kind == ReportSection::Kind::Statistics) {
                ReportSection &section = m_sections[idx];
                section.body = statisticsSummaryText(section);
                if (m_statisticsEditor.bodyEdit) {
                    const QSignalBlocker bodyBlocker(m_statisticsEditor.bodyEdit);
                    m_statisticsEditor.bodyEdit->setPlainText(section.body);
                }
                updatePreview();
            }
        } else {
            m_statisticsEditor.statsRangeStart->setEnabled(false);
            m_statisticsEditor.statsRangeEnd->setEnabled(false);
            m_statisticsEditor.statsRangeStart->setValue(0);
            m_statisticsEditor.statsRangeEnd->setValue(-1);
        }
    }

    if (m_statisticsEditor.statsRangeHint) {
        if (!hasSelection) {
            m_statisticsEditor.statsRangeHint->setText(tr("Select at least one statistics session."));
        } else {
            const int startValue = m_statisticsEditor.statsRangeStart->value();
            const int endValue = m_statisticsEditor.statsRangeEnd->value();
            QString hint;
            if (endValue < 0)
                hint = tr("Using samples from second %1 to the end (max %2 seconds available).").arg(startValue).arg(maxCommon);
            else if (endValue < startValue)
                hint = tr("Range end precedes start; adjust values to include samples.");
            else
                hint = tr("Using samples from second %1 through %2 (inclusive).").arg(startValue).arg(endValue);
            m_statisticsEditor.statsRangeHint->setText(hint);
        }
    }
}

void ReportBuilderWindow::refreshAnomalyLibrary()
{
    if (!m_anomaliesEditor.anomalyLibrary)
        return;
    const QSignalBlocker blocker(m_anomaliesEditor.anomalyLibrary);
    m_anomaliesEditor.anomalyLibrary->clear();
    QLocale locale;
    for (const auto &anomaly : m_storedAnomalies) {
        QString label = QStringLiteral("%1 (score %2)").arg(anomaly.summary,
                                                            locale.toString(anomaly.score, 'f', 2));
        if (anomaly.capturedAt.isValid())
            label += QStringLiteral(" — %1").arg(locale.toString(anomaly.capturedAt.toLocalTime(),
                                                                  QLocale::ShortFormat));
        auto *item = new QListWidgetItem(label, m_anomaliesEditor.anomalyLibrary);
        item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
        item->setData(Qt::UserRole, anomaly.id);
        item->setToolTip(anomaly.reasons.join(QStringLiteral("\n")));
        item->setCheckState(Qt::Unchecked);
    }
    m_anomaliesEditor.anomalyLibrary->setEnabled(!m_storedAnomalies.isEmpty());
    if (m_anomaliesEditor.refreshLibraryButton)
        m_anomaliesEditor.refreshLibraryButton->setEnabled(true);
    if (m_anomaliesEditor.importLibraryButton)
        m_anomaliesEditor.importLibraryButton->setEnabled(true);
    if (m_anomaliesEditor.exportLibraryButton)
        m_anomaliesEditor.exportLibraryButton->setEnabled(!m_storedAnomalies.isEmpty());
}

void ReportBuilderWindow::persistCurrentAnomalies()
{
    if (!m_statistics)
        return;

    const auto &events = m_statistics->anomalies();
    if (events.isEmpty())
        return;

    bool added = false;
    for (const auto &event : events) {
        const QString id = anomalyEventId(event);
        const bool exists = std::any_of(m_storedAnomalies.cbegin(), m_storedAnomalies.cend(),
                                        [&id](const StoredAnomaly &entry) { return entry.id == id; });
        if (exists)
            continue;
        StoredAnomaly stored;
        stored.id = id;
        stored.summary = event.summary;
        stored.reasons = event.reasons;
        stored.tags = event.tags;
        stored.score = event.score;
        stored.second = event.second;
        stored.capturedAt = QDateTime::currentDateTimeUtc();
        m_storedAnomalies.append(stored);
        added = true;
    }

    if (added) {
        sortStoredAnomalies();
        saveStoredAnomalies();
    }
}

void ReportBuilderWindow::sortStoredAnomalies()
{
    std::sort(m_storedAnomalies.begin(), m_storedAnomalies.end(), [](const StoredAnomaly &a, const StoredAnomaly &b) {
        const bool aValid = a.capturedAt.isValid();
        const bool bValid = b.capturedAt.isValid();
        if (aValid && bValid && a.capturedAt != b.capturedAt)
            return a.capturedAt > b.capturedAt;
        if (aValid != bValid)
            return aValid;
        if (a.score != b.score)
            return a.score > b.score;
        if (a.second != b.second)
            return a.second < b.second;
        return a.id < b.id;
    });
}

void ReportBuilderWindow::loadStatisticsSessions()
{
    m_statisticsSessions.clear();
    QDir dir(Statistics::defaultSessionsDir());
    if (!dir.exists())
        dir.mkpath(QStringLiteral("."));
    const QStringList files = dir.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Time);
    QLocale locale;
    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly))
            continue;
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject())
            continue;
        const QJsonObject obj = doc.object();
        const QDateTime start = QDateTime::fromString(obj.value(QStringLiteral("sessionStart")).toString(), Qt::ISODate);
        const QDateTime end = QDateTime::fromString(obj.value(QStringLiteral("sessionEnd")).toString(), Qt::ISODate);
        const QJsonArray perSecond = obj.value(QStringLiteral("perSecond")).toArray();
        int maxSecond = 0;
        for (const QJsonValue &value : perSecond)
            maxSecond = std::max(maxSecond, value.toObject().value(QStringLiteral("second")).toInt());

        StatisticsSessionInfo info;
        info.filePath = dir.filePath(fileName);
        info.startTime = start;
        info.endTime = end.isValid() ? end : start;
        info.maxSecond = maxSecond;
        const QString timeLabel = locale.toString(info.startTime.toLocalTime(), QLocale::ShortFormat);
        const QString endLabel = locale.toString(info.endTime.toLocalTime(), QLocale::ShortFormat);
        info.displayLabel = QStringLiteral("%1 → %2 (%3 s)").arg(timeLabel, endLabel).arg(maxSecond);
        m_statisticsSessions.append(info);
    }

    std::sort(m_statisticsSessions.begin(), m_statisticsSessions.end(),
              [](const StatisticsSessionInfo &a, const StatisticsSessionInfo &b) {
                  return a.startTime > b.startTime;
              });

    refreshStatisticsSessionList();
}

void ReportBuilderWindow::loadStoredAnomalies()
{
    m_storedAnomalies.clear();
    QDir dir(anomaliesDirectory());
    if (!dir.exists())
        dir.mkpath(QStringLiteral("."));
    QFile file(anomaliesFilePath());
    if (!file.open(QIODevice::ReadOnly))
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject())
        return;
    const QJsonArray items = doc.object().value(QStringLiteral("anomalies")).toArray();
    for (const QJsonValue &value : items) {
        StoredAnomaly stored = storedAnomalyFromJson(value.toObject());
        if (stored.id.isEmpty())
            continue;
        auto it = std::find_if(m_storedAnomalies.begin(), m_storedAnomalies.end(),
                               [&stored](const StoredAnomaly &existing) { return existing.id == stored.id; });
        if (it == m_storedAnomalies.end())
            m_storedAnomalies.append(stored);
        else
            *it = stored;
    }
    sortStoredAnomalies();
}

void ReportBuilderWindow::saveStoredAnomalies() const
{
    writeAnomaliesToFile(anomaliesFilePath());
}

void ReportBuilderWindow::importAnomaliesFromFile(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Import anomalies"), tr("Unable to open %1").arg(filePath));
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) {
        QMessageBox::warning(this, tr("Import anomalies"), tr("Invalid anomalies file."));
        return;
    }
    const QJsonArray items = doc.object().value(QStringLiteral("anomalies")).toArray();
    if (items.isEmpty()) {
        statusBar()->showMessage(tr("No anomalies were found in %1").arg(QFileInfo(filePath).fileName()), 5000);
        return;
    }

    int added = 0;
    for (const QJsonValue &value : items) {
        StoredAnomaly stored = storedAnomalyFromJson(value.toObject());
        if (stored.id.isEmpty())
            continue;
        auto it = std::find_if(m_storedAnomalies.begin(), m_storedAnomalies.end(),
                               [&stored](const StoredAnomaly &existing) { return existing.id == stored.id; });
        if (it == m_storedAnomalies.end())
            m_storedAnomalies.append(stored);
        else
            *it = stored;
        ++added;
    }

    if (!added) {
        statusBar()->showMessage(tr("No new anomalies imported."), 4000);
        return;
    }

    sortStoredAnomalies();
    saveStoredAnomalies();
    refreshAnomalyLibrary();

    const int idx = m_sectionList ? m_sectionList->currentRow() : -1;
    if (idx >= 0 && idx < m_sections.size() && m_sections[idx].kind == ReportSection::Kind::Anomalies) {
        m_sections[idx].body = anomaliesSummaryText(m_sections[idx]);
        syncEditorWithSection(idx);
    }
    updatePreview();

    statusBar()->showMessage(tr("Imported %1 anomalies from %2")
                                 .arg(added)
                                 .arg(QFileInfo(filePath).fileName()),
                             6000);
}

bool ReportBuilderWindow::writeAnomaliesToFile(const QString &filePath) const
{
    if (filePath.isEmpty())
        return false;
    QFileInfo info(filePath);
    QDir dir = info.dir();
    if (!dir.exists() && !dir.mkpath(QStringLiteral(".")))
        return false;
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    QJsonArray array;
    for (const auto &anomaly : m_storedAnomalies)
        array.append(storedAnomalyToJson(anomaly));
    QJsonObject root;
    root.insert(QStringLiteral("anomalies"), array);
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

ReportBuilderWindow::StoredAnomaly ReportBuilderWindow::storedAnomalyFromJson(const QJsonObject &obj) const
{
    StoredAnomaly stored;
    stored.id = obj.value(QStringLiteral("id")).toString();
    if (stored.id.isEmpty())
        stored.id = obj.value(QStringLiteral("uuid")).toString();
    stored.summary = obj.value(QStringLiteral("summary")).toString();
    stored.score = obj.value(QStringLiteral("score")).toDouble();
    stored.second = obj.value(QStringLiteral("second")).toInt();
    stored.capturedAt = QDateTime::fromString(obj.value(QStringLiteral("capturedAt")).toString(), Qt::ISODate);
    const QJsonArray reasons = obj.value(QStringLiteral("reasons")).toArray();
    for (const QJsonValue &reason : reasons)
        stored.reasons.append(reason.toString());
    const QJsonArray tags = obj.value(QStringLiteral("tags")).toArray();
    for (const QJsonValue &tag : tags)
        stored.tags.append(tag.toString());
    return stored;
}

QJsonObject ReportBuilderWindow::storedAnomalyToJson(const StoredAnomaly &anomaly) const
{
    QJsonObject obj;
    obj.insert(QStringLiteral("id"), anomaly.id);
    obj.insert(QStringLiteral("summary"), anomaly.summary);
    obj.insert(QStringLiteral("score"), anomaly.score);
    obj.insert(QStringLiteral("second"), anomaly.second);
    if (anomaly.capturedAt.isValid())
        obj.insert(QStringLiteral("capturedAt"), anomaly.capturedAt.toString(Qt::ISODate));
    QJsonArray reasons;
    for (const QString &reason : anomaly.reasons)
        reasons.append(reason);
    obj.insert(QStringLiteral("reasons"), reasons);
    QJsonArray tags;
    for (const QString &tag : anomaly.tags)
        tags.append(tag);
    obj.insert(QStringLiteral("tags"), tags);
    return obj;
}

ReportBuilderWindow::AggregatedStats ReportBuilderWindow::aggregateStatistics(const ReportSection &section) const
{
    AggregatedStats result;
    QStringList files = section.statSessionFiles;
    if (files.isEmpty()) {
        if (!m_statisticsSessions.isEmpty())
            files.append(m_statisticsSessions.first().filePath);
        else if (m_statistics && !m_statistics->lastFilePath().isEmpty())
            files.append(m_statistics->lastFilePath());
    }

    if (files.isEmpty()) {
        result.error = tr("No statistics sessions available.");
        return result;
    }

    result.requestedStart = std::max(0, section.statRangeStart);
    result.requestedEnd = section.statRangeEnd;

    QMap<int, double> packetsBySecond;
    QMap<int, double> bytesBySecond;
    int minSecond = std::numeric_limits<int>::max();
    int maxSecond = -1;
    bool hadSamples = false;

    for (const QString &filePath : files) {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            result.error = tr("Unable to read statistics file %1").arg(filePath);
            continue;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject()) {
            result.error = tr("Statistics file was malformed (%1).").arg(filePath);
            continue;
        }

        const QJsonArray perSecond = doc.object().value(QStringLiteral("perSecond")).toArray();
        if (perSecond.isEmpty()) {
            result.error = tr("Statistics file %1 contained no samples.").arg(filePath);
            continue;
        }

        hadSamples = true;
        result.sessionsUsed.append(filePath);

        for (const QJsonValue &value : perSecond) {
            const QJsonObject secondObj = value.toObject();
            const int second = secondObj.value(QStringLiteral("second")).toInt();
            if (second < result.requestedStart)
                continue;
            if (result.requestedEnd >= 0 && second > result.requestedEnd)
                continue;

            const double pps = secondObj.value(QStringLiteral("pps")).toDouble();
            const double bps = secondObj.value(QStringLiteral("bps")).toDouble();
            packetsBySecond[second] += pps;
            bytesBySecond[second] += bps;
            result.totalPackets += pps;
            result.totalBytes += bps;

            minSecond = std::min(minSecond, second);
            maxSecond = std::max(maxSecond, second);

            const QJsonObject protoCounts = secondObj.value(QStringLiteral("protocolCounts")).toObject();
            for (auto it = protoCounts.constBegin(); it != protoCounts.constEnd(); ++it)
                result.protocolTotals[it.key()] += it.value().toDouble();

            const QJsonArray connections = secondObj.value(QStringLiteral("connections")).toArray();
            for (const QJsonValue &connValue : connections) {
                const QJsonObject connObj = connValue.toObject();
                const QString src = connObj.value(QStringLiteral("src")).toString();
                const QString dst = connObj.value(QStringLiteral("dst")).toString();
                if (!src.isEmpty() && !dst.isEmpty())
                    result.connectionCounts[src + QStringLiteral(" -> ") + dst] += 1.0;
                if (!src.isEmpty())
                    result.sourceCounts[src] += 1.0;
                if (!dst.isEmpty())
                    result.destinationCounts[dst] += 1.0;
            }
        }
    }

    if (!hadSamples) {
        if (result.error.isEmpty())
            result.error = tr("Selected statistics sessions contained no usable samples.");
        return result;
    }

    result.sessionsUsed.removeDuplicates();

    if (!packetsBySecond.isEmpty() || !bytesBySecond.isEmpty()) {
        if (minSecond == std::numeric_limits<int>::max())
            minSecond = result.requestedStart;
        if (maxSecond < 0)
            maxSecond = result.requestedEnd >= 0 ? result.requestedEnd : minSecond;
        result.rangeStart = minSecond;
        result.rangeEnd = result.requestedEnd >= 0 ? std::min(maxSecond, result.requestedEnd) : maxSecond;
    } else {
        result.rangeStart = result.requestedStart;
        result.rangeEnd = result.requestedEnd;
    }

    for (auto it = packetsBySecond.cbegin(); it != packetsBySecond.cend(); ++it)
        result.packetsPerSecond.append({it.key(), it.value()});
    for (auto it = bytesBySecond.cbegin(); it != bytesBySecond.cend(); ++it)
        result.bytesPerSecond.append({it.key(), it.value()});

    result.hasSamples = !result.packetsPerSecond.isEmpty() || !result.bytesPerSecond.isEmpty() || !result.protocolTotals.isEmpty();
    return result;
}

QStringList ReportBuilderWindow::statisticsChartOptions() const
{
    return {QStringLiteral("protocols"), QStringLiteral("packets"), QStringLiteral("bytes")};
}

QString ReportBuilderWindow::chartLabelForKey(const QString &key) const
{
    if (key == QStringLiteral("protocols"))
        return tr("Protocol distribution");
    if (key == QStringLiteral("packets"))
        return tr("Packets per second");
    if (key == QStringLiteral("bytes"))
        return tr("Bytes per second");
    return key;
}

QString ReportBuilderWindow::renderStatisticsChartsHtml(const ReportSection &section, const AggregatedStats &data) const
{
    if (section.statChartKinds.isEmpty())
        return QString();
    QString html;
    for (const QString &key : section.statChartKinds) {
        const QString chartHtml = renderSingleChart(key, data);
        if (!chartHtml.isEmpty())
            html += chartHtml;
    }
    return html;
}

QString ReportBuilderWindow::renderSingleChart(const QString &key, const AggregatedStats &data) const
{
    const QString label = chartLabelForKey(key);
    const int chartWidth = 640;
    const int chartHeight = 320;
    QImage image(chartWidth, chartHeight, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::white);
    QPainter painter(&image);
    painter.setRenderHint(QPainter::Antialiasing);
    const QLocale locale;

    const int leftMargin = 72;
    const int rightMargin = 96;
    const int topMargin = 60;
    const int bottomMargin = 72;
    const QRect plotRect(leftMargin,
                         topMargin,
                         image.width() - leftMargin - rightMargin,
                         image.height() - topMargin - bottomMargin);

    auto finalize = [&](bool hasContent) -> QString {
        if (!hasContent)
            return QString();
        painter.setPen(Qt::black);
        painter.drawText(QRect(0, 0, image.width(), topMargin - 20), Qt::AlignCenter, label);
        QBuffer buffer;
        buffer.open(QIODevice::WriteOnly);
        image.save(&buffer, "PNG");
        const QString encoded = QString::fromLatin1(buffer.data().toBase64());
        return QStringLiteral("<div class=\"chart\"><img src=\"data:image/png;base64,%1\" alt=\"%2\"></div>")
            .arg(encoded, label.toHtmlEscaped());
    };

    if (key == QStringLiteral("protocols")) {
        if (data.protocolTotals.isEmpty())
            return QString();
        QList<QPair<QString, double>> items;
        for (auto it = data.protocolTotals.cbegin(); it != data.protocolTotals.cend(); ++it)
            items.append({it.key(), it.value()});
        std::sort(items.begin(), items.end(), [](const auto &a, const auto &b) {
            return a.second > b.second;
        });
        const int maxBars = std::min(8, static_cast<int>(items.size()));
        double maxValue = 0.0;
        for (int i = 0; i < maxBars; ++i)
            maxValue = std::max(maxValue, items.at(i).second);
        if (maxValue <= 0.0)
            return QString();

        painter.setPen(Qt::black);
        painter.drawRect(plotRect);
        const qreal nameWidth = leftMargin - 24;
        const qreal valueWidth = rightMargin - 24;
        const double barHeight = static_cast<double>(plotRect.height()) / (maxBars * 1.5);
        for (int i = 0; i < maxBars; ++i) {
            const double fraction = items.at(i).second / maxValue;
            const double width = fraction * plotRect.width();
            const double top = plotRect.top() + i * 1.5 * barHeight;
            QRectF bar(plotRect.left(), top, width, barHeight);
            painter.fillRect(bar, QColor(32, 96, 160));
            painter.setPen(Qt::black);
            painter.drawRect(bar);
            const QString valueText = locale.toString(items.at(i).second, 'f', 0);
            painter.drawText(QRectF(plotRect.left() - nameWidth - 4, top, nameWidth, barHeight),
                             Qt::AlignVCenter | Qt::AlignRight,
                             items.at(i).first);
            painter.drawText(QRectF(plotRect.right() + 8, top, valueWidth, barHeight),
                             Qt::AlignVCenter | Qt::AlignLeft,
                             valueText);
        }
        return finalize(true);
    }

    auto drawSeries = [&](const QVector<QPair<int, double>> &series, const QString &yLabel) -> bool {
        if (series.isEmpty())
            return false;
        double maxValue = 0.0;
        int minX = series.first().first;
        int maxX = series.last().first;
        for (const auto &point : series) {
            maxValue = std::max(maxValue, point.second);
            minX = std::min(minX, point.first);
            maxX = std::max(maxX, point.first);
        }
        if (maxValue <= 0.0 || maxX == minX)
            return false;

        painter.setPen(Qt::black);
        painter.drawRect(plotRect);
        painter.drawText(QRect(plotRect.left(), plotRect.bottom() + 16, plotRect.width(), 20),
                         Qt::AlignCenter,
                         tr("Time (s)"));
        painter.save();
        painter.translate(leftMargin - 45, plotRect.center().y());
        painter.rotate(-90);
        painter.drawText(QRect(-plotRect.height() / 2, -20, plotRect.height(), 20),
                         Qt::AlignCenter,
                         yLabel);
        painter.restore();

        const int gridLines = 4;
        for (int i = 0; i <= gridLines; ++i) {
            const double ratio = static_cast<double>(i) / gridLines;
            const qreal y = plotRect.bottom() - ratio * plotRect.height();
            painter.setPen(QColor(220, 220, 220));
            painter.drawLine(plotRect.left(), y, plotRect.right(), y);
            painter.setPen(Qt::black);
            painter.drawText(QRectF(plotRect.left() - 70, y - 10, 60, 20),
                             Qt::AlignRight | Qt::AlignVCenter,
                             locale.toString(ratio * maxValue, 'f', 0));
        }

        painter.save();
        painter.setClipRect(plotRect);
        QPainterPath path;
        for (int i = 0; i < series.size(); ++i) {
            const double ratioX = static_cast<double>(series.at(i).first - minX) / (maxX - minX);
            const double ratioY = series.at(i).second / maxValue;
            const QPointF point(plotRect.left() + ratioX * plotRect.width(),
                                plotRect.bottom() - ratioY * plotRect.height());
            if (i == 0)
                path.moveTo(point);
            else
                path.lineTo(point);
        }

        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.setPen(QPen(QColor(32, 96, 160), 2));
        painter.drawPath(path);
        painter.restore();
        return true;
    };

    if (key == QStringLiteral("packets")) {
        if (!drawSeries(data.packetsPerSecond, tr("Packets")))
            return QString();
        return finalize(true);
    }

    if (key == QStringLiteral("bytes")) {
        if (!drawSeries(data.bytesPerSecond, tr("Bytes")))
            return QString();
        return finalize(true);
    }

    return QString();
}

void ReportBuilderWindow::connectEditorSignals(const EditorWidgets &editor, ReportSection::Kind kind)
{
    if (editor.titleEdit) {
        connect(editor.titleEdit, &QLineEdit::textChanged, this, [this, kind](const QString &text) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].title = text;
            refreshSectionList();
            updatePreview();
        });
    }
    if (editor.levelSpin) {
        connect(editor.levelSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, kind](int value) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].headingLevel = value;
            updatePreview();
        });
    }
    if (editor.bodyEdit) {
        connect(editor.bodyEdit, &QTextEdit::textChanged, this, [this, kind, editor]() {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].body = editor.bodyEdit->toPlainText();
            updatePreview();
        });
    }
    if (editor.pageSpin) {
        connect(editor.pageSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, kind](int value) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].pageNumber = value;
            refreshSectionList();
            updatePreview();
        });
    }
    if (editor.annotationCombo) {
        connect(editor.annotationCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this, kind, combo = editor.annotationCombo](int index) {
            if (index < 0)
                return;
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].annotationFile = combo->itemData(index).toString();
            updatePreview();
        });
    }
    if (editor.packetTableCheck) {
        connect(editor.packetTableCheck, &QCheckBox::toggled, this, [this, kind](bool checked) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].includePacketTable = checked;
            updatePreview();
        });
    }
    if (editor.tagCheck) {
        connect(editor.tagCheck, &QCheckBox::toggled, this, [this, kind](bool checked) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].includeTags = checked;
            updatePreview();
        });
    }
    if (editor.colorCheck) {
        connect(editor.colorCheck, &QCheckBox::toggled, this, [this, kind](bool checked) {
            const int idx = m_sectionList->currentRow();
            if (idx < 0 || idx >= m_sections.size())
                return;
            if (m_sections[idx].kind != kind)
                return;
            m_sections[idx].includeColors = checked;
            updatePreview();
        });
    }
    if (editor.regenerateButton) {
        connect(editor.regenerateButton, &QPushButton::clicked,
                this, &ReportBuilderWindow::regenerateCurrentSection);
    }
}

void ReportBuilderWindow::addHeadingSection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::Heading;
    section.title = tr("New heading");
    section.headingLevel = 1;
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::addTextSection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::Text;
    section.title = tr("Narrative");
    section.body = tr("Write your findings here.");
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::addAnnotationSection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::Annotation;
    if (!m_annotations.isEmpty())
        section.annotationFile = cleanFileTitle(m_annotations.constFirst().filePath);
    section.title = tr("Packet evidence");
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::addStatisticsSection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::Statistics;
    section.title = tr("Traffic statistics");
    if (!m_statisticsSessions.isEmpty())
        section.statSessionFiles.append(m_statisticsSessions.first().filePath);
    else if (m_statistics && !m_statistics->lastFilePath().isEmpty())
        section.statSessionFiles.append(m_statistics->lastFilePath());
    section.statRangeStart = 0;
    section.statRangeEnd = -1;
    const QStringList chartOptions = statisticsChartOptions();
    if (!chartOptions.isEmpty())
        section.statChartKinds.append(chartOptions.first());
    section.body = statisticsSummaryText(section);
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::addAnomalySection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::Anomalies;
    section.title = tr("Detected anomalies");
    if (m_statistics) {
        for (const auto &event : m_statistics->anomalies())
            section.storedAnomalyIds.append(anomalyEventId(event));
    }
    section.storedAnomalyIds.removeDuplicates();
    section.body = anomaliesSummaryText(section);
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::addGeoSection()
{
    ReportSection section;
    section.kind = ReportSection::Kind::GeoOverview;
    section.title = tr("Geographic overview");
    section.body = geoOverviewSummaryText();
    m_sections.append(section);
    refreshSectionList();
    selectSection(m_sections.size() - 1);
}

void ReportBuilderWindow::removeSelectedSection()
{
    const int idx = m_sectionList->currentRow();
    if (idx < 0 || idx >= m_sections.size())
        return;
    m_sections.removeAt(idx);
    refreshSectionList();
    if (!m_sections.isEmpty()) {
        const int lastIndex = static_cast<int>(m_sections.size()) - 1;
        selectSection(std::clamp(idx, 0, lastIndex));
    }
}

void ReportBuilderWindow::moveSectionUp()
{
    const int idx = m_sectionList->currentRow();
    if (idx <= 0 || idx >= m_sections.size())
        return;
    m_sections.swapItemsAt(idx, idx - 1);
    refreshSectionList();
    selectSection(idx - 1);
}

void ReportBuilderWindow::moveSectionDown()
{
    const int idx = m_sectionList->currentRow();
    if (idx < 0 || idx >= m_sections.size() - 1)
        return;
    m_sections.swapItemsAt(idx, idx + 1);
    refreshSectionList();
    selectSection(idx + 1);
}

void ReportBuilderWindow::handleSectionSelectionChanged()
{
    const int idx = m_sectionList->currentRow();
    syncEditorWithSection(idx);
}

void ReportBuilderWindow::refreshSectionList()
{
    const int currentRow = m_sectionList ? m_sectionList->currentRow() : -1;
    const QSignalBlocker blocker(m_sectionList);
    m_sectionList->clear();
    for (int i = 0; i < m_sections.size(); ++i) {
        const ReportSection &section = m_sections.at(i);
        QString title = section.title;
        if (title.isEmpty())
            title = sectionKindLabel(section.kind);
        QString label = QString::number(i + 1) + QStringLiteral(". ") + title;
        if (section.pageNumber > 0)
            label += QStringLiteral(" [p%1]").arg(section.pageNumber);
        auto *item = new QListWidgetItem(label);
        item->setData(Qt::UserRole, i);
        m_sectionList->addItem(item);
    }
    if (currentRow >= 0 && currentRow < m_sectionList->count())
        m_sectionList->setCurrentRow(currentRow);
    else if (m_sectionList->count() > 0)
        m_sectionList->setCurrentRow(0);
    updatePreview();
}

void ReportBuilderWindow::selectSection(int index)
{
    if (!m_sectionList)
        return;
    if (index < 0 || index >= m_sectionList->count())
        return;
    m_sectionList->setCurrentRow(index);
}

void ReportBuilderWindow::syncEditorWithSection(int index)
{
    if (index < 0 || index >= m_sections.size()) {
        m_editorStack->setCurrentWidget(m_emptyPage);
        return;
    }

    const ReportSection &section = m_sections.at(index);
    auto syncPageSpin = [&](const EditorWidgets &editor) {
        if (!editor.pageSpin)
            return;
        const QSignalBlocker blocker(editor.pageSpin);
        editor.pageSpin->setValue(section.pageNumber);
    };
    switch (section.kind) {
    case ReportSection::Kind::Heading: {
        m_editorStack->setCurrentWidget(m_headingEditor.page);
        QSignalBlocker titleBlocker(m_headingEditor.titleEdit);
        QSignalBlocker levelBlocker(m_headingEditor.levelSpin);
        m_headingEditor.titleEdit->setText(section.title);
        m_headingEditor.levelSpin->setValue(section.headingLevel);
        syncPageSpin(m_headingEditor);
        break;
    }
    case ReportSection::Kind::Text: {
        m_editorStack->setCurrentWidget(m_textEditor.page);
        QSignalBlocker titleBlocker(m_textEditor.titleEdit);
        QSignalBlocker bodyBlocker(m_textEditor.bodyEdit);
        m_textEditor.titleEdit->setText(section.title);
        m_textEditor.bodyEdit->setPlainText(section.body);
        syncPageSpin(m_textEditor);
        break;
    }
    case ReportSection::Kind::Annotation: {
        m_editorStack->setCurrentWidget(m_annotationEditor.page);
        refreshAnnotationCombo(m_annotationEditor.annotationCombo);
        QSignalBlocker titleBlocker(m_annotationEditor.titleEdit);
        QSignalBlocker comboBlocker(m_annotationEditor.annotationCombo);
        QSignalBlocker tableBlocker(m_annotationEditor.packetTableCheck);
        QSignalBlocker tagBlocker(m_annotationEditor.tagCheck);
        QSignalBlocker colorBlocker(m_annotationEditor.colorCheck);
        m_annotationEditor.titleEdit->setText(section.title);
        int comboIndex = -1;
        for (int i = 0; i < m_annotationEditor.annotationCombo->count(); ++i) {
            if (m_annotationEditor.annotationCombo->itemData(i).toString() == section.annotationFile) {
                comboIndex = i;
                break;
            }
        }
        if (comboIndex >= 0)
            m_annotationEditor.annotationCombo->setCurrentIndex(comboIndex);
        m_annotationEditor.packetTableCheck->setChecked(section.includePacketTable);
        m_annotationEditor.tagCheck->setChecked(section.includeTags);
        m_annotationEditor.colorCheck->setChecked(section.includeColors);
        syncPageSpin(m_annotationEditor);
        break;
    }
    case ReportSection::Kind::Statistics: {
        m_editorStack->setCurrentWidget(m_statisticsEditor.page);
        QSignalBlocker titleBlocker(m_statisticsEditor.titleEdit);
        QSignalBlocker bodyBlocker(m_statisticsEditor.bodyEdit);
        m_statisticsEditor.titleEdit->setText(section.title);
        m_statisticsEditor.bodyEdit->setPlainText(section.body);
        m_statisticsEditor.metaLabel->setText(tr("Auto-generated from selected statistics sessions."));
        syncPageSpin(m_statisticsEditor);
        refreshStatisticsSessionList();
        refreshStatisticsChartsSelection();
        if (m_statisticsEditor.statsSessionList) {
            const QSignalBlocker listBlocker(m_statisticsEditor.statsSessionList);
            for (int i = 0; i < m_statisticsEditor.statsSessionList->count(); ++i) {
                QListWidgetItem *item = m_statisticsEditor.statsSessionList->item(i);
                const QString filePath = item->data(Qt::UserRole).toString();
                item->setCheckState(section.statSessionFiles.contains(filePath) ? Qt::Checked : Qt::Unchecked);
            }
        }
        if (m_statisticsEditor.statsChartList) {
            const QSignalBlocker chartBlocker(m_statisticsEditor.statsChartList);
            for (int i = 0; i < m_statisticsEditor.statsChartList->count(); ++i) {
                QListWidgetItem *item = m_statisticsEditor.statsChartList->item(i);
                const QString key = item->data(Qt::UserRole).toString();
                item->setCheckState(section.statChartKinds.contains(key) ? Qt::Checked : Qt::Unchecked);
            }
        }
        if (m_statisticsEditor.statsRangeStart && m_statisticsEditor.statsRangeEnd) {
            const QSignalBlocker startBlocker(m_statisticsEditor.statsRangeStart);
            const QSignalBlocker endBlocker(m_statisticsEditor.statsRangeEnd);
            m_statisticsEditor.statsRangeStart->setValue(section.statRangeStart);
            m_statisticsEditor.statsRangeEnd->setValue(section.statRangeEnd);
        }
        updateStatisticsRangeLimits();
        break;
    }
    case ReportSection::Kind::Anomalies: {
        m_editorStack->setCurrentWidget(m_anomaliesEditor.page);
        QSignalBlocker titleBlocker(m_anomaliesEditor.titleEdit);
        QSignalBlocker bodyBlocker(m_anomaliesEditor.bodyEdit);
        m_anomaliesEditor.titleEdit->setText(section.title);
        m_anomaliesEditor.bodyEdit->setPlainText(section.body);
        m_anomaliesEditor.metaLabel->setText(tr("Summaries of anomaly detector events."));
        syncPageSpin(m_anomaliesEditor);
        refreshAnomalyLibrary();
        if (m_anomaliesEditor.anomalyLibrary) {
            const QSignalBlocker libraryBlocker(m_anomaliesEditor.anomalyLibrary);
            for (int i = 0; i < m_anomaliesEditor.anomalyLibrary->count(); ++i) {
                QListWidgetItem *item = m_anomaliesEditor.anomalyLibrary->item(i);
                const QString id = item->data(Qt::UserRole).toString();
                item->setCheckState(section.storedAnomalyIds.contains(id) ? Qt::Checked : Qt::Unchecked);
            }
        }
        break;
    }
    case ReportSection::Kind::GeoOverview: {
        m_editorStack->setCurrentWidget(m_geoEditor.page);
        QSignalBlocker titleBlocker(m_geoEditor.titleEdit);
        QSignalBlocker bodyBlocker(m_geoEditor.bodyEdit);
        m_geoEditor.titleEdit->setText(section.title);
        m_geoEditor.bodyEdit->setPlainText(section.body);
        m_geoEditor.metaLabel->setText(tr("Highlights top geo flows from collected statistics."));
        syncPageSpin(m_geoEditor);
        break;
    }
    }
}

void ReportBuilderWindow::saveReportToFile()
{
    ensureReportingDirectory();
    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          tr("Save report"),
                                                          reportingDirectory(),
                                                          tr("Report (*.json)"));
    if (filePath.isEmpty())
        return;

    QString finalPath = filePath;
    if (!finalPath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
        finalPath.append(QStringLiteral(".json"));

    QJsonArray sectionArray;
    for (const ReportSection &section : std::as_const(m_sections))
        sectionArray.append(sectionToJson(section));

    QJsonObject root;
    root.insert(QStringLiteral("createdAt"), QDateTime::currentDateTime().toString(Qt::ISODate));
    root.insert(QStringLiteral("header"), headerToJson());
    root.insert(QStringLiteral("sections"), sectionArray);

    QFile file(finalPath);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Save report"), tr("Unable to save report to %1").arg(finalPath));
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    statusBar()->showMessage(tr("Report saved to %1").arg(finalPath), 5000);
}

void ReportBuilderWindow::loadReportFromFile()
{
    const QString filePath = QFileDialog::getOpenFileName(this,
                                                          tr("Load report"),
                                                          reportingDirectory(),
                                                          tr("Report (*.json)"));
    if (filePath.isEmpty())
        return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Load report"), tr("Unable to open %1").arg(filePath));
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) {
        QMessageBox::warning(this, tr("Load report"), tr("Invalid report file."));
        return;
    }
    resetHeaderToDefaults();
    loadHeaderFromJson(doc.object().value(QStringLiteral("header")).toObject());
    syncHeaderEditors();

    const QJsonArray array = doc.object().value(QStringLiteral("sections")).toArray();
    QVector<ReportSection> sections;
    sections.reserve(array.size());
    for (const QJsonValue &value : array) {
        sections.append(sectionFromJson(value.toObject()));
    }
    m_sections = sections;
    regenerateAutoSections();
    refreshSectionList();
    statusBar()->showMessage(tr("Loaded report %1").arg(filePath), 5000);
}

void ReportBuilderWindow::saveTemplate()
{
    ensureReportingDirectory();
    QDir dir(templatesDirectory());
    dir.mkpath(QStringLiteral("."));

    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          tr("Save template"),
                                                          templatesDirectory(),
                                                          tr("Template (*.json)"));
    if (filePath.isEmpty())
        return;

    QJsonArray sectionArray;
    for (const ReportSection &section : std::as_const(m_sections))
        sectionArray.append(sectionToJson(section));

    QJsonObject root;
    root.insert(QStringLiteral("type"), QStringLiteral("template"));
    root.insert(QStringLiteral("header"), headerToJson());
    root.insert(QStringLiteral("sections"), sectionArray);

    QString finalPath = filePath;
    if (!finalPath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
        finalPath.append(QStringLiteral(".json"));

    QFile file(finalPath);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Template"), tr("Unable to save template to %1").arg(finalPath));
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    statusBar()->showMessage(tr("Saved template to %1").arg(finalPath), 5000);
}

void ReportBuilderWindow::loadTemplate()
{
    ensureReportingDirectory();
    const QString filePath = QFileDialog::getOpenFileName(this,
                                                          tr("Load template"),
                                                          templatesDirectory(),
                                                          tr("Template (*.json)"));
    if (filePath.isEmpty())
        return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Template"), tr("Unable to open %1").arg(filePath));
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) {
        QMessageBox::warning(this, tr("Template"), tr("Invalid template file."));
        return;
    }
    resetHeaderToDefaults();
    loadHeaderFromJson(doc.object().value(QStringLiteral("header")).toObject());
    syncHeaderEditors();

    const QJsonArray sectionsArray = doc.object().value(QStringLiteral("sections")).toArray();
    QVector<ReportSection> sections;
    sections.reserve(sectionsArray.size());
    for (const QJsonValue &value : sectionsArray)
        sections.append(sectionFromJson(value.toObject()));
    m_sections = sections;
    regenerateAutoSections();
    refreshSectionList();
    statusBar()->showMessage(tr("Applied template %1").arg(filePath), 5000);
}

void ReportBuilderWindow::exportToPdf()
{
    ensureReportingDirectory();
    QString filePath = QFileDialog::getSaveFileName(this,
                                                    tr("Export to PDF"),
                                                    reportingDirectory(),
                                                    tr("PDF (*.pdf)"));
    if (filePath.isEmpty())
        return;

    if (!filePath.endsWith(QStringLiteral(".pdf"), Qt::CaseInsensitive))
        filePath.append(QStringLiteral(".pdf"));

    QTextDocument document;
    document.setHtml(renderFullDocument());

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(filePath);
    printer.setPageMargins(QMarginsF(15, 20, 15, 20));
    document.print(&printer);
    statusBar()->showMessage(tr("Exported PDF to %1").arg(filePath), 6000);
}

void ReportBuilderWindow::saveDraft()
{
    ensureReportingDirectory();
    QDir().mkpath(draftsDirectory());
    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          tr("Save draft"),
                                                          draftsDirectory(),
                                                          tr("Draft (*.json)"));
    if (filePath.isEmpty())
        return;

    QString finalPath = filePath;
    if (!finalPath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
        finalPath.append(QStringLiteral(".json"));

    QJsonArray sectionArray;
    for (const ReportSection &section : std::as_const(m_sections))
        sectionArray.append(sectionToJson(section));

    QJsonObject root;
    root.insert(QStringLiteral("type"), QStringLiteral("draft"));
    root.insert(QStringLiteral("header"), headerToJson());
    root.insert(QStringLiteral("sections"), sectionArray);

    QFile file(finalPath);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Draft"), tr("Unable to save draft to %1").arg(finalPath));
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    statusBar()->showMessage(tr("Draft saved to %1").arg(finalPath), 5000);
}

void ReportBuilderWindow::loadDraft()
{
    ensureReportingDirectory();
    const QString filePath = QFileDialog::getOpenFileName(this,
                                                          tr("Load draft"),
                                                          draftsDirectory(),
                                                          tr("Draft (*.json)"));
    if (filePath.isEmpty())
        return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Draft"), tr("Unable to open %1").arg(filePath));
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) {
        QMessageBox::warning(this, tr("Draft"), tr("Invalid draft file."));
        return;
    }
    resetHeaderToDefaults();
    loadHeaderFromJson(doc.object().value(QStringLiteral("header")).toObject());
    syncHeaderEditors();

    const QJsonArray sectionsArray = doc.object().value(QStringLiteral("sections")).toArray();
    QVector<ReportSection> sections;
    sections.reserve(sectionsArray.size());
    for (const QJsonValue &value : sectionsArray)
        sections.append(sectionFromJson(value.toObject()));
    m_sections = sections;
    regenerateAutoSections();
    refreshSectionList();
    statusBar()->showMessage(tr("Loaded draft %1").arg(filePath), 5000);
}

void ReportBuilderWindow::regenerateCurrentSection()
{
    const int idx = m_sectionList->currentRow();
    if (idx < 0 || idx >= m_sections.size())
        return;
    ReportSection &section = m_sections[idx];
    switch (section.kind) {
    case ReportSection::Kind::Statistics:
        section.body = statisticsSummaryText(section);
        break;
    case ReportSection::Kind::Anomalies:
        section.body = anomaliesSummaryText(section);
        break;
    case ReportSection::Kind::GeoOverview:
        section.body = geoOverviewSummaryText();
        break;
    default:
        return;
    }
    syncEditorWithSection(idx);
    updatePreview();
}

QString ReportBuilderWindow::statisticsSummaryText(const ReportSection &section) const
{
    const AggregatedStats data = aggregateStatistics(section);
    if (!data.hasSamples) {
        if (!data.error.isEmpty())
            return data.error;
        return tr("No statistics available for the selected range.");
    }

    QStringList lines;
    const QLocale locale;

    if (!data.sessionsUsed.isEmpty()) {
        QStringList names;
        for (const QString &path : data.sessionsUsed)
            names.append(cleanFileTitle(path));
        lines << tr("Sessions combined: %1").arg(names.join(QStringLiteral(", ")));
    }

    if (data.requestedEnd >= 0)
        lines << tr("Requested window: seconds %1-%2.").arg(data.requestedStart).arg(data.requestedEnd);
    else
        lines << tr("Requested window: from second %1 to capture end.").arg(data.requestedStart);

    if (data.rangeEnd >= data.rangeStart)
        lines << tr("Samples present from second %1 through %2.").arg(data.rangeStart).arg(data.rangeEnd);
    else
        lines << tr("No samples recorded in the requested interval.");

    lines << tr("Total packets: %1").arg(locale.toString(data.totalPackets, 'f', 0));
    lines << tr("Total bytes: %1").arg(locale.formattedDataSize(static_cast<quint64>(std::round(data.totalBytes))));

    if (data.rangeEnd >= data.rangeStart) {
        const double seconds = static_cast<double>(std::max(1, data.rangeEnd - data.rangeStart + 1));
        lines << tr("Average packets/s: %1")
                    .arg(locale.toString(data.totalPackets / seconds, 'f', 2));
        const double bytesPerSecValue = std::max(0.0, data.totalBytes / seconds);
        const QString bytesPerSecond = locale.formattedDataSize(static_cast<quint64>(std::round(bytesPerSecValue)))
            + QStringLiteral("/s");
        lines << tr("Average bytes/s: %1").arg(bytesPerSecond);
    }

    QList<QPair<QString, double>> protocols;
    for (auto it = data.protocolTotals.cbegin(); it != data.protocolTotals.cend(); ++it)
        protocols.append({it.key(), it.value()});
    std::sort(protocols.begin(), protocols.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });

    if (!protocols.isEmpty()) {
        lines << tr("Top protocols:");
        const int limit = std::min(5, static_cast<int>(protocols.size()));
        for (int i = 0; i < limit; ++i) {
            const double count = protocols.at(i).second;
            const double share = data.totalPackets > 0.0 ? (count / data.totalPackets) * 100.0 : 0.0;
            lines << tr("  • %1 — %2 packets (%3%)")
                       .arg(protocols.at(i).first,
                            locale.toString(count, 'f', 0))
                       .arg(locale.toString(share, 'f', 1));
        }
    } else {
        lines << tr("No protocol breakdown available.");
    }

    QList<QPair<QString, double>> connections;
    for (auto it = data.connectionCounts.cbegin(); it != data.connectionCounts.cend(); ++it)
        connections.append({it.key(), it.value()});
    std::sort(connections.begin(), connections.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });
    if (!connections.isEmpty()) {
        lines << tr("Top connection corridors:");
        const int limit = std::min(5, static_cast<int>(connections.size()));
        for (int i = 0; i < limit; ++i) {
            lines << tr("  • %1 — %2 samples")
                       .arg(connections.at(i).first,
                            locale.toString(connections.at(i).second, 'f', 0));
        }
    }

    QList<QPair<QString, double>> sources;
    for (auto it = data.sourceCounts.cbegin(); it != data.sourceCounts.cend(); ++it)
        sources.append({it.key(), it.value()});
    std::sort(sources.begin(), sources.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });
    if (!sources.isEmpty()) {
        lines << tr("Top sources:");
        const int limit = std::min(5, static_cast<int>(sources.size()));
        for (int i = 0; i < limit; ++i)
            lines << tr("  • %1 — %2 connections")
                       .arg(sources.at(i).first,
                            locale.toString(sources.at(i).second, 'f', 0));
    }

    QList<QPair<QString, double>> destinations;
    for (auto it = data.destinationCounts.cbegin(); it != data.destinationCounts.cend(); ++it)
        destinations.append({it.key(), it.value()});
    std::sort(destinations.begin(), destinations.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });
    if (!destinations.isEmpty()) {
        lines << tr("Top destinations:");
        const int limit = std::min(5, static_cast<int>(destinations.size()));
        for (int i = 0; i < limit; ++i)
            lines << tr("  • %1 — %2 connections")
                       .arg(destinations.at(i).first,
                            locale.toString(destinations.at(i).second, 'f', 0));
    }

    if (!data.error.isEmpty())
        lines << tr("Warning: %1").arg(data.error);

    return lines.join('\n');
}

QString ReportBuilderWindow::anomaliesSummaryText(const ReportSection &section) const
{
    const QLocale locale;
    QStringList lines;

    if (!section.storedAnomalyIds.isEmpty()) {
        lines << tr("Selected anomaly library entries:");
        for (const QString &id : section.storedAnomalyIds) {
            auto it = std::find_if(m_storedAnomalies.cbegin(), m_storedAnomalies.cend(),
                                   [&id](const StoredAnomaly &entry) { return entry.id == id; });
            if (it == m_storedAnomalies.cend()) {
                lines << tr("• Missing anomaly entry %1").arg(id);
                continue;
            }
            lines << tr("• [t=%1 s] Score %2 — %3")
                       .arg(it->second)
                       .arg(locale.toString(it->score, 'f', 2))
                       .arg(it->summary);
            if (it->capturedAt.isValid())
                lines << tr("    Logged: %1")
                            .arg(locale.toString(it->capturedAt.toLocalTime(), QLocale::ShortFormat));
            if (!it->tags.isEmpty())
                lines << tr("    Tags: %1").arg(it->tags.join(QStringLiteral(", ")));
            if (!it->reasons.isEmpty())
                lines << QStringLiteral("    %1").arg(it->reasons.join(QStringLiteral("; ")));
        }
        return lines.join('\n');
    }

    if (!m_statistics)
        return tr("Anomaly detector is not running for this session.");

    const auto events = m_statistics->anomalies();
    if (events.isEmpty())
        return tr("No anomalies detected during the captured interval.");

    lines << tr("Live anomalies detected during this session:");
    for (const auto &event : events) {
        lines << tr("• [t=%1 s] Score %2 — %3")
                   .arg(event.second)
                   .arg(locale.toString(event.score, 'f', 2))
                   .arg(event.summary);
        if (!event.tags.isEmpty())
            lines << tr("    Tags: %1").arg(event.tags.join(QStringLiteral(", ")));
        if (!event.reasons.isEmpty())
            lines << QStringLiteral("    %1").arg(event.reasons.join(QStringLiteral("; ")));
    }
    lines << tr("Use the library selector to pin these findings for future reports.");
    return lines.join('\n');
}

QString ReportBuilderWindow::geoOverviewSummaryText() const
{
    QString statsFile = m_statistics ? m_statistics->lastFilePath() : QString();
    if (statsFile.isEmpty()) {
        QDir dir(Statistics::defaultSessionsDir());
        const QStringList files = dir.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Time);
        if (!files.isEmpty())
            statsFile = dir.filePath(files.constFirst());
    }
    if (statsFile.isEmpty())
        return tr("No statistics sessions available for geo overview.");

    QFile file(statsFile);
    if (!file.open(QIODevice::ReadOnly))
        return tr("Unable to read statistics file %1").arg(statsFile);
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject())
        return tr("Statistics file was malformed.");

    const QJsonArray perSecond = doc.object().value(QStringLiteral("perSecond")).toArray();
    if (perSecond.isEmpty())
        return tr("Statistics file contains no samples.");

    struct FlowKey {
        QString src;
        QString dst;
    };
    struct FlowStats {
        double occurrences = 0.0;
        double packets = 0.0;
        double bytes = 0.0;
    };
    QMap<QString, FlowStats> flowMap;
    auto flowKey = [](const QString &a, const QString &b) {
        return a + QStringLiteral(" -> ") + b;
    };

    for (const QJsonValue &value : perSecond) {
        const QJsonObject secondObj = value.toObject();
        const double packets = secondObj.value(QStringLiteral("pps")).toDouble();
        const double bytes = secondObj.value(QStringLiteral("bps")).toDouble();
        const QJsonArray connections = secondObj.value(QStringLiteral("connections")).toArray();
        for (const QJsonValue &connValue : connections) {
            const QJsonObject connObj = connValue.toObject();
            const QString src = connObj.value(QStringLiteral("src")).toString();
            const QString dst = connObj.value(QStringLiteral("dst")).toString();
            const QString key = flowKey(src, dst);
            FlowStats stats = flowMap.value(key);
            stats.occurrences += 1.0;
            const auto connectionCount = std::max<qsizetype>(qsizetype(1), connections.size());
            stats.packets += packets / connectionCount;
            stats.bytes += bytes / connectionCount;
            flowMap.insert(key, stats);
        }
    }

    if (flowMap.isEmpty())
        return tr("No connection flows captured for geo overview.");

    QList<QPair<QString, FlowStats>> flows;
    for (auto it = flowMap.constBegin(); it != flowMap.constEnd(); ++it)
        flows.append({it.key(), it.value()});
    std::sort(flows.begin(), flows.end(), [](const auto &a, const auto &b) {
        return a.second.packets > b.second.packets;
    });

    const QLocale locale;
    QStringList lines;
    lines << tr("Top connection corridors:");
    const int maxFlows = std::min(5, static_cast<int>(flows.size()));
    for (int i = 0; i < maxFlows; ++i) {
        const auto &entry = flows.at(i);
        QString countryHint;
        if (m_geo) {
            const QStringList parts = entry.first.split(QStringLiteral(" -> "));
            if (parts.size() == 2) {
                const QVector<GeoStruct> geoData = m_geo->GeoVector(parts.at(0), parts.at(1));
                QStringList countries;
                for (const auto &geoStruct : geoData) {
                    for (const auto &field : geoStruct.fields) {
                        if (field.first == QStringLiteral("Country")) {
                            countries << field.second;
                            break;
                        }
                    }
                }
                countries.removeDuplicates();
                if (!countries.isEmpty())
                    countryHint = QStringLiteral(" (%1)").arg(countries.join(QStringLiteral(" ↔ ")));
            }
        }
        lines << tr("  • %1%2 — %3 packets, %4 bytes")
                    .arg(entry.first,
                         countryHint,
                         locale.toString(entry.second.packets, 'f', 0),
                         locale.toString(entry.second.bytes, 'f', 0));
    }

    return lines.join('\n');
}

QString ReportBuilderWindow::annotationHtml(const ReportSection &section) const
{
    const QString identifier = section.annotationFile;
    if (identifier.isEmpty())
        return QString();

    const AnnotationRecord *record = nullptr;
    for (const auto &ann : m_annotations) {
        if (cleanFileTitle(ann.filePath) == identifier) {
            record = &ann;
            break;
        }
    }
    if (!record)
        return tr("<p><em>Annotation %1 not found.</em></p>").arg(identifier);

    const QJsonObject root = record->document.object();
    QString html;
    QString heading = section.title.isEmpty() ? record->title : section.title;
    if (!heading.isEmpty())
        html += QStringLiteral("<h3>%1</h3>").arg(heading.toHtmlEscaped());
    if (!section.title.isEmpty() && !record->title.isEmpty() && section.title != record->title)
        html += QStringLiteral("<p class=\"annotation-source\">%1</p>")
                    .arg(record->title.toHtmlEscaped());
    if (!record->description.isEmpty())
        html += QStringLiteral("<p>%1</p>").arg(record->description.toHtmlEscaped());
    if (section.includeTags && !record->tags.isEmpty()) {
        html += QStringLiteral("<p><strong>Tags:</strong> %1</p>")
                    .arg(record->tags.join(QStringLiteral(", ")).toHtmlEscaped());
    }
    if (!record->threatLevel.isEmpty()) {
        html += QStringLiteral("<p><strong>Threat level:</strong> %1</p>")
                    .arg(record->threatLevel.toHtmlEscaped());
    }
    if (!record->recommendedAction.isEmpty()) {
        html += QStringLiteral("<p><strong>Recommended action:</strong> %1</p>")
                    .arg(record->recommendedAction.toHtmlEscaped());
    }

    if (!section.includePacketTable)
        return html;

    const QJsonArray packets = root.value(QStringLiteral("packets")).toArray();
    if (packets.isEmpty())
        return html;

    html += QStringLiteral("<table border=\"1\" cellspacing=\"0\" cellpadding=\"4\" style=\"border-collapse:collapse;width:100%;\">");
    html += QStringLiteral("<tr style=\"background:#f0f0f0;\">");
    html += QStringLiteral("<th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th>");
    if (section.includeTags)
        html += QStringLiteral("<th>Tags</th>");
    html += QStringLiteral("</tr>");

    for (const QJsonValue &value : packets) {
        const QJsonObject packet = value.toObject();
        QStringList tagList;
        for (const QJsonValue &tagVal : packet.value(QStringLiteral("tags")).toArray())
            tagList.append(tagVal.toString());
        const QString color = packet.value(QStringLiteral("color")).toString();
        QString style;
        if (section.includeColors && !color.isEmpty())
            style = QStringLiteral(" style=\"background:%1;\"").arg(color);

        html += QStringLiteral("<tr%1>").arg(style);
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("number")).toString().toHtmlEscaped());
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("time")).toString().toHtmlEscaped());
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("source")).toString().toHtmlEscaped());
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("destination")).toString().toHtmlEscaped());
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("protocol")).toString().toHtmlEscaped());
        html += QStringLiteral("<td>%1</td>").arg(packet.value(QStringLiteral("info")).toString().toHtmlEscaped());
        if (section.includeTags)
            html += QStringLiteral("<td>%1</td>").arg(tagList.join(QStringLiteral(", ")).toHtmlEscaped());
        html += QStringLiteral("</tr>");
    }
    html += QStringLiteral("</table>");
    return html;
}

QString ReportBuilderWindow::sectionToHtml(const ReportSection &section) const
{
    switch (section.kind) {
    case ReportSection::Kind::Heading: {
        const int level = std::clamp(section.headingLevel, 1, 4);
        return QStringLiteral("<h%1>%2</h%1>")
            .arg(level)
            .arg(section.title.toHtmlEscaped());
    }
    case ReportSection::Kind::Text: {
        QString html;
        if (!section.title.isEmpty())
            html += QStringLiteral("<h3>%1</h3>").arg(section.title.toHtmlEscaped());
        html += QStringLiteral("<p>%1</p>")
                    .arg(Qt::convertFromPlainText(section.body));
        return html;
    }
    case ReportSection::Kind::Annotation:
        return annotationHtml(section);
    case ReportSection::Kind::Statistics: {
        QString html;
        if (!section.title.isEmpty())
            html += QStringLiteral("<h3>%1</h3>").arg(section.title.toHtmlEscaped());
        const AggregatedStats data = aggregateStatistics(section);
        html += QStringLiteral("<pre style=\"white-space:pre-wrap;font-family:'Fira Sans',sans-serif;\">%1</pre>")
                    .arg(section.body.toHtmlEscaped());
        const QString charts = renderStatisticsChartsHtml(section, data);
        if (!charts.isEmpty())
            html += charts;
        return html;
    }
    case ReportSection::Kind::Anomalies:
    case ReportSection::Kind::GeoOverview: {
        QString html;
        if (!section.title.isEmpty())
            html += QStringLiteral("<h3>%1</h3>").arg(section.title.toHtmlEscaped());
        html += QStringLiteral("<pre style=\"white-space:pre-wrap;font-family:'Fira Sans',sans-serif;\">%1</pre>")
                    .arg(section.body.toHtmlEscaped());
        return html;
    }
    }
    return QString();
}

QString ReportBuilderWindow::renderFullDocument() const
{
    QString html;
    html += QStringLiteral("<html><head><meta charset='utf-8'><style>");
    html += QStringLiteral("body{font-family:'Segoe UI',sans-serif;font-size:11pt;color:#000;background:#fff;max-width:960px;margin:0 auto;padding:12px 24px;}");
    html += QStringLiteral("table{margin-top:6px;margin-bottom:12px;border-collapse:collapse;}");
    html += QStringLiteral("th,td{border:1px solid #cfd6e4;padding:4px 6px;color:#000;}");
    html += QStringLiteral("h1,h2,h3,h4{color:#000;}");
    html += QStringLiteral("p{color:#000;}");
    html += QStringLiteral("li{color:#000;}");
    html += QStringLiteral("pre{background:#f7f9fc;padding:8px;border-radius:6px;color:#000;}");
    html += QStringLiteral(".chart{margin:24px auto;text-align:center;}");
    html += QStringLiteral(".chart img{width:100%;max-width:640px;border:1px solid #d0d6df;padding:8px;background:#fff;display:block;margin:0 auto;}");
    html += QStringLiteral(".report-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:12px;}");
    html += QStringLiteral(".header-text{display:flex;flex-direction:column;gap:4px;}");
    html += QStringLiteral(".header-organization{font-weight:700;font-size:14pt;color:#000;}");
    html += QStringLiteral(".header-title{font-size:20pt;font-weight:600;color:#000;}");
    html += QStringLiteral(".header-period{font-size:11pt;color:#000;}");
    html += QStringLiteral(".header-logo-wrap{margin-left:24px;}");
    html += QStringLiteral(".header-logo{max-height:80px;}");
    html += QStringLiteral(".section-divider{border:none;border-top:1px solid #d0d6df;margin:32px 0;}");
    html += QStringLiteral(".annotation-source{color:#4a5568;font-size:10pt;margin-top:-10px;margin-bottom:12px;}");
    html += QStringLiteral(".page-break{page-break-before:always;break-before:page;height:0;margin:0;padding:0;}");
    html += QStringLiteral(".empty-placeholder{color:#4a5568;font-style:italic;margin:48px 0;text-align:center;}");
    html += QStringLiteral("</style></head><body>");
    html += headerHtml();
    if (m_sections.isEmpty()) {
        html += QStringLiteral("<div class=\"empty-placeholder\">%1</div>")
                    .arg(tr("Add sections on the left to build your report."));
    } else {
        int currentPage = 1;
        int nextAutoPage = 1;
        for (int i = 0; i < m_sections.size(); ++i) {
            const ReportSection &section = m_sections.at(i);
            int targetPage = section.pageNumber > 0 ? section.pageNumber : nextAutoPage;
            if (targetPage < currentPage)
                targetPage = currentPage;
            while (currentPage < targetPage) {
                html += QStringLiteral("<div class=\"page-break\"></div>");
                ++currentPage;
            }
            html += sectionToHtml(section);
            currentPage = targetPage;

            int upcomingAutoPage = section.pageNumber > 0 ? section.pageNumber + 1 : currentPage + 1;
            bool nextStartsNewPage = false;
            if (i < m_sections.size() - 1) {
                const ReportSection &nextSection = m_sections.at(i + 1);
                int nextTarget = nextSection.pageNumber > 0 ? nextSection.pageNumber : upcomingAutoPage;
                if (nextTarget < currentPage)
                    nextTarget = currentPage;
                nextStartsNewPage = nextTarget > currentPage;
            }

            if (i < m_sections.size() - 1 && !nextStartsNewPage && section.kind != ReportSection::Kind::Heading)
                html += QStringLiteral("<hr class=\"section-divider\"/>");

            nextAutoPage = upcomingAutoPage;
        }
    }
    html += QStringLiteral("</body></html>");
    return html;
}

void ReportBuilderWindow::ensureReportingDirectory() const
{
    QDir().mkpath(reportingDirectory());
    QDir().mkpath(anomaliesDirectory());
    QDir().mkpath(draftsDirectory());
    QDir().mkpath(templatesDirectory());
}

QString ReportBuilderWindow::reportingDirectory() const
{
    if (m_settings) {
        return m_settings->reportsDirectory();
    }

    QDir dir(QDir::currentPath());
    dir.mkpath(QStringLiteral("reporting"));
    dir.cd(QStringLiteral("reporting"));
    return dir.absolutePath();
}

QString ReportBuilderWindow::draftsDirectory() const
{
    return reportingDirectory() + QStringLiteral("/drafts");
}

QString ReportBuilderWindow::templatesDirectory() const
{
    return reportingDirectory() + QStringLiteral("/templates");
}

QString ReportBuilderWindow::anomaliesDirectory() const
{
    if (m_settings) {
        return m_settings->anomaliesDirectory();
    }

    return reportingDirectory() + QStringLiteral("/anomalies");
}

QString ReportBuilderWindow::anomaliesFilePath() const
{
    return QDir(anomaliesDirectory()).filePath(QStringLiteral("anomalies.json"));
}

void ReportBuilderWindow::loadAvailableAnnotations()
{
    m_annotations.clear();
    QDir dir(reportingDirectory());
    QStringList files = dir.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Time);
    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly))
            continue;
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject())
            continue;
        const QJsonObject obj = doc.object();
        AnnotationRecord record;
        record.filePath = dir.filePath(fileName);
        record.document = doc;
        record.title = obj.value(QStringLiteral("title")).toString();
        record.description = obj.value(QStringLiteral("description")).toString();
        record.threatLevel = obj.value(QStringLiteral("threatLevel")).toString();
        record.recommendedAction = obj.value(QStringLiteral("recommendedAction")).toString();
        const QJsonArray tagArray = obj.value(QStringLiteral("tags")).toArray();
        for (const QJsonValue &tagValue : tagArray)
            record.tags.append(tagValue.toString());
        record.createdAt = QDateTime::fromString(obj.value(QStringLiteral("createdAt")).toString(), Qt::ISODate);
        if (record.title.isEmpty())
            record.title = cleanFileTitle(record.filePath);
        m_annotations.append(record);
    }
}

void ReportBuilderWindow::refreshAnnotationCombo(QComboBox *combo) const
{
    if (!combo)
        return;
    const QSignalBlocker blocker(combo);
    const QString currentId = combo->currentData().toString();
    combo->clear();
    for (const auto &record : m_annotations) {
        QString label = record.title;
        if (record.createdAt.isValid())
            label += QStringLiteral(" (%1)").arg(QLocale::system().toString(record.createdAt, QLocale::ShortFormat));
        combo->addItem(label, cleanFileTitle(record.filePath));
    }
    int idx = -1;
    if (!currentId.isEmpty()) {
        for (int i = 0; i < combo->count(); ++i) {
            if (combo->itemData(i).toString() == currentId) {
                idx = i;
                break;
            }
        }
    }
    if (idx >= 0)
        combo->setCurrentIndex(idx);
    else if (combo->count() > 0)
        combo->setCurrentIndex(0);
}

QJsonObject ReportBuilderWindow::sectionToJson(const ReportSection &section) const
{
    QJsonObject obj;
    obj.insert(QStringLiteral("kind"), static_cast<int>(section.kind));
    obj.insert(QStringLiteral("title"), section.title);
    obj.insert(QStringLiteral("body"), section.body);
    obj.insert(QStringLiteral("headingLevel"), section.headingLevel);
    obj.insert(QStringLiteral("annotationFile"), section.annotationFile);
    obj.insert(QStringLiteral("includePacketTable"), section.includePacketTable);
    obj.insert(QStringLiteral("includeTags"), section.includeTags);
    obj.insert(QStringLiteral("includeColors"), section.includeColors);
    if (section.accentColor.isValid())
        obj.insert(QStringLiteral("accentColor"), section.accentColor.name(QColor::HexArgb));
    if (!section.statSessionFiles.isEmpty()) {
        QJsonArray sessions;
        for (const QString &file : section.statSessionFiles)
            sessions.append(file);
        obj.insert(QStringLiteral("statSessionFiles"), sessions);
    }
    obj.insert(QStringLiteral("statRangeStart"), section.statRangeStart);
    obj.insert(QStringLiteral("statRangeEnd"), section.statRangeEnd);
    if (!section.statChartKinds.isEmpty()) {
        QJsonArray charts;
        for (const QString &chart : section.statChartKinds)
            charts.append(chart);
        obj.insert(QStringLiteral("statChartKinds"), charts);
    }
    if (!section.storedAnomalyIds.isEmpty()) {
        QJsonArray ids;
        for (const QString &id : section.storedAnomalyIds)
            ids.append(id);
        obj.insert(QStringLiteral("storedAnomalyIds"), ids);
    }
    obj.insert(QStringLiteral("pageNumber"), section.pageNumber);
    return obj;
}

ReportBuilderWindow::ReportSection ReportBuilderWindow::sectionFromJson(const QJsonObject &obj) const
{
    ReportSection section;
    section.kind = static_cast<ReportSection::Kind>(obj.value(QStringLiteral("kind")).toInt());
    section.title = obj.value(QStringLiteral("title")).toString();
    section.body = obj.value(QStringLiteral("body")).toString();
    section.headingLevel = obj.value(QStringLiteral("headingLevel")).toInt(1);
    section.annotationFile = obj.value(QStringLiteral("annotationFile")).toString();
    section.includePacketTable = obj.value(QStringLiteral("includePacketTable")).toBool(true);
    section.includeTags = obj.value(QStringLiteral("includeTags")).toBool(true);
    section.includeColors = obj.value(QStringLiteral("includeColors")).toBool(true);
    const QString color = obj.value(QStringLiteral("accentColor")).toString();
    if (!color.isEmpty())
        section.accentColor = QColor(color);
    const QJsonArray sessionArray = obj.value(QStringLiteral("statSessionFiles")).toArray();
    for (const QJsonValue &value : sessionArray)
        section.statSessionFiles.append(value.toString());
    section.statRangeStart = obj.value(QStringLiteral("statRangeStart")).toInt(section.statRangeStart);
    section.statRangeEnd = obj.value(QStringLiteral("statRangeEnd")).toInt(section.statRangeEnd);
    const QJsonArray chartArray = obj.value(QStringLiteral("statChartKinds")).toArray();
    for (const QJsonValue &value : chartArray)
        section.statChartKinds.append(value.toString());
    const QJsonArray anomalyArray = obj.value(QStringLiteral("storedAnomalyIds")).toArray();
    for (const QJsonValue &value : anomalyArray)
        section.storedAnomalyIds.append(value.toString());
    section.pageNumber = obj.value(QStringLiteral("pageNumber")).toInt(section.pageNumber);
    section.statSessionFiles.removeAll(QString());
    section.statChartKinds.removeAll(QString());
    section.storedAnomalyIds.removeAll(QString());
    section.statSessionFiles.removeDuplicates();
    section.statChartKinds.removeDuplicates();
    section.storedAnomalyIds.removeDuplicates();
    if (section.kind == ReportSection::Kind::Statistics)
        section.body = statisticsSummaryText(section);
    else if (section.kind == ReportSection::Kind::Anomalies)
        section.body = anomaliesSummaryText(section);
    else if (section.kind == ReportSection::Kind::GeoOverview)
        section.body = geoOverviewSummaryText();
    return section;
}

QJsonObject ReportBuilderWindow::headerToJson() const
{
    QJsonObject obj;
    obj.insert(QStringLiteral("organization"), m_header.organization);
    obj.insert(QStringLiteral("title"), m_header.title);
    obj.insert(QStringLiteral("periodPreset"), m_header.periodPreset);
    if (m_header.periodStart.isValid())
        obj.insert(QStringLiteral("periodStart"), m_header.periodStart.toString(Qt::ISODate));
    if (m_header.periodEnd.isValid())
        obj.insert(QStringLiteral("periodEnd"), m_header.periodEnd.toString(Qt::ISODate));
    if (!m_header.logoPath.isEmpty())
        obj.insert(QStringLiteral("logoPath"), m_header.logoPath);
    return obj;
}

void ReportBuilderWindow::loadHeaderFromJson(const QJsonObject &obj)
{
    if (obj.isEmpty()) {
        m_cachedLogoDataUrl.clear();
        m_cachedLogoPath.clear();
        return;
    }

    if (obj.contains(QStringLiteral("organization")))
        m_header.organization = obj.value(QStringLiteral("organization")).toString(m_header.organization);
    if (obj.contains(QStringLiteral("title")))
        m_header.title = obj.value(QStringLiteral("title")).toString(m_header.title);

    const QString preset = obj.value(QStringLiteral("periodPreset")).toString(m_header.periodPreset);
    m_header.periodPreset = preset.isEmpty() ? m_header.periodPreset : preset;

    const QDate start = QDate::fromString(obj.value(QStringLiteral("periodStart")).toString(), Qt::ISODate);
    if (start.isValid())
        m_header.periodStart = start;
    const QDate end = QDate::fromString(obj.value(QStringLiteral("periodEnd")).toString(), Qt::ISODate);
    if (end.isValid())
        m_header.periodEnd = end;

    if (obj.contains(QStringLiteral("logoPath")))
        m_header.logoPath = obj.value(QStringLiteral("logoPath")).toString();

    const QString presetLower = m_header.periodPreset.toLower();
    const bool recognized = presetLower == QStringLiteral("daily") || presetLower == QStringLiteral("weekly") ||
                            presetLower == QStringLiteral("monthly") || presetLower == QStringLiteral("custom");
    if (!recognized)
        m_header.periodPreset = QStringLiteral("custom");
    else
        m_header.periodPreset = presetLower;

    if (m_header.periodPreset == QStringLiteral("custom")) {
        ensureHeaderOrder();
    } else if (!matchesPreset(m_header.periodPreset, m_header.periodStart, m_header.periodEnd)) {
        applyHeaderPreset();
    } else {
        ensureHeaderOrder();
    }

    m_cachedLogoDataUrl.clear();
    m_cachedLogoPath.clear();
}

void ReportBuilderWindow::regenerateAutoSections()
{
    for (ReportSection &section : m_sections) {
        if (section.kind == ReportSection::Kind::Statistics)
            section.body = statisticsSummaryText(section);
        else if (section.kind == ReportSection::Kind::Anomalies)
            section.body = anomaliesSummaryText(section);
        else if (section.kind == ReportSection::Kind::GeoOverview)
            section.body = geoOverviewSummaryText();
    }
    updatePreview();
}

void ReportBuilderWindow::updatePreview()
{
    if (!m_preview)
        return;
    m_preview->setHtml(renderFullDocument());
}
