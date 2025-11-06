#include "mainwindow_ui.h"
#include "../theme/theme.h"
#include "../theme/appearancedialog.h"
#include "../coloring/customizerdialog.h"
#include "../PacketTableModel.h"
#include "../statistics/geooverviewdialog.h"
#include "reportbuilderwindow.h"
#include "preferencesdialog.h"
#include "followstreamdialog.h"
#include <QSignalBlocker>
#include <QTimer>
#include <QMenu>
#include <QMenuBar>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QList>
#include <QToolButton>
#include <QUrl>

void MainWindow::setupUI() {
    // === Central UI ===
    QWidget *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout;

    // Top bar
    auto *topBar = new QHBoxLayout;
    ifaceBox   = new QComboBox;
    filterEdit = new QLineEdit; filterEdit->setPlaceholderText("tcp port 80");
    promiscBox = new QCheckBox("Promiscuous"); promiscBox->setChecked(true);
    startBtn   = new QPushButton("Start");
    stopBtn    = new QPushButton("Stop"); stopBtn->setEnabled(false);

    topBar->addWidget(ifaceBox);
    topBar->addWidget(filterEdit);
    topBar->addWidget(promiscBox);
    topBar->addWidget(startBtn);
    topBar->addWidget(stopBtn);
    mainLayout->addLayout(topBar);

    auto *toolbarLayout = new QHBoxLayout;
    toolbarLayout->setSpacing(6);

    auto makeButton = [&](const QString &symbol, const QString &tooltip) {
        auto *btn = new QToolButton;
        btn->setText(symbol);
        btn->setToolTip(tooltip);
        btn->setAutoRaise(true);
        toolbarLayout->addWidget(btn);
        return btn;
    };

    QToolButton *resetLayoutBtn = makeButton(QStringLiteral("⟲"),
                                             tr("Reset layout to default size"));
    connect(resetLayoutBtn, &QToolButton::clicked,
            this, &MainWindow::resetLayoutToDefault);

    QToolButton *resizeColumnsBtn = makeButton(QStringLiteral("⇔"),
                                               tr("Resize packet list columns to fit contents"));
    connect(resizeColumnsBtn, &QToolButton::clicked,
            this, &MainWindow::resizePacketColumnsToContents);

    QToolButton *normalSizeBtn = makeButton(QStringLiteral("▢"),
                                            tr("Return the window to its normal size"));
    connect(normalSizeBtn, &QToolButton::clicked,
            this, &MainWindow::restoreDefaultWindowSize);

    QToolButton *shrinkTextBtn = makeButton(QStringLiteral("A−"),
                                            tr("Shrink the main window text"));
    connect(shrinkTextBtn, &QToolButton::clicked,
            this, &MainWindow::shrinkText);

    QToolButton *enlargeTextBtn = makeButton(QStringLiteral("A+"),
                                             tr("Enlarge the main window text"));
    connect(enlargeTextBtn, &QToolButton::clicked,
            this, &MainWindow::enlargeText);

    coloringToggleButton = makeButton(QStringLiteral("🎨"),
                                      tr("Draw packets using coloring rules"));
    coloringToggleButton->setCheckable(true);
    coloringToggleButton->setChecked(coloringEnabled);
    connect(coloringToggleButton, &QToolButton::toggled,
            this, &MainWindow::toggleColoring);

    autoScrollToggleButton = makeButton(QStringLiteral("⤓"),
                                        tr("Automatically scroll to the last packet during a live capture"));
    autoScrollToggleButton->setCheckable(true);
    autoScrollToggleButton->setChecked(autoScrollEnabled);
    connect(autoScrollToggleButton, &QToolButton::toggled,
            this, &MainWindow::toggleAutoScroll);

    QToolButton *goFirstBtn = makeButton(QStringLiteral("⏮"),
                                         tr("Go to the first packet"));
    connect(goFirstBtn, &QToolButton::clicked,
            this, &MainWindow::goToFirstPacket);

    QToolButton *goLastBtn = makeButton(QStringLiteral("⏭"),
                                        tr("Go to the last packet"));
    connect(goLastBtn, &QToolButton::clicked,
            this, &MainWindow::goToLastPacket);

    QToolButton *goToPacketBtn = makeButton(QStringLiteral("⌖"),
                                            tr("Go to a specified packet"));
    connect(goToPacketBtn, &QToolButton::clicked,
            this, &MainWindow::goToPacketNumber);

    QToolButton *prevPacketBtn = makeButton(QStringLiteral("◀"),
                                            tr("Go to the previous packet"));
    connect(prevPacketBtn, &QToolButton::clicked,
            this, &MainWindow::goToPreviousPacket);

    QToolButton *nextPacketBtn = makeButton(QStringLiteral("▶"),
                                            tr("Go to the next packet"));
    connect(nextPacketBtn, &QToolButton::clicked,
            this, &MainWindow::goToNextPacket);

    QToolButton *findPacketBtn = makeButton(QStringLiteral("🔍"),
                                            tr("Find a packet"));
    connect(findPacketBtn, &QToolButton::clicked,
            this, &MainWindow::findPacket);

    toolbarLayout->addStretch();
    mainLayout->addLayout(toolbarLayout);

    // Packet table + details/hex splitter
    mainSplitter = new QSplitter(Qt::Horizontal);

    // 1) Left Pane: Packets
    //PacketTable usage (TODO: swap QTableWidget to QTableView)
    leftSplitter = new QSplitter(Qt::Vertical);
    // packetTable = new QTableWidget;
    // packetTable->setColumnCount(7);
    // packetTable->setHorizontalHeaderLabels(
    //     {"No.","Time","Source","Destination","Protocol","Length","Info"}); //QTableWidget before QTableView
    packetTable = new QTableView;
    packetModel = new PacketTableModel(this);
    packetTable->setModel(packetModel);
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // connect(packetTable, &QTableWidget::cellClicked,
    //         this, &MainWindow::onPacketClicked); //QTableWidget before QTableView
    connect(packetTable, &QTableView::clicked,
            this, &MainWindow::onPacketClicked);
    packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    // connect(packetTable, &QTableWidget::customContextMenuRequested,
    //     this, &MainWindow::onPacketTableContextMenu); //QTableWidget before QTableView
    connect(packetTable, &QWidget::customContextMenuRequested,
            this, &MainWindow::onPacketTableContextMenu);
    leftSplitter->addWidget(packetTable);

    // Map
    const QString mapPath = QCoreApplication::applicationDirPath() + "/resources/WorldMap.svg";
    mapWidget = new GeoMapWidget(mapPath, this);
    mapWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    leftSplitter->addWidget(mapWidget);

    mainSplitter->addWidget(leftSplitter);

    // 2) Right pane
    rightSplitter = new QSplitter(Qt::Vertical);

    // 2a) Information tree
    detailsTree = new QTreeWidget;
    detailsTree->setHeaderLabels({ "Info", "Value" });
    detailsTree->setRootIsDecorated(true);
    detailsTree->setIndentation(20);
    detailsTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    detailsTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    rightSplitter->addWidget(detailsTree);

    // 2b) Hex view & payload
    payloadTabs = new QTabWidget;
    payloadTabs->setDocumentMode(true);

    hexEdit = new QPlainTextEdit;
    hexEdit->setReadOnly(true);
    payloadTabs->addTab(hexEdit, tr("Hex Dump"));

    QWidget *payloadTab = new QWidget;
    auto *payloadLayout = new QVBoxLayout(payloadTab);
    payloadLayout->setContentsMargins(0, 0, 0, 0);
    auto *payloadControls = new QHBoxLayout;
    auto *decodeLabel = new QLabel(tr("Decode as:"));
    payloadDecodeCombo = new QComboBox;
    payloadDecodeCombo->addItem(tr("ASCII"));
    payloadDecodeCombo->addItem(tr("Hex"));
    payloadControls->addWidget(decodeLabel);
    payloadControls->addWidget(payloadDecodeCombo);
    payloadControls->addStretch();
    payloadLayout->addLayout(payloadControls);

    payloadView = new QPlainTextEdit;
    payloadView->setReadOnly(true);
    payloadLayout->addWidget(payloadView);

    payloadTabs->addTab(payloadTab, tr("Payload"));
    rightSplitter->addWidget(payloadTabs);

    // TOP5 Pie Chart
    pieChart = new PieChart;
    pieChart->setMinimumHeight(120);
    pieChart->setColorizer(&packetColorizer);
    rightSplitter->addWidget(pieChart);

    mainSplitter->addWidget(rightSplitter);

    mainSplitter->setStretchFactor(0, 3); //left
    mainSplitter->setStretchFactor(1, 2); //right
    leftSplitter->setStretchFactor(0, 5); // packets
    leftSplitter->setStretchFactor(1, 1); // map
    rightSplitter->setStretchFactor(0, 3); // detailsTree
    rightSplitter->setStretchFactor(1, 2); // payloadTabs
    rightSplitter->setStretchFactor(2, 1); // pieChart

    defaultMainSplitterSizes = {900, 520};
    mainSplitter->setSizes(defaultMainSplitterSizes);
    defaultLeftSplitterSizes = {650, 220};
    leftSplitter->setSizes(defaultLeftSplitterSizes);
    defaultRightSplitterSizes = {420, 320, 220};
    rightSplitter->setSizes(defaultRightSplitterSizes);


    mainLayout->addWidget(mainSplitter);
    central->setLayout(mainLayout);
    setCentralWidget(central);

    resize(1280, 850);

    connect(startBtn, &QPushButton::clicked,
            this, &MainWindow::startSniffing);
    connect(stopBtn,  &QPushButton::clicked,
            this, &MainWindow::stopSniffing);
    connect(filterEdit, &QLineEdit::textChanged,
            this, &MainWindow::onFilterTextChanged);

    // === Menu bar ===
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    auto *fileMenu = menuBar->addMenu("File");
    // === Save/Open file ===
    actionOpen = fileMenu->addAction("Open...", this, [this]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Open PCAP", "", "PCAP Files (*.pcap)");
        if (!fileName.isEmpty()) {
            parser.openFromPcap(fileName);

            for (const CapturedPacket &packet : parser.getAllPackets()) {
                QStringList infos;
                infos << QString::number(0) << QString::number(packet.data.size());
                handlePacket(packet.data, infos, packet.linkType);
            }
        }
    });

    actionSave = fileMenu->addAction("Save As...", this, [this](){
        QString fileName = QFileDialog::getSaveFileName(this, "Save PCAP", "", "PCAP Files (*.pcap)");
        if (!fileName.isEmpty()) {
            parser.saveToPcap(fileName);
        }
    });

    actionOpen->setEnabled(true);
    actionSave->setEnabled(true);
    // ===end section===

    newSession = fileMenu->addAction("New Session", this, &MainWindow::startNewSession);
    fileMenu->addSeparator();
    fileMenu->addAction("Exit",      this, [](){ qApp->quit(); });

    auto *captureMenu = menuBar->addMenu("Capture");
    captureMenu->addAction("Start", startBtn, &QPushButton::click);
    captureMenu->addAction("Stop",  stopBtn,  &QPushButton::click);

    auto *analyzeMenu = menuBar->addMenu("Analyze");
    analyzeMenu->addAction("Follow Stream", this, &MainWindow::openFollowStreamDialog);
    anomalyInspectorAction = analyzeMenu->addAction(tr("Anomaly Inspector…"),
                                                   this,
                                                   &MainWindow::openAnomalyInspector);
    showPayloadOnlyAction = analyzeMenu->addAction("Show Payload Only");
    showPayloadOnlyAction->setCheckable(true);
    connect(showPayloadOnlyAction, &QAction::toggled,
            this, &MainWindow::togglePayloadOnlyMode);
    auto *goMenu = menuBar->addMenu(tr("Go"));
    goMenu->addAction(tr("First Packet"), this, &MainWindow::goToFirstPacket);
    goMenu->addAction(tr("Previous Packet"), this, &MainWindow::goToPreviousPacket);
    goMenu->addAction(tr("Next Packet"), this, &MainWindow::goToNextPacket);
    goMenu->addAction(tr("Last Packet"), this, &MainWindow::goToLastPacket);
    goMenu->addSeparator();
    goMenu->addAction(tr("Go to Packet…"), this, &MainWindow::goToPacketNumber);
    goMenu->addAction(tr("Find Packet…"), this, &MainWindow::findPacket);
    goMenu->addSeparator();
    goMenu->addAction(tr("Previous Packet in Conversation"),
                      this,
                      &MainWindow::goToPreviousPacketInConversation);
    goMenu->addAction(tr("Next Packet in Conversation"),
                      this,
                      &MainWindow::goToNextPacketInConversation);
    auto *statsMenu = menuBar->addMenu("Statistics");
    statsMenu->addAction("Summary", this, [this]() {
        StatsDialog dlg(this);
        dlg.exec();
    });
    statsMenu->addAction("GeoOverview", this, [this]() {
        GeoOverviewDialog dlg(&geo, this);
        dlg.exec();
    });
    statsMenu->addAction("Session Manager...", this, &MainWindow::openSessionManager);


    auto *toolsMenu = menuBar->addMenu("Tools");
    toolsMenu->addAction("Preferences", this, &MainWindow::openPreferences);

    toolsMenu->addSeparator();

    toolsMenu->addAction(tr("Reporting…"), this, &MainWindow::openReportBuilder);
    toolsMenu->addAction("Open Logs Folder", this, []() {
        QMessageBox::information(nullptr, "Tools", "Planned");
    });


    auto *viewMenu = menuBar->addMenu("View");
    viewMenu->addAction("Customize coloring…",
                        this, &MainWindow::showColorizeCustomizer);
    viewMenu->addAction("Export Coloring…", this, [this](){
        QString fn = QFileDialog::getSaveFileName(
            this, "Export Coloring", QString(), "JSON (*.json)");
        if (!fn.isEmpty() && packetColorizer.saveRulesToJson(fn)) {
            showColorizeCustomizer();
        }
    });

    viewMenu->addAction("Import Coloring…", this, [this](){
        QString fn = QFileDialog::getOpenFileName(
            this, "Import Coloring", QString(), "JSON (*.json)");
        if (!fn.isEmpty() && packetColorizer.loadRulesFromJson(fn)) {
            packetColorizer.saveRulesToSettings();
            showColorizeCustomizer();
        }
    });
    viewMenu->addAction(tr("Appearance…"), this, &MainWindow::showAppearanceDialog);
        themeToggleAction = viewMenu->addAction(
        Theme::toggleActionText(),
        this, &MainWindow::toggleTheme
    );
    otherThemesAction = viewMenu->addAction("Other themes…",
                                        this, &MainWindow::showOtherThemesDialog);

    auto *helpMenu = menuBar->addMenu("Help");
    helpMenu->addAction("About", this, [](){
        QDesktopServices::openUrl(QUrl("https://omnisecura.github.io/FoxProbeWebsite"));
    });
    // --- Status bar ---
    protocolCombo = new QComboBox(this);
    protocolCombo->setMinimumWidth(100);
    protocolCombo->setToolTip("Top 5 protocols");
    statusBar()->addWidget(protocolCombo);

    packetCountLabel = new QLabel("Packets: 0", this);
    sessionTimeLabel = new QLabel("Time: 00:00:00", this);
    statusBar()->addPermanentWidget(packetCountLabel);
    statusBar()->addPermanentWidget(sessionTimeLabel);

    sessionTimer = new QTimer(this);
    connect(sessionTimer, &QTimer::timeout,
            this, &MainWindow::updateSessionTime);

    packetCount = 0;
    protocolCounts.clear();
    updateProtocolCombo();

    connect(payloadDecodeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onPayloadDecodeChanged);

    applyPayloadOnlyMode(payloadOnlyMode);

    Theme::applyTo(this, Theme::mainWindowContextKey());
}

void MainWindow::listInterfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    {
        QSignalBlocker blocker(ifaceBox);
        ifaceBox->clear();
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            QMessageBox::critical(this, "Error", errbuf);
            return;
        }
        for (auto *d = alldevs; d; d = d->next)
            ifaceBox->addItem(d->name);
        pcap_freealldevs(alldevs);
    }
    const QString preferredInterface = appSettings.defaultInterface();
    if (!preferredInterface.isEmpty()) {
        const int index = ifaceBox->findText(preferredInterface);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
            return;
        }
    }
    const QString lastUsed = appSettings.lastUsedInterface();
    if (!lastUsed.isEmpty()) {
        const int index = ifaceBox->findText(lastUsed);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
            return;
        }
    }
    if (ifaceBox->count() > 0) {
        ifaceBox->setCurrentIndex(0);
    }
}

void MainWindow::openPreferences() {
    QStringList interfaces;
    interfaces.reserve(ifaceBox->count());
    for (int i = 0; i < ifaceBox->count(); ++i) {
        interfaces << ifaceBox->itemText(i);
    }

    PreferencesDialog dlg(appSettings, interfaces, this);
    if (dlg.exec() == QDialog::Accepted) {
        const QString preferredInterface = appSettings.defaultInterface();
        if (!preferredInterface.isEmpty()) {
            const int index = ifaceBox->findText(preferredInterface);
            if (index != -1) {
                ifaceBox->setCurrentIndex(index);
            }
        }
        Theme::applyTheme(appSettings.theme());
        themeToggleAction->setText(Theme::toggleActionText());

        if (appSettings.autoStartCapture() && startBtn->isEnabled() && ifaceBox->count() > 0) {
            QTimer::singleShot(0, startBtn, &QPushButton::click);
        }
    }
}

void MainWindow::openReportBuilder()
{
    if (reportWindow) {
        reportWindow->show();
        reportWindow->raise();
        reportWindow->activateWindow();
        return;
    }

    reportWindow = new ReportBuilderWindow(annotations,
                                           stats.get(),
                                           &geo,
                                           &appSettings,
                                           this);
    reportWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    connect(reportWindow, &QObject::destroyed, this, [this]() {
        reportWindow = nullptr;
    });
    reportWindow->show();
}

void MainWindow::openFollowStreamDialog() {
    FollowStreamDialog dlg(&parser, this);
    dlg.setStreams(parser.getStreamConversations());
    dlg.exec();
}

void MainWindow::showAppearanceDialog() {
    AppearanceDialog dlg(this);
    dlg.exec();
    Theme::applyTo(this, Theme::mainWindowContextKey());
}

void MainWindow::showOtherThemesDialog() {
    OtherThemesDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        Theme::applyTheme(dlg.selectedTheme());
        Theme::applyTo(this, Theme::mainWindowContextKey());
    }
}

void MainWindow::applyPayloadOnlyMode(bool enabled)
{
    if (packetTable) {
        const QList<int> columnsToToggle = {
            PacketColumns::ColumnSource,
            PacketColumns::ColumnDestination,
            PacketColumns::ColumnInfo
        };
        for (int column : columnsToToggle) {
            packetTable->setColumnHidden(column, enabled);
        }
    }

    if (mapWidget)
        mapWidget->setVisible(!enabled);
    if (detailsTree)
        detailsTree->setVisible(!enabled);
    if (pieChart)
        pieChart->setVisible(!enabled);

    if (payloadTabs) {
        payloadTabs->setVisible(true);
        if (enabled && payloadTabs->count() > 1)
            payloadTabs->setCurrentIndex(1);
    }
}

void MainWindow::togglePayloadOnlyMode(bool enabled)
{
    if (payloadOnlyMode == enabled)
        return;

    payloadOnlyMode = enabled;

    if (showPayloadOnlyAction && showPayloadOnlyAction->isChecked() != enabled) {
        QSignalBlocker blocker(showPayloadOnlyAction);
        showPayloadOnlyAction->setChecked(enabled);
    }

    applyPayloadOnlyMode(enabled);
}
