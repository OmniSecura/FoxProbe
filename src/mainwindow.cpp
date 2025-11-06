#include "mainwindow.h"
#include "protocols/proto_struct.h"
#include "coloring/packetcolorizer.h"
#include "theme/theme.h"
#include "gui/mainwindow_ui.h"
#include "gui/followstreamdialog.h"
#include "statistics/sessionmanagerdialog.h"
#include "statistics/anomalyinspectordialog.h"

#include <QComboBox>
#include <QFileInfo>
#include <QLineEdit>
#include <QTimer>
#include <QSignalBlocker>
#include <QInputDialog>
#include <QToolButton>
#include <QItemSelectionModel>
#include <QItemSelection>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ifaceBox(nullptr),
      filterEdit(nullptr),
      promiscBox(nullptr),
      startBtn(nullptr),
      stopBtn(nullptr),
      mainSplitter(nullptr),
      leftSplitter(nullptr),
      rightSplitter(nullptr),
      packetTable(nullptr),
      packetModel(nullptr), //new for QTableView
      detailsTree(nullptr),
      payloadTabs(nullptr),
      hexEdit(nullptr),
      payloadView(nullptr),
      payloadDecodeCombo(nullptr),
      workerThread(nullptr),
      worker(nullptr)
{
    Theme::loadTheme();
    setupUI();
    refreshAnomalyInspector();

    defaultWindowSize = size();
    defaultAppFont = QApplication::font();
    updateColoringToggle();
    updateAutoScrollToggle();

    connect(ifaceBox, &QComboBox::currentTextChanged,
            this, [this](const QString &text) {
                appSettings.setLastUsedInterface(text);
            });
    connect(promiscBox, &QCheckBox::toggled,
            this, [this](bool checked) {
                appSettings.setPromiscuousMode(checked);
            });
    connect(filterEdit, &QLineEdit::editingFinished,
            this, [this]() {
                appSettings.setDefaultFilter(filterEdit->text());
            });

    listInterfaces();
    loadPreferences();
    packetColorizer.loadRulesFromSettings();
}

MainWindow::~MainWindow() {
    packetColorizer.saveRulesToSettings();
    stopSniffing();
}

void MainWindow::loadPreferences() {
    promiscBox->setChecked(appSettings.promiscuousMode());
    filterEdit->setText(appSettings.defaultFilter());

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
        }
    }

    themeToggleAction->setText(Theme::toggleActionText());

    if (appSettings.autoStartCapture() && startBtn->isEnabled() && ifaceBox->count() > 0) {
        QTimer::singleShot(0, startBtn, &QPushButton::click);
    }
}

void MainWindow::openSessionManager()
{
    SessionManagerDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    const auto record = dlg.selectedSession();
    if (!record) {
        return;
    }

    auto loaded = SessionStorage::loadSession(*record);
    if (!loaded) {
        QMessageBox::warning(this,
                             tr("Session Manager"),
                             tr("Failed to load the selected session."));
        return;
    }

    if (!loadOfflineSession(*loaded)) {
        QMessageBox::warning(this,
                             tr("Session Manager"),
                             tr("Unable to display the selected session."));
    }
}

void MainWindow::persistCurrentSession()
{
    if (!stats) {
        return;
    }

    const QString statsDir = Statistics::defaultSessionsDir();
    if (!stats->SaveStatsToJson(statsDir, true)) {
        if (QStatusBar *bar = statusBar()) {
            bar->showMessage(tr("Failed to persist session statistics to %1").arg(statsDir), 5000);
        }
        return;
    }

    const QString statsFile = stats->lastFilePath();
    if (!statsFile.isEmpty()) {
        QFileInfo info(statsFile);
        const QString pcapPath = info.absolutePath()
                               + QLatin1Char('/')
                               + info.completeBaseName()
                               + QStringLiteral(".pcap");
        parser.saveToPcap(pcapPath);
    }
    refreshAnomalyInspector();
}

bool MainWindow::loadOfflineSession(const SessionStorage::LoadedSession &session)
{
    if (stopBtn && stopBtn->isEnabled()) {
        stopSniffing();
    }

    if (sessionTimer) {
        sessionTimer->stop();
    }

    startNewSession();
    protocolCounts.clear();

    qint64 duration = 0;
    if (session.record.startTime.isValid() && session.record.endTime.isValid()) {
        duration = session.record.startTime.secsTo(session.record.endTime);
        if (duration < 0) {
            duration = 0;
        }
    }
    sessionStartTime = QDateTime::currentDateTime().addSecs(-duration);
    updateSessionTime();

    parser.clearBuffer();

    const QDateTime statsStart = session.record.startTime.isValid()
        ? session.record.startTime
        : QDateTime::currentDateTime();
    initializeStatistics(statsStart);

    QDateTime packetTimestamp = statsStart;

    for (const CapturedPacket &packet : session.packets) {
        Sniffing::appendPacket(packet);
        QStringList infos;
        infos << QString::number(packetTimestamp.toSecsSinceEpoch())
              << QString::number(packet.data.size());
        handlePacket(packet.data, infos, packet.linkType);
        packetTimestamp = packetTimestamp.addMSecs(1);
    }

    if (stats) {
        stats->finalizePendingData();
    }
    refreshAnomalyInspector();

    return true;
}

void MainWindow::resetLayoutToDefault()
{
    if (mainSplitter && !defaultMainSplitterSizes.isEmpty())
        mainSplitter->setSizes(defaultMainSplitterSizes);
    if (leftSplitter && !defaultLeftSplitterSizes.isEmpty())
        leftSplitter->setSizes(defaultLeftSplitterSizes);
    if (rightSplitter && !defaultRightSplitterSizes.isEmpty())
        rightSplitter->setSizes(defaultRightSplitterSizes);

    if (defaultWindowSize.isValid())
        resize(defaultWindowSize);

    if (fontSizeOffset != 0)
        fontSizeOffset = 0;
    QApplication::setFont(defaultAppFont);
}

void MainWindow::resizePacketColumnsToContents()
{
    if (packetTable)
        packetTable->resizeColumnsToContents();
}

void MainWindow::restoreDefaultWindowSize()
{
    if (defaultWindowSize.isValid())
        resize(defaultWindowSize);
}

void MainWindow::shrinkText()
{
    fontSizeOffset -= 1;
    applyFontOffset();
}

void MainWindow::enlargeText()
{
    fontSizeOffset += 1;
    applyFontOffset();
}

void MainWindow::toggleColoring(bool enabled)
{
    if (coloringEnabled == enabled)
        return;

    coloringEnabled = enabled;
    updateColoringToggle();
    refreshPacketColoring();
}

void MainWindow::toggleAutoScroll(bool enabled)
{
    if (autoScrollEnabled == enabled)
        return;

    autoScrollEnabled = enabled;
    updateAutoScrollToggle();
    if (autoScrollEnabled && packetTable)
        packetTable->scrollToBottom();
}

void MainWindow::goToLastPacket()
{
    if (!packetModel)
        return;
    const int lastRow = packetModel->rowCount() - 1;
    if (lastRow >= 0)
        selectPacketRow(lastRow);
}

void MainWindow::goToFirstPacket()
{
    if (!packetModel || packetModel->rowCount() == 0)
        return;
    selectPacketRow(0);
}

void MainWindow::goToPacketNumber()
{
    if (!packetModel)
        return;
    const int count = packetModel->rowCount();
    if (count <= 0)
        return;

    bool ok = false;
    const int number = QInputDialog::getInt(this,
                                            tr("Go to Packet"),
                                            tr("Packet number:"),
                                            1,
                                            1,
                                            count,
                                            1,
                                            &ok);
    if (ok)
        selectPacketRow(number - 1);
}

void MainWindow::goToNextPacket()
{
    if (!packetModel || !packetTable)
        return;

    const int count = packetModel->rowCount();
    if (count <= 0)
        return;

    const QModelIndex current = packetTable->currentIndex();
    int nextRow = current.isValid() ? current.row() + 1 : 0;
    if (nextRow >= count)
        nextRow = count - 1;
    selectPacketRow(nextRow);
}

void MainWindow::goToPreviousPacket()
{
    if (!packetModel || !packetTable)
        return;

    const int count = packetModel->rowCount();
    if (count <= 0)
        return;

    const QModelIndex current = packetTable->currentIndex();
    int previousRow = current.isValid() ? current.row() - 1 : 0;
    if (previousRow < 0)
        previousRow = 0;
    selectPacketRow(previousRow);
}

void MainWindow::goToNextPacketInConversation()
{
    goToPacketInConversation(true);
}

void MainWindow::goToPreviousPacketInConversation()
{
    goToPacketInConversation(false);
}

void MainWindow::goToPacketInConversation(bool forward)
{
    if (!packetModel || !packetTable)
        return;

    const QModelIndex current = packetTable->currentIndex();
    if (!current.isValid())
        return;

    QString endpointA;
    QString endpointB;
    if (!conversationKeyForRow(current.row(), endpointA, endpointB))
        return;

    const int count = packetModel->rowCount();
    if (count <= 1)
        return;

    int index = current.row() + (forward ? 1 : -1);
    while (index >= 0 && index < count) {
        QString otherA;
        QString otherB;
        if (conversationKeyForRow(index, otherA, otherB)) {
            if (otherA == endpointA && otherB == endpointB) {
                selectPacketRow(index);
                return;
            }
        }
        index += forward ? 1 : -1;
    }
}

bool MainWindow::conversationKeyForRow(int row, QString &endpointA, QString &endpointB) const
{
    if (!packetModel)
        return false;
    if (row < 0 || row >= packetModel->rowCount())
        return false;

    PacketTableRow tableRow = packetModel->row(row);
    if (tableRow.columns.size() <= ColumnDestination)
        return false;

    const QString source = tableRow.columns.value(ColumnSource);
    const QString destination = tableRow.columns.value(ColumnDestination);

    if (source.isEmpty() && destination.isEmpty())
        return false;

    if (source <= destination) {
        endpointA = source;
        endpointB = destination;
    } else {
        endpointA = destination;
        endpointB = source;
    }

    return true;
}

void MainWindow::findPacket()
{
    if (!packetModel)
        return;
    const int count = packetModel->rowCount();
    if (count <= 0)
        return;

    bool ok = false;
    const QString text = QInputDialog::getText(this,
                                              tr("Find Packet"),
                                              tr("Search text:"),
                                              QLineEdit::Normal,
                                              QString(),
                                              &ok);
    if (!ok || text.isEmpty())
        return;

    int start = -1;
    if (packetTable) {
        const QModelIndex current = packetTable->currentIndex();
        if (current.isValid())
            start = current.row();
    }

    for (int offset = 1; offset <= count; ++offset) {
        const int row = (start + offset) % count;
        PacketTableRow r = packetModel->row(row);
        bool match = false;
        for (const QString &column : r.columns) {
            if (column.contains(text, Qt::CaseInsensitive)) {
                match = true;
                break;
            }
        }
        if (match) {
            selectPacketRow(row);
            return;
        }
    }

    QMessageBox::information(this,
                             tr("Find Packet"),
                             tr("No packets matched \"%1\".").arg(text));
}

void MainWindow::applyFontOffset()
{
    QFont font = defaultAppFont;
    if (font.pointSize() > 0) {
        const int base = defaultAppFont.pointSize();
        int newSize = base + fontSizeOffset;
        if (newSize < 6) {
            newSize = 6;
            fontSizeOffset = newSize - base;
        }
        font.setPointSize(newSize);
    } else if (font.pixelSize() > 0) {
        const int base = defaultAppFont.pixelSize();
        int newSize = base + fontSizeOffset;
        if (newSize < 8) {
            newSize = 8;
            fontSizeOffset = newSize - base;
        }
        font.setPixelSize(newSize);
    }
    QApplication::setFont(font);
}

void MainWindow::refreshPacketColoring()
{
    if (!packetModel)
        return;

    const int count = packetModel->rowCount();
    for (int row = 0; row < count; ++row) {
        QColor color;
        if (coloringEnabled) {
            PacketTableRow r = packetModel->row(row);
            if (!r.rawData.isEmpty()) {
                if (packetColorizer.linkType() != r.linkType)
                    packetColorizer.setLinkType(r.linkType, 0);
                const u_char *pkt = reinterpret_cast<const u_char*>(r.rawData.constData());
                pcap_pkthdr hdr{};
                hdr.caplen = static_cast<bpf_u_int32>(r.rawData.size());
                hdr.len = hdr.caplen;
                color = packetColorizer.colorFor(&hdr, pkt);
            }
        }
        packetModel->setRowBackground(row, color);
    }
}

void MainWindow::selectPacketRow(int row)
{
    if (!packetModel || !packetTable)
        return;
    if (row < 0 || row >= packetModel->rowCount())
        return;

    QItemSelectionModel *selection = packetTable->selectionModel();
    const QModelIndex index = packetModel->index(row, 0);
    if (!index.isValid())
        return;

    if (selection)
        selection->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    packetTable->setCurrentIndex(index);
    packetTable->scrollTo(index);
    onPacketClicked(index);
}

void MainWindow::initializeStatistics(const QDateTime &sessionStart)
{
    stats.reset();
    stats = std::make_unique<Statistics>(sessionStart);
    connect(stats.get(), &Statistics::anomalyDetected,
            this, &MainWindow::onAnomalyDetected);
    anomalyEvents.clear();
    refreshAnomalyInspector();
}

void MainWindow::refreshAnomalyInspector()
{
    if (anomalyInspectorAction) {
        if (anomalyEvents.isEmpty()) {
            anomalyInspectorAction->setText(tr("Anomaly Inspector…"));
        } else {
            anomalyInspectorAction->setText(tr("Anomaly Inspector… (%1)")
                                               .arg(anomalyEvents.size()));
        }
    }
    if (anomalyDialog) {
        anomalyDialog->setEvents(anomalyEvents);
    }
}

void MainWindow::openAnomalyInspector()
{
    if (!anomalyDialog) {
        anomalyDialog = new AnomalyInspectorDialog(this);
        connect(anomalyDialog, &AnomalyInspectorDialog::requestFocusPackets,
                this, &MainWindow::focusAnomalyPackets);
    }
    anomalyDialog->setEvents(anomalyEvents);
    anomalyDialog->show();
    anomalyDialog->raise();
    anomalyDialog->activateWindow();
}

void MainWindow::focusAnomalyPackets(const QVector<int> &rows)
{
    if (!packetModel || !packetTable || rows.isEmpty()) {
        return;
    }

    QItemSelectionModel *selection = packetTable->selectionModel();
    if (!selection) {
        return;
    }

    selection->clearSelection();
    int firstValid = -1;
    for (int row : rows) {
        if (row < 0 || row >= packetModel->rowCount()) {
            continue;
        }
        if (firstValid == -1) {
            firstValid = row;
        }
        const QModelIndex left = packetModel->index(row, 0);
        const QModelIndex right = packetModel->index(row, PacketColumns::ColumnCount - 1);
        QItemSelection range(left, right);
        selection->select(range, QItemSelectionModel::Select | QItemSelectionModel::Rows);
    }

    if (firstValid != -1) {
        const QModelIndex index = packetModel->index(firstValid, 0);
        packetTable->setCurrentIndex(index);
        packetTable->scrollTo(index);
        onPacketClicked(index);
    }
}

void MainWindow::onAnomalyDetected(const AnomalyDetector::Event &event)
{
    anomalyEvents.append(event);
    refreshAnomalyInspector();
}

void MainWindow::updateColoringToggle()
{
    if (!coloringToggleButton)
        return;

    QSignalBlocker blocker(coloringToggleButton);
    coloringToggleButton->setChecked(coloringEnabled);
    coloringToggleButton->setToolTip(coloringEnabled
                                     ? tr("Disable coloring rules")
                                     : tr("Draw packets using coloring rules"));
}

void MainWindow::updateAutoScrollToggle()
{
    if (!autoScrollToggleButton)
        return;

    QSignalBlocker blocker(autoScrollToggleButton);
    autoScrollToggleButton->setChecked(autoScrollEnabled);
    autoScrollToggleButton->setToolTip(autoScrollEnabled
                                       ? tr("Stop automatically scrolling to the last packet")
                                       : tr("Automatically scroll to the last packet during live capture"));
}
