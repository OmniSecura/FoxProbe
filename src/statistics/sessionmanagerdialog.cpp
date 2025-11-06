#include "sessionmanagerdialog.h"
#include "../theme/theme.h"

#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <QPalette>
#include <QColor>
#include <QDir>

SessionManagerDialog::SessionManagerDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Session Manager"));
    resize(720, 420);
    setupUi();

    m_sessionsDir = SessionStorage::sessionsDirectory();
    QDir().mkpath(m_sessionsDir);
    if (!m_sessionsDir.isEmpty()) {
        m_watcher.addPath(m_sessionsDir);
        connect(&m_watcher, &QFileSystemWatcher::directoryChanged,
                this, &SessionManagerDialog::refreshSessions);
    }

    refreshSessions();

    Theme::applyTo(this, Theme::sessionManagerContextKey());
}

QVector<SessionStorage::SessionRecord> SessionManagerDialog::sessions() const
{
    return m_sessions;
}

std::optional<SessionStorage::SessionRecord> SessionManagerDialog::selectedSession() const
{
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_sessions.size()) {
        return std::nullopt;
    }
    return m_sessions.at(row);
}

void SessionManagerDialog::setupUi()
{
    auto *layout = new QVBoxLayout(this);

    m_hintLabel = new QLabel(tr("Saved sessions are stored in %1")
                             .arg(SessionStorage::sessionsDirectory()), this);
    m_hintLabel->setWordWrap(true);
    layout->addWidget(m_hintLabel);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({ tr("Start"), tr("End"), tr("Packets"),
                                         tr("Protocols"), tr("Capture File") });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setAlternatingRowColors(true);
    layout->addWidget(m_table);

    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &SessionManagerDialog::updateButtons);
    connect(m_table, &QTableWidget::cellDoubleClicked,
            this, &SessionManagerDialog::openSelectedSession);

    auto *buttonLayout = new QHBoxLayout;
    buttonLayout->addStretch(1);

    m_refreshButton = new QPushButton(tr("Refresh"), this);
    m_openButton = new QPushButton(tr("Open"), this);
    m_openButton->setEnabled(false);

    buttonLayout->addWidget(m_refreshButton);
    buttonLayout->addWidget(m_openButton);

    layout->addLayout(buttonLayout);

    auto *closeBox = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(closeBox, &QDialogButtonBox::rejected, this, &SessionManagerDialog::reject);
    layout->addWidget(closeBox);

    connect(m_refreshButton, &QPushButton::clicked,
            this, &SessionManagerDialog::refreshSessions);
    connect(m_openButton, &QPushButton::clicked,
            this, &SessionManagerDialog::openSelectedSession);
}

void SessionManagerDialog::refreshSessions()
{
    m_sessions = SessionStorage::listSessions();
    m_table->setRowCount(m_sessions.size());

    for (int row = 0; row < m_sessions.size(); ++row) {
        const auto &session = m_sessions.at(row);
        auto *startItem = new QTableWidgetItem(session.startTime.toString(Qt::ISODate));
        auto *endItem   = new QTableWidgetItem(session.endTime.toString(Qt::ISODate));
        auto *packetItem = new QTableWidgetItem(QString::number(session.totalPackets));
        auto *protocolItem = new QTableWidgetItem(session.protocols.join(", "));
        auto *pcapItem = new QTableWidgetItem(session.hasPcap
                                              ? tr("Available")
                                              : tr("Missing"));

        if (!session.hasPcap) {
            const QColor disabledColor = palette().color(QPalette::Disabled, QPalette::Text);
            startItem->setForeground(disabledColor);
            endItem->setForeground(disabledColor);
            packetItem->setForeground(disabledColor);
            protocolItem->setForeground(disabledColor);
            pcapItem->setForeground(disabledColor);
        }

        m_table->setItem(row, 0, startItem);
        m_table->setItem(row, 1, endItem);
        m_table->setItem(row, 2, packetItem);
        m_table->setItem(row, 3, protocolItem);
        m_table->setItem(row, 4, pcapItem);
    }

    updateButtons();
}

void SessionManagerDialog::updateButtons()
{
    const auto selection = selectedSession();
    m_openButton->setEnabled(selection.has_value() && selection->hasPcap);
}

void SessionManagerDialog::openSelectedSession()
{
    if (!m_openButton->isEnabled()) {
        return;
    }
    accept();
}
