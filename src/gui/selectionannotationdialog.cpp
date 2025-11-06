#include "selectionannotationdialog.h"

#include <QAbstractItemView>
#include <QAction>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QColorDialog>
#include <QBrush>

#include <algorithm>

namespace {
const QColor kDefaultHighlightColor(255, 232, 128);
}

SelectionAnnotationDialog::SelectionAnnotationDialog(const QVector<PacketSummary> &packets,
                                                     QWidget *parent)
    : QDialog(parent)
    , m_packets(packets)
{
    setWindowTitle(tr("Report Selection"));
    setModal(true);

    m_summaryLabel = new QLabel(this);
    if (!m_packets.isEmpty()) {
        QVector<int> rows;
        rows.reserve(m_packets.size());
        for (const auto &pkt : m_packets)
            rows.append(pkt.row);
        std::sort(rows.begin(), rows.end());

        QString summary;
        if (rows.size() == 1) {
            summary = tr("Packet #%1").arg(rows.first() + 1);
        } else {
            summary = tr("Packets #%1 – #%2 (%3 items)")
                          .arg(rows.first() + 1)
                          .arg(rows.last() + 1)
                          .arg(rows.size());
        }
        m_summaryLabel->setText(summary);
    }

    m_packetTable = new QTableWidget(this);
    m_packetTable->setColumnCount(7);
    m_packetTable->setHorizontalHeaderLabels({
        tr("No."),
        tr("Time"),
        tr("Source"),
        tr("Destination"),
        tr("Protocol"),
        tr("Info"),
        tr("Tags")
    });
    m_packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->verticalHeader()->setVisible(false);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_packetTable,
            &QTableWidget::customContextMenuRequested,
            this,
            &SelectionAnnotationDialog::showContextMenu);

    m_packetTable->setRowCount(m_packets.size());
    m_packetColors.resize(m_packets.size());
    m_packetTagEdits.resize(m_packets.size());

    for (int row = 0; row < m_packets.size(); ++row) {
        const PacketSummary &pkt = m_packets.at(row);

        auto insertItem = [this, row](int column, const QString &text) {
            auto *item = new QTableWidgetItem(text);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            m_packetTable->setItem(row, column, item);
        };

        insertItem(0, pkt.number);
        insertItem(1, pkt.time);
        insertItem(2, pkt.source);
        insertItem(3, pkt.destination);
        insertItem(4, pkt.protocol);
        insertItem(5, pkt.info);

        auto *tagEdit = new QLineEdit(this);
        tagEdit->setPlaceholderText(tr("Tags for packet %1").arg(pkt.number));
        m_packetTagEdits[row] = tagEdit;
        m_packetTable->setCellWidget(row, 6, tagEdit);

        applyRowColor(row);
    }

    m_titleEdit = new QLineEdit(this);
    m_titleEdit->setPlaceholderText(tr("Short title for this report"));

    m_descriptionEdit = new QTextEdit(this);
    m_descriptionEdit->setPlaceholderText(tr("Describe why this sequence matters…"));
    m_descriptionEdit->setMinimumHeight(100);

    m_threatCombo = new QComboBox(this);
    m_threatCombo->addItems({
        tr("Informational"),
        tr("Benign"),
        tr("Suspicious"),
        tr("Malicious"),
        tr("Critical")
    });

    m_tagsEdit = new QLineEdit(this);
    m_tagsEdit->setPlaceholderText(tr("Global tags (comma separated)"));

    m_actionCombo = new QComboBox(this);
    m_actionCombo->addItems({
        tr("No immediate action"),
        tr("Investigate further"),
        tr("Block related traffic"),
        tr("Notify response team"),
        tr("Escalate incident")
    });

    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                       Qt::Horizontal,
                                       this);
    connect(m_buttonBox, &QDialogButtonBox::accepted, this, &SelectionAnnotationDialog::accept);
    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &SelectionAnnotationDialog::reject);

    auto *form = new QFormLayout;
    form->addRow(tr("Title"), m_titleEdit);
    form->addRow(tr("Description"), m_descriptionEdit);
    form->addRow(tr("Threat level"), m_threatCombo);
    form->addRow(tr("Global tags"), m_tagsEdit);
    form->addRow(tr("Recommended action"), m_actionCombo);

    auto *contentLayout = new QHBoxLayout;
    contentLayout->addWidget(m_packetTable, 3);
    contentLayout->addLayout(form, 2);
    contentLayout->setStretch(0, 3);
    contentLayout->setStretch(1, 2);
    contentLayout->setSpacing(16);
    contentLayout->setAlignment(form, Qt::AlignTop);

    auto *layout = new QVBoxLayout;
    if (!m_summaryLabel->text().isEmpty())
        layout->addWidget(m_summaryLabel);
    layout->addLayout(contentLayout);
    layout->addWidget(m_buttonBox);

    setLayout(layout);
}

SelectionAnnotationDialog::Result SelectionAnnotationDialog::result() const
{
    Result res;
    res.title = m_titleEdit->text();
    res.description = m_descriptionEdit->toPlainText();
    res.threatLevel = m_threatCombo->currentText();
    res.recommendedAction = m_actionCombo->currentText();

    QStringList baseTags = splitTags(m_tagsEdit->text());
    const QString autoTag = defaultTagForThreat();
    if (!autoTag.isEmpty())
        baseTags.prepend(autoTag);
    baseTags.removeDuplicates();
    res.tags = baseTags;

    res.packets.reserve(m_packets.size());
    for (int i = 0; i < m_packets.size(); ++i) {
        Result::PacketDetail detail;
        detail.row = m_packets.at(i).row;

        QStringList perPacketTags = baseTags;
        if (i < m_packetTagEdits.size() && m_packetTagEdits.at(i)) {
            const QString text = m_packetTagEdits.at(i)->text();
            const QStringList extra = splitTags(text);
            for (const QString &tag : extra)
                perPacketTags.append(tag);
        }
        perPacketTags.removeDuplicates();
        detail.tags = perPacketTags;

        if (i < m_packetColors.size())
            detail.color = m_packetColors.at(i);

        res.packets.append(detail);
    }

    return res;
}

void SelectionAnnotationDialog::showContextMenu(const QPoint &pos)
{
    if (!m_packetTable)
        return;

    const QModelIndex index = m_packetTable->indexAt(pos);
    if (index.isValid() && !m_packetTable->selectionModel()->isSelected(index)) {
        m_packetTable->selectionModel()->select(
            index,
            QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    const QModelIndexList selectedRows = m_packetTable->selectionModel()->selectedRows();
    if (selectedRows.isEmpty())
        return;

    QMenu menu(this);
    QAction *highlightAction = menu.addAction(tr("Highlight…"));
    QAction *clearHighlightAction = menu.addAction(tr("Clear highlight"));

    QAction *chosen = menu.exec(m_packetTable->viewport()->mapToGlobal(pos));
    if (!chosen)
        return;

    QList<int> rows;
    rows.reserve(selectedRows.size());
    for (const QModelIndex &selected : selectedRows)
        rows.append(selected.row());

    if (chosen == highlightAction) {
        QColor initialColor;
        for (int r : rows) {
            if (r >= 0 && r < m_packetColors.size()) {
                initialColor = m_packetColors.at(r);
                if (initialColor.isValid())
                    break;
            }
        }
        if (!initialColor.isValid())
            initialColor = kDefaultHighlightColor;

        const QColor color = QColorDialog::getColor(initialColor,
                                                    this,
                                                    tr("Choose highlight color"));
        if (!color.isValid())
            return;

        for (int r : rows) {
            if (r < 0 || r >= m_packetColors.size())
                continue;
            m_packetColors[r] = color;
            applyRowColor(r);
        }
    } else if (chosen == clearHighlightAction) {
        for (int r : rows) {
            if (r < 0 || r >= m_packetColors.size())
                continue;
            m_packetColors[r] = QColor();
            applyRowColor(r);
        }
    }
}

QStringList SelectionAnnotationDialog::splitTags(const QString &text) const
{
    QStringList tags;
    const QStringList parts = text.split(',', Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        const QString trimmed = part.trimmed();
        if (!trimmed.isEmpty())
            tags << trimmed;
    }
    return tags;
}

QString SelectionAnnotationDialog::defaultTagForThreat() const
{
    const QString threat = m_threatCombo->currentText();
    if (threat.compare(tr("Benign"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("safe");
    }
    if (threat.compare(tr("Suspicious"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("suspicious");
    }
    if (threat.compare(tr("Malicious"), Qt::CaseInsensitive) == 0 ||
        threat.compare(tr("Critical"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("malware");
    }
    return QString();
}

void SelectionAnnotationDialog::applyRowColor(int row)
{
    if (!m_packetTable || row < 0 || row >= m_packetTable->rowCount())
        return;

    const QColor color = m_packetColors.value(row);
    if (!color.isValid()) {
        for (int column = 0; column < 6; ++column) {
            if (auto *item = m_packetTable->item(row, column)) {
                item->setBackground(QBrush());
                item->setForeground(QBrush());
            }
        }
        if (auto *tagEdit = m_packetTagEdits.value(row, nullptr))
            tagEdit->setStyleSheet(QString());
        return;
    }

    const QColor foreground = (color.lightness() < 128)
        ? QColor(Qt::white)
        : QColor(Qt::black);

    for (int column = 0; column < 6; ++column) {
        if (auto *item = m_packetTable->item(row, column)) {
            item->setBackground(color);
            item->setForeground(foreground);
        }
    }

    if (auto *tagEdit = m_packetTagEdits.value(row, nullptr)) {
        const QString tagStyle = QStringLiteral(
                                       "QLineEdit { background-color: %1; color: %2; } "
                                       "QLineEdit::placeholder { color: %2; }")
                                     .arg(color.name())
                                     .arg(foreground.name());
        tagEdit->setStyleSheet(tagStyle);
    }
}
