#include "anomalyinspectordialog.h"

#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTreeWidgetItem>
#include <QSet>
#include <QVariant>
#include <QMetaType>

#include <algorithm>

namespace {
QString joinReasons(const QStringList &reasons)
{
    return reasons.join(QStringLiteral("\n • "));
}

QString formatDetails(const QVariantMap &details)
{
    if (details.isEmpty()) {
        return QString();
    }

    QStringList keys = details.keys();
    std::sort(keys.begin(), keys.end());

    QStringList lines;
    for (const QString &key : keys) {
        const QVariant value = details.value(key);
        if (value.typeId() == QMetaType::QStringList) {
            lines << QStringLiteral("%1: %2").arg(key, value.toStringList().join(QStringLiteral(", ")));
        } else if (value.typeId() == QMetaType::QVariantList) {
            QStringList nested;
            const QVariantList list = value.toList();
            for (const QVariant &entry : list) {
                if (entry.canConvert<QVariantMap>()) {
                    QStringList pairs;
                    const QVariantMap map = entry.toMap();
                    const QStringList mapKeys = map.keys();
                    for (const QString &mapKey : mapKeys) {
                        pairs << QStringLiteral("%1=%2").arg(mapKey, map.value(mapKey).toString());
                    }
                    nested << QStringLiteral("{%1}").arg(pairs.join(QStringLiteral(", ")));
                } else {
                    nested << entry.toString();
                }
            }
            lines << QStringLiteral("%1: %2").arg(key, nested.join(QStringLiteral(", ")));
        } else {
            lines << QStringLiteral("%1: %2").arg(key, value.toString());
        }
    }
    return lines.join(QLatin1Char('\n'));
}
} // namespace

AnomalyInspectorDialog::AnomalyInspectorDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Anomaly Inspector"));
    resize(760, 540);

    auto *mainLayout = new QVBoxLayout(this);

    auto *filterLayout = new QHBoxLayout;
    auto *categoryLabel = new QLabel(tr("Category:"));
    m_categoryCombo = new QComboBox;
    m_categoryCombo->addItem(tr("All categories"), QString());
    m_searchEdit = new QLineEdit;
    m_searchEdit->setPlaceholderText(tr("Filter text…"));
    filterLayout->addWidget(categoryLabel);
    filterLayout->addWidget(m_categoryCombo);
    filterLayout->addWidget(m_searchEdit);
    mainLayout->addLayout(filterLayout);

    m_eventTree = new QTreeWidget;
    m_eventTree->setColumnCount(4);
    m_eventTree->setHeaderLabels({tr("Time (s)"), tr("Score"), tr("Tags"), tr("Summary")});
    m_eventTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_eventTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_eventTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_eventTree->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_eventTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_eventTree->setRootIsDecorated(false);
    mainLayout->addWidget(m_eventTree);

    m_detailsView = new QPlainTextEdit;
    m_detailsView->setReadOnly(true);
    m_detailsView->setMinimumHeight(140);
    mainLayout->addWidget(m_detailsView);

    auto *buttonLayout = new QHBoxLayout;
    m_focusButton = new QPushButton(tr("Focus Packets"));
    m_focusButton->setEnabled(false);
    auto *closeButton = new QPushButton(tr("Close"));
    buttonLayout->addWidget(m_focusButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);
    mainLayout->addLayout(buttonLayout);

    connect(closeButton, &QPushButton::clicked,
            this, &QDialog::close);
    connect(m_focusButton, &QPushButton::clicked,
            this, &AnomalyInspectorDialog::onFocusRequested);
    connect(m_categoryCombo, &QComboBox::currentTextChanged,
            this, &AnomalyInspectorDialog::applyFilter);
    connect(m_searchEdit, &QLineEdit::textChanged,
            this, &AnomalyInspectorDialog::applyFilter);
    connect(m_eventTree, &QTreeWidget::currentItemChanged,
            this, &AnomalyInspectorDialog::onSelectionChanged);
    connect(m_eventTree, &QTreeWidget::itemDoubleClicked,
            this, [this](QTreeWidgetItem *, int) { onFocusRequested(); });
}

void AnomalyInspectorDialog::setEvents(const QVector<AnomalyDetector::Event> &events)
{
    m_events = events;
    rebuildCategoryFilter();
    applyFilter();
}

void AnomalyInspectorDialog::applyFilter()
{
    const QString tagFilter = m_categoryCombo->currentData().toString();
    const QString textFilter = m_searchEdit->text().trimmed();

    m_eventTree->clear();
    m_filteredEvents.clear();

    const Qt::CaseSensitivity cs = Qt::CaseInsensitive;

    for (const auto &event : m_events) {
        if (!tagFilter.isEmpty() && !event.tags.contains(tagFilter)) {
            continue;
        }

        if (!textFilter.isEmpty()) {
            const QString haystack = event.summary
                + QLatin1Char('\n') + event.reasons.join(QStringLiteral("\n"))
                + QLatin1Char('\n') + event.tags.join(QStringLiteral(" "));
            if (!haystack.contains(textFilter, cs)) {
                continue;
            }
        }

        const int filteredIndex = m_filteredEvents.size();
        m_filteredEvents.append(event);

        auto *item = new QTreeWidgetItem(m_eventTree);
        item->setText(0, QString::number(event.second));
        item->setText(1, QString::number(event.score, 'f', 2));
        item->setText(2, event.tags.join(QStringLiteral(", ")));
        item->setText(3, event.summary);
        item->setData(0, Qt::UserRole, filteredIndex);
    }

    if (m_eventTree->topLevelItemCount() > 0) {
        m_eventTree->setCurrentItem(m_eventTree->topLevelItem(0));
    } else {
        m_detailsView->clear();
        m_focusButton->setEnabled(false);
    }
}

void AnomalyInspectorDialog::onSelectionChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!current) {
        m_detailsView->clear();
        m_focusButton->setEnabled(false);
        return;
    }

    const int filteredIndex = current->data(0, Qt::UserRole).toInt();
    updateDetails(filteredIndex);
}

void AnomalyInspectorDialog::onFocusRequested()
{
    QTreeWidgetItem *current = m_eventTree->currentItem();
    if (!current) {
        return;
    }
    const int filteredIndex = current->data(0, Qt::UserRole).toInt();
    if (filteredIndex < 0 || filteredIndex >= m_filteredEvents.size()) {
        return;
    }
    const QVector<int> rows = m_filteredEvents.at(filteredIndex).packetRows;
    if (!rows.isEmpty()) {
        emit requestFocusPackets(rows);
    }
}

void AnomalyInspectorDialog::rebuildCategoryFilter()
{
    QSet<QString> tags;
    for (const auto &event : m_events) {
        for (const QString &tag : event.tags) {
            tags.insert(tag);
        }
    }

    const QString previous = m_categoryCombo->currentData().toString();

    m_categoryCombo->blockSignals(true);
    m_categoryCombo->clear();
    m_categoryCombo->addItem(tr("All categories"), QString());

    QStringList sortedTags = tags.values();
    std::sort(sortedTags.begin(), sortedTags.end());
    for (const QString &tag : sortedTags) {
        m_categoryCombo->addItem(tag, tag);
    }

    int index = m_categoryCombo->findData(previous);
    if (index == -1) {
        index = 0;
    }
    m_categoryCombo->setCurrentIndex(index);
    m_categoryCombo->blockSignals(false);
}

void AnomalyInspectorDialog::updateDetails(int filteredIndex)
{
    if (filteredIndex < 0 || filteredIndex >= m_filteredEvents.size()) {
        m_detailsView->clear();
        m_focusButton->setEnabled(false);
        return;
    }

    const AnomalyDetector::Event &event = m_filteredEvents.at(filteredIndex);

    QStringList sections;
    sections << tr("Summary: %1").arg(event.summary);
    sections << tr("Score: %1").arg(event.score, 0, 'f', 2);
    if (!event.tags.isEmpty()) {
        sections << tr("Tags: %1").arg(event.tags.join(QStringLiteral(", ")));
    }

    if (!event.reasons.isEmpty()) {
        sections << QString();
        sections << tr("Reasons:");
        sections << QStringLiteral(" • %1").arg(joinReasons(event.reasons));
    }

    const QString detailText = formatDetails(event.details);
    if (!detailText.isEmpty()) {
        sections << QString();
        sections << tr("Details:");
        sections << detailText;
    }

    m_detailsView->setPlainText(sections.join(QLatin1Char('\n')));
    m_focusButton->setEnabled(!event.packetRows.isEmpty());
}
