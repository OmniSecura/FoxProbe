#include "followstreamdialog.h"

#include "payloadformatter.h"
#include "protocols/proto_struct.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QTimeZone>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFile>
#include <QFontDatabase>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLocale>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextStream>
#include <QVBoxLayout>
#include <QStringList>

namespace {
QString formatEndpoint(const Sniffing::StreamEndpoint &endpoint)
{
    return QStringLiteral("%1:%2").arg(endpoint.address, QString::number(endpoint.port));
}
}

FollowStreamDialog::FollowStreamDialog(Sniffing *sniffer, QWidget *parent)
    : QDialog(parent)
    , m_sniffer(sniffer)
{
    setWindowTitle(tr("Follow Stream"));
    resize(1000, 650);
    initializeUI();
    ensurePayloadFont();
    updateSearchControls();
}

void FollowStreamDialog::initializeUI()
{
    auto *mainLayout = new QHBoxLayout(this);

    // Left side – list of streams and quick actions
    auto *leftLayout = new QVBoxLayout;

    filterEdit = new QLineEdit(this);
    filterEdit->setPlaceholderText(tr("Filter streams (address, port, protocol)…"));
    connect(filterEdit, &QLineEdit::textChanged, this, &FollowStreamDialog::onFilterTextChanged);
    leftLayout->addWidget(filterEdit);

    streamList = new QListWidget(this);
    streamList->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(streamList, &QListWidget::currentRowChanged,
            this, &FollowStreamDialog::onStreamSelectionChanged);
    leftLayout->addWidget(streamList, 1);

    directionLabel = new QLabel(this);
    directionLabel->setWordWrap(true);
    leftLayout->addWidget(directionLabel);

    statsLabel = new QLabel(this);
    statsLabel->setWordWrap(true);
    leftLayout->addWidget(statsLabel);

    auto *leftButtons = new QHBoxLayout;
    refreshButton = new QPushButton(tr("Refresh"), this);
    connect(refreshButton, &QPushButton::clicked, this, &FollowStreamDialog::reloadStreams);
    resetButton = new QPushButton(tr("Reset"), this);
    connect(resetButton, &QPushButton::clicked, this, &FollowStreamDialog::clearStreams);
    leftButtons->addWidget(refreshButton);
    leftButtons->addWidget(resetButton);
    leftButtons->addStretch();
    leftLayout->addLayout(leftButtons);

    mainLayout->addLayout(leftLayout, 1);

    // Right side – options, payload view, actions
    auto *rightLayout = new QVBoxLayout;

    auto *optionsLayout = new QGridLayout;
    optionsLayout->addWidget(new QLabel(tr("Direction:"), this), 0, 0);
    directionCombo = new QComboBox(this);
    connect(directionCombo, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(directionCombo, 0, 1);

    optionsLayout->addWidget(new QLabel(tr("Format:"), this), 0, 2);
    formatCombo = new QComboBox(this);
    formatCombo->addItem(tr("Plain ASCII"));
    formatCombo->addItem(tr("Hex Dump"));
    formatCombo->addItem(tr("ASCII + Hex Table"));
    formatCombo->addItem(tr("C Escaped"));
    formatCombo->addItem(tr("Base64"));
    connect(formatCombo, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(formatCombo, 0, 3);

    metadataCheck = new QCheckBox(tr("Show metadata"), this);
    metadataCheck->setChecked(true);
    connect(metadataCheck, &QCheckBox::toggled, this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(metadataCheck, 1, 0, 1, 2);

    showEmptyCheck = new QCheckBox(tr("Include empty packets"), this);
    connect(showEmptyCheck, &QCheckBox::toggled, this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(showEmptyCheck, 1, 2, 1, 2);

    relativeTimeCheck = new QCheckBox(tr("Relative timestamps"), this);
    relativeTimeCheck->setChecked(true);
    connect(relativeTimeCheck, &QCheckBox::toggled, this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(relativeTimeCheck, 2, 0, 1, 2);

    wrapCheck = new QCheckBox(tr("Wrap lines"), this);
    connect(wrapCheck, &QCheckBox::toggled, this, &FollowStreamDialog::updatePayload);
    optionsLayout->addWidget(wrapCheck, 2, 2, 1, 2);

    rightLayout->addLayout(optionsLayout);

    auto *searchLayout = new QGridLayout;
    searchLayout->addWidget(new QLabel(tr("Search:"), this), 0, 0);
    searchEdit = new QLineEdit(this);
    connect(searchEdit, &QLineEdit::textChanged, this, &FollowStreamDialog::updateSearchControls);
    connect(searchEdit, &QLineEdit::returnPressed, this, &FollowStreamDialog::findNext);
    searchLayout->addWidget(searchEdit, 0, 1, 1, 2);

    caseSensitiveCheck = new QCheckBox(tr("Case sensitive"), this);
    connect(caseSensitiveCheck, &QCheckBox::toggled, this, &FollowStreamDialog::updateSearchControls);
    searchLayout->addWidget(caseSensitiveCheck, 0, 3);

    findPrevButton = new QPushButton(tr("Find Previous"), this);
    connect(findPrevButton, &QPushButton::clicked, this, &FollowStreamDialog::findPrevious);
    searchLayout->addWidget(findPrevButton, 1, 1);

    findNextButton = new QPushButton(tr("Find Next"), this);
    connect(findNextButton, &QPushButton::clicked, this, &FollowStreamDialog::findNext);
    searchLayout->addWidget(findNextButton, 1, 2);
    searchLayout->setColumnStretch(1, 1);
    searchLayout->setColumnStretch(2, 1);

    rightLayout->addLayout(searchLayout);

    payloadView = new QPlainTextEdit(this);
    payloadView->setReadOnly(true);
    payloadView->setLineWrapMode(QPlainTextEdit::NoWrap);
    rightLayout->addWidget(payloadView, 1);

    auto *actionsLayout = new QHBoxLayout;
    copyButton = new QPushButton(tr("Copy"), this);
    connect(copyButton, &QPushButton::clicked, this, &FollowStreamDialog::copyToClipboard);
    copyButton->setEnabled(false);
    actionsLayout->addWidget(copyButton);

    saveButton = new QPushButton(tr("Save As…"), this);
    connect(saveButton, &QPushButton::clicked, this, &FollowStreamDialog::saveToFile);
    saveButton->setEnabled(false);
    actionsLayout->addWidget(saveButton);
    actionsLayout->addStretch();
    rightLayout->addLayout(actionsLayout);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &FollowStreamDialog::reject);
    rightLayout->addWidget(buttonBox);

    mainLayout->addLayout(rightLayout, 2);
}

void FollowStreamDialog::ensurePayloadFont()
{
    if (!payloadView)
        return;
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    payloadView->setFont(font);
}

void FollowStreamDialog::setStreams(const QVector<Sniffing::StreamConversation> &streams)
{
    m_streams = streams;
    populateStreamList();
    selectDefaultStream();
    updatePayload();
}

void FollowStreamDialog::populateStreamList()
{
    if (!streamList)
        return;

    const QString filter = filterEdit ? filterEdit->text().trimmed() : QString();
    streamList->clear();
    m_filteredIndices.clear();

    Qt::CaseSensitivity cs = Qt::CaseInsensitive;
    QLocale locale;

    for (int i = 0; i < m_streams.size(); ++i) {
        const auto &conv = m_streams.at(i);
        QString label = conv.label();
        QString endpoints = QStringLiteral("%1 ⇄ %2")
            .arg(formatEndpoint(conv.endpointA), formatEndpoint(conv.endpointB));
        QString meta = QStringLiteral("%1 packets | %2 → %3: %4 B | %3 → %2: %5 B")
            .arg(locale.toString(conv.packetCount))
            .arg(formatEndpoint(conv.endpointA))
            .arg(formatEndpoint(conv.endpointB))
            .arg(locale.toString(conv.totalBytesAToB))
            .arg(locale.toString(conv.totalBytesBToA));

        QString searchable = label + ' ' + endpoints + ' ' + meta;
        if (!filter.isEmpty() && !searchable.contains(filter, cs))
            continue;

        auto *item = new QListWidgetItem(QStringLiteral("%1\n%2\n%3")
                                              .arg(label, endpoints, meta), streamList);
        item->setData(Qt::UserRole, i);
        m_filteredIndices.append(i);
    }

    if (streamList->count() == 0) {
        statsLabel->setText(tr("No streams available."));
        directionLabel->clear();
    }
}

void FollowStreamDialog::selectDefaultStream()
{
    if (!streamList)
        return;
    if (streamList->count() > 0) {
        if (streamList->currentRow() < 0)
            streamList->setCurrentRow(0);
    }
    else {
        streamList->setCurrentRow(-1);
    }
}

int FollowStreamDialog::currentStreamIndex() const
{
    if (!streamList)
        return -1;
    if (auto *item = streamList->currentItem())
        return item->data(Qt::UserRole).toInt();
    return -1;
}

void FollowStreamDialog::onStreamSelectionChanged()
{
    const int index = currentStreamIndex();
    if (index < 0 || index >= m_streams.size()) {
        payloadView->clear();
        statsLabel->setText(tr("No streams available."));
        directionCombo->clear();
        return;
    }

    updateDirectionCombo(m_streams.at(index));
    updatePayload();
}

void FollowStreamDialog::updateDirectionCombo(const Sniffing::StreamConversation &conv)
{
    if (!directionCombo)
        return;

    const QString a = formatEndpoint(conv.endpointA);
    const QString b = formatEndpoint(conv.endpointB);

    directionCombo->blockSignals(true);
    directionCombo->clear();
    directionCombo->addItem(tr("Both directions"));
    directionCombo->addItem(tr("%1 → %2").arg(a, b));
    directionCombo->addItem(tr("%1 → %2").arg(b, a));
    directionCombo->setCurrentIndex(0);
    directionCombo->blockSignals(false);

    QString initiator = conv.initiatorIsA ? a : b;
    directionLabel->setText(tr("%1\nInitiator: %2")
                            .arg(conv.label(), initiator));
}

bool FollowStreamDialog::shouldIncludeSegment(const Sniffing::StreamSegment &segment) const
{
    return showEmptyCheck && showEmptyCheck->isChecked() ? true : !segment.payload.isEmpty();
}

QString FollowStreamDialog::currentDirectionString(const Sniffing::StreamConversation &conv, bool fromAtoB) const
{
    const QString a = formatEndpoint(conv.endpointA);
    const QString b = formatEndpoint(conv.endpointB);
    return fromAtoB ? QStringLiteral("%1 → %2").arg(a, b)
                    : QStringLiteral("%1 → %2").arg(b, a);
}

QString FollowStreamDialog::tcpFlagsToString(quint8 flags) const
{
    QStringList parts;
    if (flags & TH_FIN) parts << QStringLiteral("FIN");
    if (flags & TH_SYN) parts << QStringLiteral("SYN");
    if (flags & TH_RST) parts << QStringLiteral("RST");
    if (flags & TH_PUSH) parts << QStringLiteral("PSH");
    if (flags & TH_ACK) parts << QStringLiteral("ACK");
    if (flags & TH_URG) parts << QStringLiteral("URG");
#ifdef TH_ECE
    if (flags & TH_ECE) parts << QStringLiteral("ECE");
#endif
#ifdef TH_CWR
    if (flags & TH_CWR) parts << QStringLiteral("CWR");
#endif
    if (parts.isEmpty())
        return QStringLiteral("0x%1").arg(flags, 2, 16, QLatin1Char('0')).toUpper();
    return parts.join(QLatin1Char('|'));
}

QString FollowStreamDialog::buildSegmentBlock(const Sniffing::StreamConversation &conv,
                                              const Sniffing::StreamSegment &segment,
                                              qint64 baseSec,
                                              qint64 baseUsec) const
{
    QStringList lines;
    if (metadataCheck && metadataCheck->isChecked()) {
        QString timestamp;
        if (relativeTimeCheck && relativeTimeCheck->isChecked()) {
            qint64 secDiff = segment.timestampSeconds - baseSec;
            qint64 usecDiff = segment.timestampMicros - baseUsec;
            double delta = double(secDiff) + double(usecDiff) / 1'000'000.0;
            timestamp = QStringLiteral("+%1 s").arg(delta, 0, 'f', 6);
        } else {
            QDateTime dt = QDateTime::fromSecsSinceEpoch(segment.timestampSeconds, QTimeZone::UTC);
            dt = dt.addMSecs(segment.timestampMicros / 1000.0);
            timestamp = dt.toString(Qt::ISODateWithMs);
        }
        QString header = QStringLiteral("[%1] %2  payload=%3 B")
            .arg(timestamp,
                 currentDirectionString(conv, segment.fromAtoB))
            .arg(segment.payloadLength);
        if (segment.isTcp) {
            header += QStringLiteral("  seq=%1 ack=%2 win=%3 flags=%4")
                .arg(segment.sequenceNumber)
                .arg(segment.acknowledgementNumber)
                .arg(segment.windowSize)
                .arg(tcpFlagsToString(segment.tcpFlags));
        }
        lines << header;
    }

    if (!segment.payload.isEmpty())
        lines << formatPayload(segment.payload);

    return lines.join(QLatin1Char('\n'));
}

QString FollowStreamDialog::formatPayload(const QByteArray &payload) const
{
    if (!formatCombo)
        return QString();

    switch (static_cast<FormatMode>(formatCombo->currentIndex())) {
    case Ascii:
        return PayloadFormatter::toAscii(payload);
    case HexDump:
        return formatHexDump(payload);
    case AsciiHexTable:
        return formatAsciiHexTable(payload);
    case CEscaped:
        return formatEscaped(payload);
    case Base64:
        return QString::fromLatin1(payload.toBase64());
    }
    return {};
}

QString FollowStreamDialog::formatHexDump(const QByteArray &payload) const
{
    if (payload.isEmpty())
        return {};

    QString output;
    QTextStream stream(&output);
    const int lineWidth = 16;
    for (int offset = 0; offset < payload.size(); offset += lineWidth) {
        QByteArray chunk = payload.mid(offset, lineWidth);
        stream << QStringLiteral("%1  ").arg(offset, 6, 16, QLatin1Char('0')).toUpper();
        for (int i = 0; i < chunk.size(); ++i) {
            stream << QStringLiteral("%1 ").arg(static_cast<unsigned char>(chunk[i]), 2, 16, QLatin1Char('0')).toUpper();
        }
        stream << '\n';
    }
    return output.trimmed();
}

QString FollowStreamDialog::formatAsciiHexTable(const QByteArray &payload) const
{
    if (payload.isEmpty())
        return {};

    QString output;
    QTextStream stream(&output);
    const int lineWidth = 16;
    for (int offset = 0; offset < payload.size(); offset += lineWidth) {
        QByteArray chunk = payload.mid(offset, lineWidth);
        stream << QStringLiteral("%1  ").arg(offset, 6, 16, QLatin1Char('0')).toUpper();
        for (int i = 0; i < chunk.size(); ++i) {
            stream << QStringLiteral("%1 ").arg(static_cast<unsigned char>(chunk[i]), 2, 16, QLatin1Char('0')).toUpper();
            if (i == 7)
                stream << ' ';
        }
        if (chunk.size() < lineWidth) {
            const int missing = lineWidth - chunk.size();
            for (int i = 0; i < missing; ++i) {
                stream << "   ";
                if (chunk.size() + i == 7)
                    stream << ' ';
            }
        }
        stream << " |" << PayloadFormatter::toAscii(chunk) << "|\n";
    }
    return output.trimmed();
}

QString FollowStreamDialog::formatEscaped(const QByteArray &payload) const
{
    if (payload.isEmpty())
        return {};

    QString output;
    output.reserve(payload.size() * 4);
    for (unsigned char ch : payload) {
        switch (ch) {
        case '\\': output += QLatin1String("\\\\"); break;
        case '\n': output += QLatin1String("\\n"); break;
        case '\r': output += QLatin1String("\\r"); break;
        case '\t': output += QLatin1String("\\t"); break;
        case '\"': output += QLatin1String("\\\""); break;
        default:
            if (ch >= 0x20 && ch <= 0x7E) {
                output.append(QChar::fromLatin1(static_cast<char>(ch)));
            } else {
                output += QStringLiteral("\\x%1").arg(ch, 2, 16, QLatin1Char('0')).toUpper();
            }
        }
    }
    return output;
}

void FollowStreamDialog::updateStats(const Sniffing::StreamConversation &conv)
{
    if (!statsLabel)
        return;

    int packetsAToB = 0;
    int packetsBToA = 0;
    for (const auto &segment : conv.segments) {
        if (segment.fromAtoB)
            ++packetsAToB;
        else
            ++packetsBToA;
    }

    double duration = 0.0;
    if (conv.packetCount > 0) {
        qint64 secDiff = conv.lastTimestampSec - conv.firstTimestampSec;
        qint64 usecDiff = conv.lastTimestampUsec - conv.firstTimestampUsec;
        duration = double(secDiff) + double(usecDiff) / 1'000'000.0;
    }

    QLocale locale;
    const QString a = formatEndpoint(conv.endpointA);
    const QString b = formatEndpoint(conv.endpointB);
    QString summary = tr("Packets %1 (%2 → %3: %4, %3 → %2: %5)\nBytes %6 → %7 | Duration %8 s")
        .arg(locale.toString(conv.packetCount))
        .arg(a)
        .arg(b)
        .arg(locale.toString(packetsAToB))
        .arg(locale.toString(packetsBToA))
        .arg(locale.toString(conv.totalBytesAToB))
        .arg(locale.toString(conv.totalBytesBToA))
        .arg(locale.toString(duration, 'f', 6));
    statsLabel->setText(summary);
}

void FollowStreamDialog::updatePayload()
{
    if (!payloadView)
        return;

    payloadView->setLineWrapMode(wrapCheck && wrapCheck->isChecked()
                                 ? QPlainTextEdit::WidgetWidth
                                 : QPlainTextEdit::NoWrap);

    const int index = currentStreamIndex();
    if (index < 0 || index >= m_streams.size()) {
        payloadView->setPlainText(tr("No streams available."));
        copyButton->setEnabled(false);
        saveButton->setEnabled(false);
        return;
    }

    const auto &conv = m_streams.at(index);
    updateStats(conv);

    qint64 baseSec = conv.segments.isEmpty() ? 0 : conv.segments.first().timestampSeconds;
    qint64 baseUsec = conv.segments.isEmpty() ? 0 : conv.segments.first().timestampMicros;
    const int directionMode = directionCombo ? directionCombo->currentIndex() : 0;

    QStringList blocks;
    blocks.reserve(conv.segments.size());
    for (const auto &segment : conv.segments) {
        if (directionMode == 1 && !segment.fromAtoB)
            continue;
        if (directionMode == 2 && segment.fromAtoB)
            continue;
        if (!shouldIncludeSegment(segment))
            continue;
        QString block = buildSegmentBlock(conv, segment, baseSec, baseUsec);
        if (!block.isEmpty())
            blocks << block;
    }

    if (blocks.isEmpty()) {
        payloadView->setPlainText(tr("No payload data available for the selected options."));
    } else {
        QString text;
        for (int i = 0; i < blocks.size(); ++i) {
            if (i != 0)
                text += QLatin1String("\n\n");
            text += blocks.at(i);
        }
        payloadView->setPlainText(text);
    }

    const bool hasContent = !payloadView->document()->isEmpty();
    if (copyButton)
        copyButton->setEnabled(hasContent);
    if (saveButton)
        saveButton->setEnabled(hasContent);
    updateSearchControls();
}

void FollowStreamDialog::onFilterTextChanged(const QString &)
{
    populateStreamList();
    selectDefaultStream();
    updatePayload();
}

void FollowStreamDialog::copyToClipboard()
{
    if (!payloadView || payloadView->document()->isEmpty())
        return;
    QApplication::clipboard()->setText(payloadView->toPlainText());
}

void FollowStreamDialog::saveToFile()
{
    if (!payloadView || payloadView->document()->isEmpty())
        return;

    const QString fileName = QFileDialog::getSaveFileName(
        this, tr("Save Stream Payload"), QString(), tr("Text Files (*.txt);;All Files (*)"));
    if (fileName.isEmpty())
        return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return;

    QTextStream stream(&file);
    stream << payloadView->toPlainText();
}

void FollowStreamDialog::findNext()
{
    if (!payloadView)
        return;
    const QString needle = searchEdit ? searchEdit->text() : QString();
    if (needle.isEmpty())
        return;

    QTextDocument::FindFlags flags;
    if (caseSensitiveCheck && caseSensitiveCheck->isChecked())
        flags |= QTextDocument::FindCaseSensitively;

    if (!payloadView->find(needle, flags)) {
        QTextCursor cursor = payloadView->textCursor();
        cursor.movePosition(QTextCursor::Start);
        payloadView->setTextCursor(cursor);
        payloadView->find(needle, flags);
    }
}

void FollowStreamDialog::findPrevious()
{
    if (!payloadView)
        return;
    const QString needle = searchEdit ? searchEdit->text() : QString();
    if (needle.isEmpty())
        return;

    QTextDocument::FindFlags flags = QTextDocument::FindBackward;
    if (caseSensitiveCheck && caseSensitiveCheck->isChecked())
        flags |= QTextDocument::FindCaseSensitively;

    if (!payloadView->find(needle, flags)) {
        QTextCursor cursor = payloadView->textCursor();
        cursor.movePosition(QTextCursor::End);
        payloadView->setTextCursor(cursor);
        payloadView->find(needle, flags);
    }
}

void FollowStreamDialog::reloadStreams()
{
    if (!m_sniffer)
        return;
    setStreams(m_sniffer->getStreamConversations());
}

void FollowStreamDialog::clearStreams()
{
    if (m_sniffer)
        m_sniffer->resetStreams();
    setStreams(m_sniffer ? m_sniffer->getStreamConversations() : QVector<Sniffing::StreamConversation>());
}

void FollowStreamDialog::updateSearchControls()
{
    const bool hasText = searchEdit && !searchEdit->text().isEmpty();
    if (findNextButton)
        findNextButton->setEnabled(hasText);
    if (findPrevButton)
        findPrevButton->setEnabled(hasText);
    if (caseSensitiveCheck)
        caseSensitiveCheck->setEnabled(hasText);
}
