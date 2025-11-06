#ifndef FOLLOWSTREAMDIALOG_H
#define FOLLOWSTREAMDIALOG_H

#include <QDialog>
#include <QVector>
#include "packets/sniffing.h"

class QListWidget;
class QPlainTextEdit;
class QComboBox;
class QCheckBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QDialogButtonBox;

class FollowStreamDialog : public QDialog
{
    Q_OBJECT
public:
    explicit FollowStreamDialog(Sniffing *sniffer, QWidget *parent = nullptr);

    void setStreams(const QVector<Sniffing::StreamConversation> &streams);

private slots:
    void onStreamSelectionChanged();
    void updatePayload();
    void onFilterTextChanged(const QString &text);
    void copyToClipboard();
    void saveToFile();
    void findNext();
    void findPrevious();
    void reloadStreams();
    void clearStreams();
    void updateSearchControls();

private:
    enum FormatMode {
        Ascii = 0,
        HexDump,
        AsciiHexTable,
        CEscaped,
        Base64
    };

    Sniffing *m_sniffer = nullptr;
    QVector<Sniffing::StreamConversation> m_streams;
    QVector<int> m_filteredIndices;

    QListWidget *streamList = nullptr;
    QPlainTextEdit *payloadView = nullptr;
    QComboBox *directionCombo = nullptr;
    QComboBox *formatCombo = nullptr;
    QCheckBox *metadataCheck = nullptr;
    QCheckBox *wrapCheck = nullptr;
    QCheckBox *showEmptyCheck = nullptr;
    QCheckBox *relativeTimeCheck = nullptr;
    QLineEdit *filterEdit = nullptr;
    QLineEdit *searchEdit = nullptr;
    QCheckBox *caseSensitiveCheck = nullptr;
    QLabel *statsLabel = nullptr;
    QLabel *directionLabel = nullptr;
    QPushButton *findNextButton = nullptr;
    QPushButton *findPrevButton = nullptr;
    QPushButton *copyButton = nullptr;
    QPushButton *saveButton = nullptr;
    QPushButton *refreshButton = nullptr;
    QPushButton *resetButton = nullptr;

    void initializeUI();
    void populateStreamList();
    void selectDefaultStream();
    int currentStreamIndex() const;
    bool shouldIncludeSegment(const Sniffing::StreamSegment &segment) const;
    QString buildSegmentBlock(const Sniffing::StreamConversation &conv,
                              const Sniffing::StreamSegment &segment,
                              qint64 baseSec,
                              qint64 baseUsec) const;
    QString formatPayload(const QByteArray &payload) const;
    QString formatHexDump(const QByteArray &payload) const;
    QString formatAsciiHexTable(const QByteArray &payload) const;
    QString formatEscaped(const QByteArray &payload) const;
    QString currentDirectionString(const Sniffing::StreamConversation &conv, bool fromAtoB) const;
    QString tcpFlagsToString(quint8 flags) const;
    void updateDirectionCombo(const Sniffing::StreamConversation &conv);
    void updateStats(const Sniffing::StreamConversation &conv);
    void ensurePayloadFont();
};

#endif // FOLLOWSTREAMDIALOG_H
