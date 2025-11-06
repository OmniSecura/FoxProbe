#ifndef SELECTIONANNOTATIONDIALOG_H
#define SELECTIONANNOTATIONDIALOG_H

#include <QColor>
#include <QDialog>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QPoint>

class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;
class QTextEdit;
class QTableWidget;

class SelectionAnnotationDialog : public QDialog
{
    Q_OBJECT
public:
    struct PacketSummary {
        int row = -1;
        QString number;
        QString time;
        QString source;
        QString destination;
        QString protocol;
        QString info;
    };

    struct Result {
        struct PacketDetail {
            int row = -1;
            QStringList tags;
            QColor color;
        };

        QString title;
        QString description;
        QStringList tags;
        QString threatLevel;
        QString recommendedAction;
        QVector<PacketDetail> packets;
    };

    explicit SelectionAnnotationDialog(const QVector<PacketSummary> &packets,
                                       QWidget *parent = nullptr);

    Result result() const;

private slots:
    void showContextMenu(const QPoint &pos);

private:
    QStringList splitTags(const QString &text) const;
    QString defaultTagForThreat() const;
    void applyRowColor(int row);

    QVector<PacketSummary> m_packets;
    QVector<QColor> m_packetColors;
    QVector<QLineEdit*> m_packetTagEdits;

    QLabel *m_summaryLabel;
    QLineEdit *m_titleEdit;
    QTextEdit *m_descriptionEdit;
    QComboBox *m_threatCombo;
    QLineEdit *m_tagsEdit;
    QComboBox *m_actionCombo;
    QTableWidget *m_packetTable;
    QDialogButtonBox *m_buttonBox;
};

#endif // SELECTIONANNOTATIONDIALOG_H
