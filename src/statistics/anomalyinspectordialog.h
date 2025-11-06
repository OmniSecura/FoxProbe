#ifndef ANOMALYINSPECTORDIALOG_H
#define ANOMALYINSPECTORDIALOG_H

#include <QDialog>
#include <QVector>

#include "anomalydetector.h"

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

class AnomalyInspectorDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AnomalyInspectorDialog(QWidget *parent = nullptr);

    void setEvents(const QVector<AnomalyDetector::Event> &events);

signals:
    void requestFocusPackets(const QVector<int> &rows);

private slots:
    void applyFilter();
    void onSelectionChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onFocusRequested();

private:
    void rebuildCategoryFilter();
    void updateDetails(int filteredIndex);

    QComboBox *m_categoryCombo = nullptr;
    QLineEdit *m_searchEdit = nullptr;
    QTreeWidget *m_eventTree = nullptr;
    QPlainTextEdit *m_detailsView = nullptr;
    QPushButton *m_focusButton = nullptr;

    QVector<AnomalyDetector::Event> m_events;
    QVector<AnomalyDetector::Event> m_filteredEvents;
};

#endif // ANOMALYINSPECTORDIALOG_H
