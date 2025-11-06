#ifndef SESSIONMANAGERDIALOG_H
#define SESSIONMANAGERDIALOG_H

#include <QDialog>
#include <QFileSystemWatcher>
#include <QVector>
#include <optional>

#include "sessionstorage.h"

class QTableWidget;
class QPushButton;
class QLabel;

class SessionManagerDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SessionManagerDialog(QWidget *parent = nullptr);

    QVector<SessionStorage::SessionRecord> sessions() const;
    std::optional<SessionStorage::SessionRecord> selectedSession() const;

private slots:
    void refreshSessions();
    void updateButtons();
    void openSelectedSession();

private:
    void setupUi();

    QTableWidget *m_table = nullptr;
    QPushButton *m_openButton = nullptr;
    QPushButton *m_refreshButton = nullptr;
    QLabel *m_hintLabel = nullptr;
    QFileSystemWatcher m_watcher;
    QVector<SessionStorage::SessionRecord> m_sessions;
    QString m_sessionsDir;
};

#endif // SESSIONMANAGERDIALOG_H
