#ifndef APPEARANCEDIALOG_H
#define APPEARANCEDIALOG_H

#include <QDialog>
#include <QString>

class QComboBox;
class QLabel;
class QPushButton;
class QGroupBox;

class AppearanceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AppearanceDialog(QWidget *parent = nullptr);

private slots:
    void onContextChanged(int index);
    void editCurrentContext();
    void resetCurrentContext();

private:
    QString currentContextKey() const;
    void updatePreview();

    QComboBox  *m_contextCombo = nullptr;
    QGroupBox  *m_previewGroup = nullptr;
    QLabel     *m_previewText = nullptr;
    QPushButton *m_editButton = nullptr;
    QPushButton *m_resetButton = nullptr;
};

#endif // APPEARANCEDIALOG_H
