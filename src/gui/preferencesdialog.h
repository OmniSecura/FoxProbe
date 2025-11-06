
#ifndef PREFERENCESDIALOG_H
#define PREFERENCESDIALOG_H

#include <QDialog>
#include <QStringList>

#include "../appsettings.h"

class QCheckBox;
class QComboBox;
class QLineEdit;

class PreferencesDialog : public QDialog {
    Q_OBJECT
public:
    PreferencesDialog(AppSettings &settings,
                      const QStringList &interfaces,
                      QWidget *parent = nullptr);

protected:
    void accept() override;

private slots:
    void chooseReportsDirectory();
    void chooseAnomaliesDirectory();
    void chooseSessionsDirectory();

private:
    void populateInterfaces(const QStringList &interfaces);
    void populateThemes();

    AppSettings &settings;
    QComboBox *interfaceCombo = nullptr;
    QCheckBox *autoStartCheck = nullptr;
    QComboBox *themeCombo = nullptr;
    QLineEdit *reportsDirEdit = nullptr;
    QLineEdit *anomaliesDirEdit = nullptr;
    QLineEdit *sessionsDirEdit = nullptr;
};

#endif // PREFERENCESDIALOG_H
