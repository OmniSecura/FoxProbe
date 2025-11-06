#ifndef OTHERTHEMESDIALOG_H
#define OTHERTHEMESDIALOG_H

#include <QDialog>
#include <QPalette>
#include <QStringList>

namespace Ui { class OtherThemesDialog; }

class OtherThemesDialog : public QDialog {
    Q_OBJECT

public:
    explicit OtherThemesDialog(QWidget *parent = nullptr);
    ~OtherThemesDialog();

    // Name selected when OK was pressed
    QString selectedTheme() const;

private slots:
    void on_addCustom_clicked();
    void on_removeCustom_clicked();
    void on_themeList_currentTextChanged(const QString &name);

private:
    Ui::OtherThemesDialog *ui;
    const QStringList builtIns { "Greenish", "Black+Orange" };

    void loadList();
    void saveCustomNames();
    void applyPaletteToPreview(const QPalette &palette);
};

#endif // OTHERTHEMESDIALOG_H
