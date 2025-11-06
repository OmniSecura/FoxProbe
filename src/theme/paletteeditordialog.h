#ifndef PALETTEEDITORDIALOG_H
#define PALETTEEDITORDIALOG_H

#include <QDialog>
#include <QColor>
#include <QPalette>

class QPushButton;
class QLabel;
class QGroupBox;

class PaletteEditorDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PaletteEditorDialog(QWidget *parent = nullptr);

    void setPalette(const QPalette &palette);
    QPalette selectedPalette() const;

signals:
    void palettePreviewChanged(const QPalette &palette);

private slots:
    void chooseColor(int roleIndex);

private:
    void createEditors();
    void updatePreview();
    void setRoleColor(int roleIndex, const QColor &color);

    struct RoleRow {
        QString     label;
        QPushButton *button = nullptr;
        QLabel      *swatch = nullptr;
        QColor       color;
        QPalette::ColorRole role;
    };

    QVector<RoleRow> m_rows;
    QPalette         m_basePalette;
    QGroupBox *m_previewGroup = nullptr;
    QLabel    *m_previewLabel = nullptr;
};

#endif // PALETTEEDITORDIALOG_H
