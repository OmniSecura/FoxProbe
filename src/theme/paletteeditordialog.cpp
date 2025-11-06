#include "paletteeditordialog.h"

#include <QColorDialog>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFrame>

PaletteEditorDialog::PaletteEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Edit palette"));
    resize(420, 360);

    createEditors();
}

void PaletteEditorDialog::createEditors()
{
    auto *mainLayout = new QVBoxLayout(this);

    struct RoleInfo { QPalette::ColorRole role; const char *label; };
    const QVector<RoleInfo> roles = {
        { QPalette::Window,          QT_TRANSLATE_NOOP("PaletteEditorDialog", "Window frame") },
        { QPalette::Base,            QT_TRANSLATE_NOOP("PaletteEditorDialog", "Base background") },
        { QPalette::AlternateBase,   QT_TRANSLATE_NOOP("PaletteEditorDialog", "Alternate background") },
        { QPalette::Text,            QT_TRANSLATE_NOOP("PaletteEditorDialog", "Text color") },
        { QPalette::Button,          QT_TRANSLATE_NOOP("PaletteEditorDialog", "Button background") },
        { QPalette::ButtonText,      QT_TRANSLATE_NOOP("PaletteEditorDialog", "Button text") },
        { QPalette::Highlight,       QT_TRANSLATE_NOOP("PaletteEditorDialog", "Highlight") },
        { QPalette::HighlightedText, QT_TRANSLATE_NOOP("PaletteEditorDialog", "Highlighted text") }
    };

    for (int i = 0; i < roles.size(); ++i) {
        RoleRow row;
        row.role  = roles[i].role;
        row.label = tr(roles[i].label);
        row.button = new QPushButton(tr("Choose…"), this);
        row.swatch = new QLabel(this);
        row.swatch->setFixedSize(64, 24);
        row.swatch->setFrameShape(QFrame::Box);
        row.swatch->setAutoFillBackground(true);

        auto *hLayout = new QHBoxLayout;
        hLayout->addWidget(new QLabel(row.label, this));
        hLayout->addStretch();
        hLayout->addWidget(row.swatch);
        hLayout->addWidget(row.button);
        mainLayout->addLayout(hLayout);

        connect(row.button, &QPushButton::clicked, this, [this, i]() {
            chooseColor(i);
        });

        m_rows.push_back(row);
    }

    m_previewGroup = new QGroupBox(tr("Preview"), this);
    auto *previewLayout = new QVBoxLayout(m_previewGroup);
    m_previewLabel = new QLabel(tr("Lorem ipsum dolor sit amet"), m_previewGroup);
    m_previewLabel->setAlignment(Qt::AlignCenter);
    m_previewLabel->setAutoFillBackground(true);
    previewLayout->addWidget(m_previewLabel);
    mainLayout->addWidget(m_previewGroup);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(buttons);
}

void PaletteEditorDialog::setPalette(const QPalette &palette)
{
    m_basePalette = palette;
    for (int i = 0; i < m_rows.size(); ++i) {
        const QColor color = palette.color(m_rows[i].role);
        setRoleColor(i, color);
    }
    updatePreview();
}

QPalette PaletteEditorDialog::selectedPalette() const
{
    QPalette result = m_basePalette;
    for (const auto &row : m_rows) {
        if (row.color.isValid()) {
            result.setColor(row.role, row.color);
        }
    }
    const QColor textColor = result.color(QPalette::Text);
    if (textColor.isValid()) {
        result.setColor(QPalette::WindowText, textColor);
    }
    return result;
}

void PaletteEditorDialog::chooseColor(int roleIndex)
{
    if (roleIndex < 0 || roleIndex >= m_rows.size()) {
        return;
    }

    QColorDialog dialog(m_rows[roleIndex].color, this);
    dialog.setOption(QColorDialog::DontUseNativeDialog, true);

    const QColor previous = m_rows[roleIndex].color;
    connect(&dialog, &QColorDialog::currentColorChanged, this, [this, roleIndex](const QColor &color) {
        setRoleColor(roleIndex, color);
        updatePreview();
    });

    if (dialog.exec() == QDialog::Accepted) {
        setRoleColor(roleIndex, dialog.currentColor());
    } else {
        setRoleColor(roleIndex, previous);
    }
    updatePreview();
}

void PaletteEditorDialog::updatePreview()
{
    QPalette previewPalette = selectedPalette();
    m_previewGroup->setPalette(previewPalette);
    m_previewGroup->setAutoFillBackground(true);
    m_previewLabel->setPalette(previewPalette);
    m_previewLabel->setAutoFillBackground(true);
    emit palettePreviewChanged(previewPalette);
}

void PaletteEditorDialog::setRoleColor(int roleIndex, const QColor &color)
{
    if (roleIndex < 0 || roleIndex >= m_rows.size()) {
        return;
    }

    RoleRow &row = m_rows[roleIndex];
    row.color = color;

    QPalette pal = row.swatch->palette();
    const QColor fallbackColor = m_basePalette.color(row.role);
    pal.setColor(QPalette::Window, color.isValid() ? color : fallbackColor);
    row.swatch->setPalette(pal);

    if (color.isValid()) {
        row.button->setText(color.name().toUpper());
    } else {
        row.button->setText(tr("Choose…"));
    }
}
