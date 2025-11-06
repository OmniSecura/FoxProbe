#include "appearancedialog.h"

#include "paletteeditordialog.h"
#include "theme.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

AppearanceDialog::AppearanceDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Appearance"));
    resize(440, 360);

    auto *mainLayout = new QVBoxLayout(this);

    auto *contextLayout = new QHBoxLayout;
    auto *contextLabel = new QLabel(tr("Customize"), this);
    m_contextCombo = new QComboBox(this);
    const auto contexts = Theme::availableContexts();
    for (const auto &key : contexts) {
        m_contextCombo->addItem(Theme::contextLabel(key), key);
    }
    connect(m_contextCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AppearanceDialog::onContextChanged);
    contextLayout->addWidget(contextLabel);
    contextLayout->addWidget(m_contextCombo, 1);
    mainLayout->addLayout(contextLayout);

    m_previewGroup = new QGroupBox(tr("Preview"), this);
    auto *previewLayout = new QVBoxLayout(m_previewGroup);
    m_previewText = new QLabel(tr("Sample text and buttons"), m_previewGroup);
    m_previewText->setAlignment(Qt::AlignCenter);
    m_previewText->setAutoFillBackground(true);
    previewLayout->addWidget(m_previewText);

    auto *previewButtonsLayout = new QHBoxLayout;
    auto *exampleButton = new QPushButton(tr("Example"), m_previewGroup);
    auto *exampleSecondary = new QPushButton(tr("Secondary"), m_previewGroup);
    previewButtonsLayout->addStretch();
    previewButtonsLayout->addWidget(exampleButton);
    previewButtonsLayout->addWidget(exampleSecondary);
    previewButtonsLayout->addStretch();
    previewLayout->addLayout(previewButtonsLayout);

    mainLayout->addWidget(m_previewGroup, 1);

    auto *buttonRow = new QHBoxLayout;
    m_editButton = new QPushButton(tr("Edit colors…"), this);
    m_resetButton = new QPushButton(tr("Reset"), this);
    buttonRow->addStretch();
    buttonRow->addWidget(m_editButton);
    buttonRow->addWidget(m_resetButton);
    mainLayout->addLayout(buttonRow);

    connect(m_editButton, &QPushButton::clicked, this, &AppearanceDialog::editCurrentContext);
    connect(m_resetButton, &QPushButton::clicked, this, &AppearanceDialog::resetCurrentContext);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(buttonBox);

    if (m_contextCombo->count() > 0) {
        m_contextCombo->setCurrentIndex(0);
        updatePreview();
    }
}

void AppearanceDialog::onContextChanged(int)
{
    updatePreview();
}

void AppearanceDialog::editCurrentContext()
{
    const QString key = currentContextKey();
    if (key.isEmpty()) {
        return;
    }

    PaletteEditorDialog editor(this);
    editor.setPalette(Theme::paletteForContext(key));
    if (editor.exec() == QDialog::Accepted) {
        Theme::saveContextPalette(key, editor.selectedPalette());
        Theme::loadTheme();
        updatePreview();
    }
}

void AppearanceDialog::resetCurrentContext()
{
    const QString key = currentContextKey();
    if (key.isEmpty()) {
        return;
    }
    Theme::clearContextPalette(key);
    Theme::loadTheme();
    updatePreview();
}

QString AppearanceDialog::currentContextKey() const
{
    if (!m_contextCombo || m_contextCombo->currentIndex() < 0) {
        return QString();
    }
    return m_contextCombo->currentData().toString();
}

void AppearanceDialog::updatePreview()
{
    const QString key = currentContextKey();
    const QPalette palette = Theme::paletteForContext(key);

    m_previewGroup->setPalette(palette);
    m_previewGroup->setAutoFillBackground(true);
    m_previewText->setPalette(palette);
    m_previewText->setAutoFillBackground(true);
    m_previewText->setText(tr("Preview for %1").arg(Theme::contextLabel(key)));
}
