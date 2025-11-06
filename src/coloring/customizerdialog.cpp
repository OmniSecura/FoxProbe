#include "customizerdialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QInputDialog>
#include <QColorDialog>

CustomizerDialog::CustomizerDialog(QWidget *parent,
                                   QVector<ColoringRule> initialRules)
  : QDialog(parent),
    m_rules(std::move(initialRules))
{
    setWindowTitle(tr("Customize Coloring Rules"));
    resize(400, 300);

    m_listWidget = new QListWidget(this);
    m_addBtn     = new QPushButton(tr("Add…"), this);
    m_editBtn    = new QPushButton(tr("Edit…"), this);
    m_removeBtn  = new QPushButton(tr("Remove"), this);

    connect(m_listWidget, &QListWidget::currentRowChanged, this, [this](int row) {
        if (row >= 0 && row < m_rules.size()) {
            updatePreview(m_rules[row].color);
        }
    });

    connect(m_addBtn,    &QPushButton::clicked, this, &CustomizerDialog::onAdd);
    connect(m_editBtn,   &QPushButton::clicked, this, &CustomizerDialog::onEdit);
    connect(m_removeBtn, &QPushButton::clicked, this, &CustomizerDialog::onRemove);

    auto *btnLayout = new QHBoxLayout;
    btnLayout->addWidget(m_addBtn);
    btnLayout->addWidget(m_editBtn);
    btnLayout->addWidget(m_removeBtn);

    auto *dialogButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok|QDialogButtonBox::Cancel,
        Qt::Horizontal, this);
    connect(dialogButtons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(dialogButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    m_previewGroup = new QGroupBox(tr("Preview"), this);
    auto *previewLayout = new QVBoxLayout(m_previewGroup);
    m_previewLabel = new QLabel(tr("Example packet"), m_previewGroup);
    m_previewLabel->setAlignment(Qt::AlignCenter);
    m_previewLabel->setAutoFillBackground(true);
    previewLayout->addWidget(m_previewLabel);

    auto *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(m_listWidget);
    mainLayout->addLayout(btnLayout);
    mainLayout->addWidget(m_previewGroup);
    mainLayout->addWidget(dialogButtons);
    setLayout(mainLayout);

    rebuildList();
    if (!m_rules.isEmpty()) {
        m_listWidget->setCurrentRow(0);
    } else {
        updatePreview(Qt::transparent);
    }
}

CustomizerDialog::~CustomizerDialog() = default;

void CustomizerDialog::rebuildList() {
    const int prevRow = m_listWidget->currentRow();
    m_listWidget->clear();
    for (auto &r : m_rules) {
        auto *item = new QListWidgetItem(r.bpfExpression, m_listWidget);
        item->setBackground(r.color);
        item->setForeground(r.color.lightness() < 128
                            ? Qt::white
                            : Qt::black);
    }
    if (!m_rules.isEmpty()) {
        const int row = (prevRow >= 0 && prevRow < m_rules.size()) ? prevRow : 0;
        m_listWidget->setCurrentRow(row);
        updatePreview(m_rules[row].color);
    } else {
        updatePreview(Qt::transparent);
    }
}

void CustomizerDialog::onAdd() {
    bool ok=false;
    QString expr = QInputDialog::getText(
        this, tr("New rule"), tr("BPF expression:"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || expr.isEmpty()) return;

    QColor c = pickColor(Qt::yellow, tr("Choose rule color"));
    if (!c.isValid()) return;

    ColoringRule r; r.bpfExpression = expr; r.color = c;
    m_rules.push_back(std::move(r));
    rebuildList();
}

void CustomizerDialog::onEdit() {
    int idx = m_listWidget->currentRow();
    if (idx<0) return;

    bool ok=false;
    QString expr = QInputDialog::getText(
        this, tr("Edit rule"), tr("BPF expression:"),
        QLineEdit::Normal, m_rules[idx].bpfExpression, &ok);
    if (!ok || expr.isEmpty()) return;

    QColor c = pickColor(m_rules[idx].color, tr("Choose rule color"));
    if (!c.isValid()) return;

    m_rules[idx].bpfExpression = expr;
    m_rules[idx].color         = c;
    rebuildList();
}

void CustomizerDialog::onRemove() {
    int idx = m_listWidget->currentRow();
    if (idx<0) return;
    m_rules.removeAt(idx);
    rebuildList();
}

QVector<ColoringRule> CustomizerDialog::takeRules() {
    return std::move(m_rules);
}

QColor CustomizerDialog::pickColor(const QColor &initialColor, const QString &title)
{
    const QColor previous = m_previewColor;

    QColorDialog dialog(initialColor, this);
    dialog.setWindowTitle(title);
    dialog.setOption(QColorDialog::DontUseNativeDialog, true);
    connect(&dialog, &QColorDialog::currentColorChanged,
            this, &CustomizerDialog::updatePreview);

    QColor chosen;
    if (dialog.exec() == QDialog::Accepted) {
        chosen = dialog.currentColor();
        updatePreview(chosen);
    } else {
        updatePreview(previous);
    }
    return chosen;
}

void CustomizerDialog::updatePreview(const QColor &color)
{
    m_previewColor = color;
    QPalette pal = m_previewLabel->palette();
    const QColor fallbackColor = pal.color(QPalette::Window);
    pal.setColor(QPalette::Window, color.isValid() ? color : fallbackColor);
    const QColor textColor = (!color.isValid() || color.lightness() >= 128)
            ? Qt::black
            : Qt::white;
    pal.setColor(QPalette::WindowText, textColor);
    m_previewLabel->setPalette(pal);
    m_previewLabel->setAutoFillBackground(true);
    m_previewLabel->setText(color.isValid()
                            ? tr("Preview: %1").arg(color.name().toUpper())
                            : tr("Preview"));
}
