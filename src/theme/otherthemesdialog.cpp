#include "otherthemesdialog.h"
#include "ui_otherthemesdialog.h"
#include "theme.h"
#include "paletteeditordialog.h"

OtherThemesDialog::OtherThemesDialog(QWidget *parent)
  : QDialog(parent), ui(new Ui::OtherThemesDialog)
{
    ui->setupUi(this);
    loadList();

    connect(ui->themeList, &QListWidget::currentTextChanged,
            this, &OtherThemesDialog::on_themeList_currentTextChanged);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    connect(ui->addCustom, &QPushButton::clicked,
            this, &OtherThemesDialog::on_addCustom_clicked);
    connect(ui->removeCustom, &QPushButton::clicked,
            this, &OtherThemesDialog::on_removeCustom_clicked);
}

OtherThemesDialog::~OtherThemesDialog()
{
    delete ui;
}

QString OtherThemesDialog::selectedTheme() const
{
    return ui->themeList->currentItem()
         ? ui->themeList->currentItem()->text()
         : QString();
}

void OtherThemesDialog::loadList()
{
    ui->themeList->clear();
    for (auto &n : builtIns)
        ui->themeList->addItem(n);
    QSettings s("Engineering","FoxProbe");
    for (auto &n : s.value("CustomThemes/List").toStringList())
        ui->themeList->addItem(n);
    if (ui->themeList->count())
        ui->themeList->setCurrentRow(0);
}

void OtherThemesDialog::saveCustomNames()
{
    QSettings s("Engineering","FoxProbe");
    QStringList customs;
    for (int i = builtIns.size(); i < ui->themeList->count(); ++i)
        customs << ui->themeList->item(i)->text();
    s.setValue("CustomThemes/List", customs);
}

void OtherThemesDialog::on_themeList_currentTextChanged(const QString &name)
{
    if (name.isEmpty()) {
        applyPaletteToPreview(qApp->palette());
        return;
    }
    applyPaletteToPreview(Theme::paletteForName(name));
}

void OtherThemesDialog::on_addCustom_clicked()
{
    bool ok;
    QString name = QInputDialog::getText(this,
        "New Theme", "Enter theme name:",
        QLineEdit::Normal, {}, &ok);
    if (!ok || name.isEmpty()) return;

    PaletteEditorDialog editor(this);
    const QString baseTheme = selectedTheme();
    const QPalette basePalette = baseTheme.isEmpty()
        ? qApp->palette()
        : Theme::paletteForName(baseTheme);
    editor.setPalette(basePalette);

    const QPalette originalPreview = ui->previewGroup->palette();
    auto liveConnection = connect(&editor, &PaletteEditorDialog::palettePreviewChanged,
                                  this, [this](const QPalette &palette) {
        applyPaletteToPreview(palette);
    });
    if (editor.exec() != QDialog::Accepted)
    {
        disconnect(liveConnection);
        applyPaletteToPreview(originalPreview);
        return;
    }

    disconnect(liveConnection);

    const QPalette palette = editor.selectedPalette();
    Theme::saveCustomPalette(name,
                             palette.color(QPalette::Window),
                             palette.color(QPalette::Base),
                             palette.color(QPalette::Text),
                             palette.color(QPalette::Button),
                             palette.color(QPalette::ButtonText),
                             palette.color(QPalette::AlternateBase),
                             palette.color(QPalette::Highlight),
                             palette.color(QPalette::HighlightedText));

    QSettings s("Engineering","FoxProbe");
    auto list = s.value("CustomThemes/List").toStringList();
    if (!list.contains(name)) {
        list << name;
        s.setValue("CustomThemes/List", list);
    }

    loadList();
    saveCustomNames();
    auto items = ui->themeList->findItems(name, Qt::MatchExactly);
    if (!items.isEmpty())
        ui->themeList->setCurrentItem(items.first());
}

void OtherThemesDialog::on_removeCustom_clicked()
{
    auto item = ui->themeList->currentItem();
    if (!item) return;
    QString name = item->text();
    if (builtIns.contains(name)) return;

    QSettings s("Engineering","FoxProbe");
    s.remove(QString("CustomThemes/%1").arg(name));
    auto list = s.value("CustomThemes/List").toStringList();
    list.removeAll(name);
    s.setValue("CustomThemes/List", list);

    loadList();
    saveCustomNames();
}

void OtherThemesDialog::applyPaletteToPreview(const QPalette &palette)
{
    ui->previewGroup->setAutoFillBackground(true);
    ui->previewGroup->setPalette(palette);
    const auto widgets = ui->previewGroup->findChildren<QWidget*>();
    for (auto *w : widgets) {
        w->setAutoFillBackground(true);
        w->setPalette(palette);
    }
}
