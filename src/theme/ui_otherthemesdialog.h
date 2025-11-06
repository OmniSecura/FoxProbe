#ifndef UI_OTHERTHEMESDIALOG_H
#define UI_OTHERTHEMESDIALOG_H

#include <QtCore/QCoreApplication>
#include <QtWidgets>

QT_BEGIN_NAMESPACE
class Ui_OtherThemesDialog
{
public:
    QHBoxLayout       *hbox;
    // ← Left pane: list + buttons
    QVBoxLayout       *leftLayout;
    QListWidget       *themeList;
    QHBoxLayout       *buttonLayout;
    QPushButton       *addCustom;
    QPushButton       *removeCustom;
    QDialogButtonBox  *buttonBox;
    // → Right pane: preview of main UI
    QGroupBox         *previewGroup;
    QVBoxLayout       *previewLayout;
    QHBoxLayout       *topBarLayout;
    QComboBox         *previewIface;
    QLineEdit         *previewFilter;
    QCheckBox         *previewPromisc;
    QPushButton       *previewStart;
    QPushButton       *previewStop;
    QTableWidget      *previewTable;
    QSplitter         *previewSplitterH;
    QTreeWidget       *previewTree;
    QTextEdit         *previewHex;

    void setupUi(QDialog *d)
    {
        d->setObjectName("OtherThemesDialog");
        d->resize(800,400);

        // main split
        hbox = new QHBoxLayout(d);

        // ← LEFT
        leftLayout = new QVBoxLayout;
        themeList = new QListWidget(d);
        leftLayout->addWidget(themeList);
        buttonLayout = new QHBoxLayout;
        addCustom = new QPushButton("+ Add…", d);
        removeCustom = new QPushButton("– Remove", d);
        buttonLayout->addWidget(addCustom);
        buttonLayout->addWidget(removeCustom);
        leftLayout->addLayout(buttonLayout);
        buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel, d);
        leftLayout->addWidget(buttonBox);
        hbox->addLayout(leftLayout,1);

        // → RIGHT (preview)
        previewGroup = new QGroupBox("Preview", d);
        previewLayout = new QVBoxLayout(previewGroup);

        topBarLayout = new QHBoxLayout;
        previewIface   = new QComboBox(previewGroup);
        previewIface->addItem("wlan0");
        previewFilter  = new QLineEdit(previewGroup);
        previewFilter->setPlaceholderText("tcp port 80");
        previewPromisc = new QCheckBox("Promiscuous", previewGroup);
        previewPromisc->setChecked(true);
        previewStart   = new QPushButton("Start", previewGroup);
        previewStop    = new QPushButton("Stop", previewGroup);
        previewStop->setEnabled(false);
        topBarLayout->addWidget(previewIface);
        topBarLayout->addWidget(previewFilter);
        topBarLayout->addWidget(previewPromisc);
        topBarLayout->addWidget(previewStart);
        topBarLayout->addWidget(previewStop);
        previewLayout->addLayout(topBarLayout);

        previewTable = new QTableWidget(previewGroup);
        previewTable->setColumnCount(7);
        previewTable->setHorizontalHeaderLabels({"No.","Time","Source","Dest.","Proto","Len","Info"});
        previewTable->horizontalHeader()->setStretchLastSection(true);
        previewTable->setFixedHeight(120);
        previewLayout->addWidget(previewTable);

        previewSplitterH = new QSplitter(Qt::Horizontal, previewGroup);
        previewTree = new QTreeWidget(previewSplitterH);
        previewTree->setHeaderLabels({"Info","Value"});
        previewTree->setFixedWidth(200);
        previewHex = new QTextEdit(previewSplitterH);
        previewHex->setReadOnly(true);
        previewSplitterH->addWidget(previewTree);
        previewSplitterH->addWidget(previewHex);
        previewLayout->addWidget(previewSplitterH,1);

        hbox->addWidget(previewGroup,2);

        QMetaObject::connectSlotsByName(d);
    }
};
namespace Ui { class OtherThemesDialog: public Ui_OtherThemesDialog {}; }
QT_END_NAMESPACE

#endif // UI_OTHERTHEMESDIALOG_H
