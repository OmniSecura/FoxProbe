#include "statsdialog.h"
#include "../theme/theme.h"

StatsDialog::StatsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Session Statistics");
    resize(1000, 780);

    // — Menu with Save/Export —
    auto *menuBar  = new QMenuBar(this);
    auto *fileMenu = menuBar->addMenu("File");
    fileMenu->addAction("Save as PNG", this, [this]() {
        QString fn = QFileDialog::getSaveFileName(this,
                            "Save Chart as PNG", "", "*.png");
        if (fn.isEmpty()) return;
        QPixmap pm;
        if (stackedWidget->currentIndex() == 0)
            pm = barChartWidget->grab();
        else if (stackedWidget->currentIndex() == 1)
            pm = lineChartWidget->grab();
        else
            return;
        pm.save(fn);
    });
    fileMenu->addAction("Export CSV", this, [this]() {
        QString fn = QFileDialog::getSaveFileName(this,
                            "Export Data as CSV", "", "*.csv");
        if (fn.isEmpty()) return;
        QFile f(fn);
        if (!f.open(QIODevice::WriteOnly)) {
            qWarning() << "Cannot open" << fn;
            return;
        }
        QTextStream ts(&f);
        int idx = stackedWidget->currentIndex();
        if (idx == 0) {
            ts << "Protocol,Count\n";
            auto plot = barChartWidget->currentPlot();
            for (auto it = plot.constBegin(); it != plot.constEnd(); ++it)
                ts << it.key() << "," << it.value() << "\n";
        } else if (idx == 1) {
            ts << "Interval,Value\n";
            auto pts = lineChartWidget->currentData();
            for (auto &p : pts)
                ts << p.x() << "," << p.y() << "\n";
        }
        f.close();
    });

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setMenuBar(menuBar);

    // — Chart selection buttons —
    auto *btnLayout = new QHBoxLayout;
    barChartBtn  = new QPushButton("Bar chart",  this);
    lineChartBtn = new QPushButton("Line chart", this);
    btnLayout->addWidget(barChartBtn);
    btnLayout->addWidget(lineChartBtn);
    mainLayout->addLayout(btnLayout);

    // — Filters row —
    optionsBar = new QHBoxLayout;
    mainLayout->addLayout(optionsBar);

    // — Charts —
    barChartWidget  = new BarChart(this);
    barScrollArea   = new QScrollArea(this);
    barScrollArea->setWidgetResizable(true);
    barScrollArea->setWidget(barChartWidget);

    lineChartWidget = new LineChart(this);

    stackedWidget = new QStackedWidget(this);
    stackedWidget->addWidget(barScrollArea);    // index 0
    stackedWidget->addWidget(lineChartWidget);  // index 1
    mainLayout->addWidget(stackedWidget);

    connect(barChartBtn,  &QPushButton::clicked, this, [this](){
        stackedWidget->setCurrentIndex(0);
    });
    connect(lineChartBtn, &QPushButton::clicked, this, [this](){
        stackedWidget->setCurrentIndex(1);
    });
    connect(stackedWidget,
            &QStackedWidget::currentChanged,
            this,
            &StatsDialog::updateOptionsBar);

    // — Close button —
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected,
            this, &StatsDialog::reject);
    mainLayout->addWidget(buttons);

    setLayout(mainLayout);

    // Initialize filters for the first (bar) chart
    updateOptionsBar(0);

    Theme::applyTo(this, Theme::statisticsContextKey());
}

StatsDialog::~StatsDialog() = default;

void StatsDialog::updateOptionsBar(int index)
{
    // Clear any existing widgets
    QLayoutItem *child;
    while ((child = optionsBar->takeAt(0)) != nullptr) {
        if (child->widget())
            child->widget()->deleteLater();
        delete child;
    }

    if (index == 0) {
        // — BarChart filters —

        // Mode selector
        barFilter = new QComboBox(this);
        barFilter->addItems({ "All time", "Current session", "By session" });
        optionsBar->addWidget(barFilter);
        connect(barFilter,
                &QComboBox::currentTextChanged,
                this,
                [this](const QString &t) {
            if (sessionSel) {
                optionsBar->removeWidget(sessionSel);
                sessionSel->deleteLater();
                sessionSel = nullptr;
            }
            if (t == "By session") {
                sessionSel = new QComboBox(this);
                sessionSel->addItems(barChartWidget->availableSessionLabels());
                optionsBar->addWidget(sessionSel);
                connect(sessionSel,
                        QOverload<int>::of(&QComboBox::currentIndexChanged),
                        this,
                        [this](int idx) {
                    barChartWidget->setSessionIndex(idx);
                });
                barChartWidget->setMode(chart::Mode::BySession);
            } else if (t == "Current session") {
                barChartWidget->setMode(chart::Mode::CurrentSession);
            } else {
                barChartWidget->setMode(chart::Mode::AllTime);
            }
        });
        barFilter->setCurrentText("All time");

        // Sort selector
        sortCombo = new QComboBox(this);
        sortCombo->addItems({ "By value", "Alphabetical" });
        optionsBar->addWidget(sortCombo);
        connect(sortCombo,
                &QComboBox::currentTextChanged,
                this,
                [this](const QString &t) {
            barChartWidget->setSortMode(
                t == "Alphabetical"
                  ? BarChart::Alphabetical
                  : BarChart::ByValue
            );
        });
        sortCombo->setCurrentText("By value");

        // Protocols filter
        protocolBtn = new QPushButton("Protocols...", this);
        optionsBar->addWidget(protocolBtn);
        connect(protocolBtn, &QPushButton::clicked, this, [this]() {
            QDialog dlg(this);
            dlg.setWindowTitle("Select Protocols");
            QVBoxLayout layout(&dlg);
            QVector<QCheckBox*> boxes;
            for (auto &p : barChartWidget->availableProtocols()) {
                auto *cb = new QCheckBox(p, &dlg);
                cb->setChecked(true);
                layout.addWidget(cb);
                boxes.append(cb);
            }
            QDialogButtonBox dbb(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                &dlg);
            layout.addWidget(&dbb);
            connect(&dbb, &QDialogButtonBox::accepted,  &dlg, &QDialog::accept);
            connect(&dbb, &QDialogButtonBox::rejected,  &dlg, &QDialog::reject);
            if (dlg.exec() == QDialog::Accepted) {
                QStringList sel;
                for (auto *cb : boxes)
                    if (cb->isChecked())
                        sel << cb->text();
                barChartWidget->setProtocolFilter(sel);
            }
        });

    }
    else if (index == 1) {
        // — LineChart filters —

        // Mode selector
        lineMode = new QComboBox(this);
        lineMode->addItems({ "All time", "Current session", "By session" });
        optionsBar->addWidget(lineMode);
        connect(lineMode,
                QOverload<int>::of(&QComboBox::currentIndexChanged),
                this,
                [this](int idx) {
            if (lineSession) {
                optionsBar->removeWidget(lineSession);
                lineSession->deleteLater();
                lineSession = nullptr;
            }
            if (idx == 2) {  // By session
                lineSession = new QComboBox(this);
                lineSession->addItems(
                    lineChartWidget->availableSessionLabels()
                );
                optionsBar->addWidget(lineSession);
                connect(lineSession,
                        QOverload<int>::of(&QComboBox::currentIndexChanged),
                        this,
                        [this](int sidx) {
                    lineChartWidget->setSessionIndex(sidx);
                });
                lineChartWidget->setMode(chart::Mode::BySession);
            }
            else if (idx == 1) {
                lineChartWidget->setMode(chart::Mode::CurrentSession);
            }
            else {  // All time
                lineChartWidget->setMode(chart::Mode::AllTime);
            }
        });
        lineMode->setCurrentIndex(0);

        // Metric selector
        metricCombo = new QComboBox(this);
        metricCombo->addItems(lineChartWidget->availableMetrics());
        optionsBar->addWidget(metricCombo);
        connect(metricCombo,
                QOverload<int>::of(&QComboBox::currentIndexChanged),
                this,
                [this](int midx) {
            lineChartWidget->setMetric(LineChart::Metric(midx));
        });
        metricCombo->setCurrentIndex(0);

        // Resolution selector
        {
            QComboBox *resCombo = new QComboBox(this);
            resCombo->addItems({ "Seconds", "Minutes", "Hours" });
            optionsBar->addWidget(resCombo);
            connect(resCombo,
                    QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this,
                    [this](int ridx) {
                lineChartWidget->setResolution(
                    LineChart::Resolution(ridx)
                );
            });
            resCombo->setCurrentIndex(0);
        }
    }
}
