#ifndef STATSDIALOG_H
#define STATSDIALOG_H

#include "charts/barchart.h"
#include "charts/linechart.h"
#include "charts/ChartConfig.h"

class StatsDialog : public QDialog {
    Q_OBJECT

public:
    explicit StatsDialog(QWidget *parent = nullptr);
    ~StatsDialog();

    void updateOptionsBar(int index);

private:
    QHBoxLayout    *optionsBar;
    QStackedWidget *stackedWidget;

    QPushButton *barChartBtn, *lineChartBtn, *protocolBtn;
    QComboBox   *barFilter   = nullptr;
    QComboBox   *sessionSel  = nullptr;
    QComboBox   *sortCombo   = nullptr;

    // LineChart controls
    QComboBox   *lineMode    = nullptr;
    QComboBox   *lineSession = nullptr;
    QComboBox   *metricCombo = nullptr;

    QScrollArea *barScrollArea;
    BarChart    *barChartWidget;
    LineChart   *lineChartWidget;
};

#endif // STATSDIALOG_H
