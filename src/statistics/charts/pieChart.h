#ifndef PIECHART_H
#define PIECHART_H

#include "ChartConfig.h"
#include "../../coloring/packetcolorizer.h"

class PieChart : public QWidget {
public:
    explicit PieChart(QWidget *parent = nullptr);
    void setData(const QList<QPair<QString,int>> &data);
    void setColorizer(PacketColorizer *colorizer);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    QList<QPair<QString,int>> m_data;
    int m_total = 0;
    QRectF m_pieRect;
    PacketColorizer *m_colorizer = nullptr;
    int indexAtAngle(int angleDeg) const;
    void showSliceTooltip(int sliceIndex, const QPoint &globalPos);
};

#endif // PIECHART_H
