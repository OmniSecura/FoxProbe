#include "pieChart.h"

PieChart::PieChart(QWidget *parent)
    : QWidget(parent),
      m_colorizer(nullptr)
{
    setMouseTracking(true);
    m_data.clear();
}

void PieChart::setData(const QList<QPair<QString,int>> &data)
{
    m_data = data;
    m_total = 0;
    for (const auto &p : m_data)
        m_total += p.second;
    update();
}

void PieChart::setColorizer(PacketColorizer *colorizer)
{
    m_colorizer = colorizer;
    update();
}

void PieChart::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.fillRect(rect(), palette().window());

    if (m_data.isEmpty()) return;

    int total = 0;
    for (const auto &p : m_data) total += p.second;
    if (total <= 0) return;

    int margin = 10;
    int side = qMin(width(), height()) - 2 * margin;
    if (side < 20) return;
    m_pieRect = QRectF((width()  - side) / 2.0,
                       (height() - side) / 2.0,
                       side, side);

    int n = m_data.size();
    QVector<int> spans(n);
    int desiredSum = 360 * 16;
    int sumSpans = 0;
    for (int i = 0; i < n; ++i) {
        qreal rawAngle16 = (qreal)m_data[i].second / total * 360.0 * 16.0;
        spans[i] = int(qRound(rawAngle16));
        if (spans[i] == 0 && m_data[i].second > 0) spans[i] = 1;
        sumSpans += spans[i];
    }
    int diff = desiredSum - sumSpans;
    if (n > 0) spans[0] += diff;

    int startAngle16 = 0;
    for (int i = 0; i < n; ++i) {
        QColor sliceColor = QColor(Qt::lightGray).lighter(150);

        if (m_colorizer) {
            QString protoLower = m_data[i].first.toLower();
            for (const ColoringRule &r : m_colorizer->rules()) {
                QString ruleProto = r.bpfExpression.toLower().trimmed();
                if (!ruleProto.isEmpty() && protoLower.startsWith(ruleProto)) {
                    sliceColor = r.color;
                    break;
                }
            }
        }

        painter.setBrush(sliceColor);
        painter.setPen(Qt::NoPen);
        painter.drawPie(m_pieRect, startAngle16, spans[i]);
        startAngle16 += spans[i];
    }
    const int legendItemHeight = 18;
    const int legendSquareSize = 12;
    int legendX = int(m_pieRect.right()) + 10;
    int legendY = int(m_pieRect.top());
    if (legendX + 120 < width()) {
        int neededHeight = n * legendItemHeight;
        if (legendY + neededHeight < height()) {
            painter.setPen(palette().text().color());
            for (int i = 0; i < n; ++i) {
                QColor squareColor = QColor(Qt::lightGray).lighter(150);
                if (m_colorizer) {
                    QString protoLower = m_data[i].first.toLower();
                    for (const ColoringRule &r : m_colorizer->rules()) {
                        QString ruleProto = r.bpfExpression.toLower().trimmed();
                        if (!ruleProto.isEmpty() && protoLower.startsWith(ruleProto)) {
                            squareColor = r.color;
                            break;
                        }
                    }
                }
                painter.setBrush(squareColor);
                painter.setPen(Qt::NoPen);
                QRectF square(legendX,
                              legendY + i * legendItemHeight + 2,
                              legendSquareSize,
                              legendSquareSize);
                painter.drawRect(square);

                painter.setPen(palette().text().color());
                QString txt = m_data[i].first;
                painter.drawText(legendX + legendSquareSize + 5,
                                 legendY + i * legendItemHeight + legendSquareSize,
                                 txt);
            }
        }
    }
}

void PieChart::mouseMoveEvent(QMouseEvent *event)
{
    if (m_data.isEmpty()) {
        QToolTip::hideText();
        return;
    }

    QPointF globalPosF = event->globalPosition();
    QPoint pos = event->pos();
    if (!m_pieRect.contains(pos)) {
        QToolTip::hideText();
        return;
    }

    qreal cx = m_pieRect.center().x();
    qreal cy = m_pieRect.center().y();
    qreal dx = pos.x() - cx;
    qreal dy = pos.y() - cy;
    qreal r = m_pieRect.width() / 2.0;
    if (dx*dx + dy*dy > r*r) {
        QToolTip::hideText();
        return;
    }

    qreal mathY = -dy;
    qreal mathX = dx;
    qreal angleRad = qAtan2(mathY, mathX);
    qreal angleDeg = qRadiansToDegrees(angleRad);
    if (angleDeg < 0) angleDeg += 360.0;

    int sliceIndex = indexAtAngle(int(angleDeg));
    if (sliceIndex >= 0) {
        showSliceTooltip(sliceIndex, globalPosF.toPoint());
    } else {
        QToolTip::hideText();
    }
}

void PieChart::resizeEvent(QResizeEvent *event)
{
    QToolTip::hideText();
    QWidget::resizeEvent(event);
}

int PieChart::indexAtAngle(int angleDeg) const
{
    if (m_data.isEmpty()) return -1;

    int total = 0;
    for (const auto &p : m_data) total += p.second;
    if (total <= 0) return -1;

    qreal cumDeg = 0.0;
    for (int i = 0; i < m_data.size(); ++i) {
        qreal sliceDeg = (qreal)m_data[i].second / total * 360.0;
        qreal nextCum = cumDeg + sliceDeg;
        if (angleDeg >= cumDeg && angleDeg < nextCum) {
            return i;
        }
        cumDeg = nextCum;
    }
    if (angleDeg >= cumDeg && angleDeg < 360.0 + 0.0001) {
        return m_data.size() - 1;
    }
    return -1;
}

void PieChart::showSliceTooltip(int sliceIndex, const QPoint &globalPos)
{
    if (sliceIndex < 0 || sliceIndex >= m_data.size()) {
        QToolTip::hideText();
        return;
    }
    QString protoName = m_data[sliceIndex].first;
    int count = m_data[sliceIndex].second;
    double pct = m_total > 0 ? (double)count * 100.0 / (double)m_total : 0.0;
    QString tip = QString("%1: %2 (%3%)")
                      .arg(protoName)
                      .arg(count)
                      .arg(QString::number(pct, 'f', 1));
    if (QToolTip::text() == tip) {
        return;
    }
    QToolTip::showText(globalPos, tip, this);
}
