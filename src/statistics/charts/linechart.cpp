#include "linechart.h"
#include "../../theme/theme.h"
LineChart::LineChart(QWidget *parent)
    : QWidget(parent)
{
    m_sessionsDir = QCoreApplication::applicationDirPath()
                   + "/src/statistics/sessions";

    m_watcher.addPath(m_sessionsDir);
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, [this](){
        loadJson(m_sessionsDir);
        rebuildData();
        update();
    });

    loadJson(m_sessionsDir);
    rebuildData();
}

void LineChart::loadJson(const QString &dir)
{
    m_sessions.clear();
    QDir d(dir);
    QStringList files = d.entryList({"*.json"}, QDir::Files, QDir::Name);

    QMap<QDateTime, SessionData> temp;
    for (const QString &fn : files) {
        QFile f(d.filePath(fn));
        if (!f.open(QIODevice::ReadOnly)) {
            qWarning() << "LineChart: cannot open JSON:" << fn;
            continue;
        }
        auto doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (!doc.isObject())
            continue;
        auto obj = doc.object();
        QDateTime start = QDateTime::fromString(obj["sessionStart"].toString(), Qt::ISODate);
        QDateTime end   = QDateTime::fromString(obj["sessionEnd"].toString(),   Qt::ISODate);
        auto &sd = temp[start];
        if (sd.packetsPerSecond.isEmpty()) {
            sd.start = start;
            sd.end   = end;
        } else {
            sd.end = qMax(sd.end, end);
        }

        auto perSec = obj["perSecond"].toArray();
        for (auto pv : perSec) {
            auto o   = pv.toObject();
            int sec  = o["second"].toInt();
            qint64 p = qRound(o["pps"].toDouble());
            qint64 b = qRound(o["bps"].toDouble());
            sd.packetsPerSecond[sec] += p;
            sd.bytesPerSecond[sec]   += b;
        }
    }

    for (auto sd : temp.values())
        m_sessions.append(sd);
    std::sort(m_sessions.begin(), m_sessions.end(),
              [](auto &a, auto &b){ return a.start < b.start; });
}

void LineChart::setMode(Mode mode)
{
    m_mode = mode;
    chart::currentTimeMode = mode;
    rebuildData();
    update();
}

void LineChart::setSessionIndex(int idx)
{
    m_selectedSession = idx;
    m_mode = Mode::BySession;
    rebuildData();
    update();
}

void LineChart::setMetric(Metric metric)
{
    m_metric = metric;
    rebuildData();
    update();
}

void LineChart::setResolution(Resolution res)
{
    m_resolution = res;
    rebuildData();
    update();
}

void LineChart::rebuildData()
{
    m_points.clear();
    m_maxX = m_maxY = 0;

    QMap<int, QPair<qint64,qint64>> agg;
    QVector<SessionData> chosen;
    if (m_mode == Mode::AllTime) {
        chosen = m_sessions;
    } else if (m_mode == Mode::CurrentSession) {
        if (!m_sessions.isEmpty())
            chosen = { m_sessions.last() };
    } else {
        if (m_selectedSession >= 0
         && m_selectedSession < m_sessions.size())
            chosen = { m_sessions[m_selectedSession] };
    }

    for (auto &s : chosen) {
        for (auto it = s.packetsPerSecond.constBegin();
             it != s.packetsPerSecond.constEnd(); ++it)
        {
            int sec = it.key();
            int bucket;
            switch (m_resolution) {
              case Seconds: bucket = sec;        break;
              case Minutes: bucket = sec/60;     break;
              case Hours:   bucket = sec/3600;   break;
            }
            agg[bucket].first  += s.bytesPerSecond.value(sec,0);
            agg[bucket].second += it.value();
        }
    }

    for (auto it = agg.constBegin(); it != agg.constEnd(); ++it) {
        int bucket = it.key();
        qint64 bytes   = it.value().first;
        qint64 packets = it.value().second;
        double val = 0;
        switch (m_metric) {
          case PacketsPerSecond: val = packets;                 break;
          case BytesPerSecond:   val = bytes;                   break;
          case BitsPerSecond:    val = double(bytes)*8.0;       break;
          case AvgPacketSize:    val = packets>0
                                       ? double(bytes)/packets
                                       : 0.0;                   break;
        }
        m_points.append({ double(bucket), val });
        m_maxX = qMax(m_maxX, double(bucket));
        m_maxY = qMax(m_maxY, val);
    }
}

void LineChart::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const int leftM=60, bottomM=40, rightM=20, topM=20;
    QRectF area(leftM, topM,
                width()-leftM-rightM,
                height()-topM-bottomM);

    // Y-axis label
    QString yLabel;
    switch (m_metric) {
      case PacketsPerSecond:    yLabel = "PPS";         break;
      case BytesPerSecond:      yLabel = "BPS";         break;
      case BitsPerSecond:       yLabel = "bps";         break;
      case AvgPacketSize:       yLabel = "Avg pkt (B)"; break;
    }
    p.save();
    QFontMetrics fm(p.font());
    int textW = fm.horizontalAdvance(yLabel);
    p.translate(leftM/2, height()/2 + textW/2);
    p.rotate(-90);
    p.drawText(0, 0, yLabel);
    p.restore();

    // Grid + Y ticks
    for (int i=1; i<=4; ++i) {
        qreal y = area.bottom() - (i/5.0)*area.height();
        p.setPen(QColor(200,200,200));
        p.drawLine(area.left(), y, area.right(), y);
        p.setPen(Qt::black);
        QString lbl = QString::number((i/5.0)*m_maxY, 'f', 0);
        p.drawText(0, y-8, leftM-5, 16,
                   Qt::AlignRight|Qt::AlignVCenter, lbl);
    }

    // X-axis ticks & labels
    if (m_maxX > 0) {
        p.setPen(Qt::black);
        qreal scaleX = area.width() / (m_maxX * m_zoom);
        for (int b=0; b<=int(m_maxX); ++b) {
            qreal x = area.left() + b*scaleX;
            p.drawLine(x, area.bottom(), x, area.bottom()+5);
            QString label;
            switch (m_resolution) {
              case Seconds: label = QString::number(b);      break;
              case Minutes: label = QString("%1m").arg(b);   break;
              case Hours:   label = QString("%1h").arg(b);   break;
            }
            p.drawText(x-15, area.bottom()+5, 30, bottomM-5,
                       Qt::AlignHCenter|Qt::AlignTop, label);
        }
    }

    // Draw line
    if (!m_points.isEmpty() && m_maxX>0 && m_maxY>0) {
        QPainterPath path;
        qreal scaleX = area.width()  / (m_maxX * m_zoom);
        qreal scaleY = area.height() / m_maxY;
        QVector<QPointF> pts = m_points;
        std::sort(pts.begin(), pts.end(),
                  [](auto &a, auto &b){ return a.x()<b.x(); });
        for (int i=0; i<pts.size(); ++i) {
            qreal x = area.left() + pts[i].x()*scaleX;
            qreal y = area.bottom() - pts[i].y()*scaleY;
            if (i==0) path.moveTo(x,y);
            else      path.lineTo(x,y);
        }
        p.setPen(QPen(Theme::barColor(),2));
        p.drawPath(path);
    }

    // Axes lines
    p.setPen(Qt::black);
    p.drawLine(area.topLeft(),    area.bottomLeft());
    p.drawLine(area.bottomLeft(), area.bottomRight());
}

void LineChart::wheelEvent(QWheelEvent *ev)
{
    if (ev->modifiers() & Qt::ControlModifier) {
        double d = ev->angleDelta().y()>0 ? 1.1 : 0.9;
        m_zoom = qBound(0.2, m_zoom*d, 5.0);
        update();
        ev->accept();
    } else {
        QWidget::wheelEvent(ev);
    }
}

// ————— ACCESSORS —————

QStringList LineChart::availableSessionLabels() const
{
    QStringList list;
    for (auto &s : m_sessions) {
        list << s.start.toString("yyyy-MM-dd hh:mm:ss")
              + " → "
              + s.end.toString("hh:mm:ss");
    }
    return list;
}

QStringList LineChart::availableMetrics() const
{
    return {
        "Packets-per-Second",
        "Bytes-per-Second",
        "Bits-per-Second",
        "Avg Packet Size"
    };
}


void LineChart::mouseMoveEvent(QMouseEvent *ev)
{
    const int leftM=60, bottomM=40, rightM=20, topM=20;
    QRectF area(leftM, topM,
                width()-leftM-rightM,
                height()-topM-bottomM);

    if (!m_points.isEmpty() && m_maxX>0 && m_maxY>0 && area.contains(ev->pos())) {
        qreal scaleX = area.width()  / (m_maxX * m_zoom);
        double hoveredX = (ev->position().x() - area.left()) / scaleX;
        int bestIndex = -1;
        double bestDist = std::numeric_limits<double>::max();
        for (int i=0; i<m_points.size(); ++i) {
            double d = std::fabs(m_points[i].x() - hoveredX);
            if (d < bestDist) { bestDist = d; bestIndex = i; }
        }
        if (bestIndex >= 0) {
            const auto &pt = m_points[bestIndex];
            QString lbl = QString("%1: %2")
                              .arg(pt.x())
                              .arg(QString::number(pt.y(), 'f', 0));
            QToolTip::showText(ev->globalPosition().toPoint(), lbl, this);
        }
    }

    QWidget::mouseMoveEvent(ev);
}

void LineChart::leaveEvent(QEvent *)
{
    QToolTip::hideText();
}