#include "barchart.h"
#include "../../theme/theme.h"  

BarChart::BarChart(QWidget *parent)
    : QWidget(parent)
{
    m_sessionsDir = QCoreApplication::applicationDirPath()
                   + "/src/statistics/sessions";

    m_watcher.addPath(m_sessionsDir);
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, [this](){
        loadJson(m_sessionsDir);
        rebuildAggregation();
        update();
    });

    setMouseTracking(true);
    loadJson(m_sessionsDir);
    rebuildAggregation();
}

void BarChart::loadJson(const QString &dir)
{
    m_sessions.clear();
    QDir d(dir);
    QStringList files = d.entryList({"*.json"}, QDir::Files, QDir::Name);

    QMap<QDateTime, SessionData> temp;
    for (const QString &fn : files) {
        QFile f(d.filePath(fn));
        if (!f.open(QIODevice::ReadOnly)) {
            qWarning() << "BarChart: cannot open JSON:" << fn;
            continue;
        }
        auto doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (!doc.isObject())
            continue;
        auto obj = doc.object();
        QDateTime start = QDateTime::fromString(obj["sessionStart"].toString(),
                                                Qt::ISODate);
        QDateTime end   = QDateTime::fromString(obj["sessionEnd"].toString(),
                                                Qt::ISODate);
        auto &sd = temp[start];
        if (sd.protocolCounts.isEmpty()) {
            sd.sessionStart = start;
            sd.sessionEnd   = end;
        } else {
            sd.sessionEnd = qMax(sd.sessionEnd, end);
        }
        auto perSec = obj["perSecond"].toArray();
        for (auto pv : perSec) {
            auto counts = pv.toObject()["protocolCounts"].toObject();
            for (auto key : counts.keys())
                sd.protocolCounts[key] += counts[key].toInt();
        }
    }

    for (auto sd : temp.values())
        m_sessions.append(sd);

    std::sort(m_sessions.begin(), m_sessions.end(),
              [](auto &a, auto &b){ return a.sessionStart < b.sessionStart; });
}

void BarChart::setMode(Mode mode)       
{ m_mode = mode; chart::currentTimeMode = mode; rebuildAggregation(); update(); }
void BarChart::setSessionIndex(int i)  
{ m_selectedSession = i; m_mode = Mode::BySession; rebuildAggregation(); update(); }
void BarChart::setProtocolFilter(const QStringList &p)
{ m_protocolFilter = p; rebuildAggregation(); update(); }
void BarChart::setSortMode(SortMode s) 
{ m_sortMode = s; rebuildAggregation(); update(); }

void BarChart::rebuildAggregation()
{
    m_currentPlot.clear();
    QVector<SessionData> chosen;
    switch (m_mode) {
      case Mode::AllTime:
        chosen = m_sessions;
        break;
      case Mode::CurrentSession:
        if (!m_sessions.isEmpty())
            chosen = { m_sessions.last() };
        break;
      case Mode::BySession:
        if (m_selectedSession >= 0
         && m_selectedSession < m_sessions.size())
            chosen = { m_sessions[m_selectedSession] };
        break;
    }

    for (auto &s : chosen) {
        for (auto it = s.protocolCounts.constBegin();
             it != s.protocolCounts.constEnd(); ++it)
        {
            if (!m_protocolFilter.isEmpty()
             && !m_protocolFilter.contains(it.key()))
                continue;
            m_currentPlot[it.key()] += it.value();
        }
    }
    m_totalCount = 0;
    for (auto v : m_currentPlot.values())
        m_totalCount += v;
}

void BarChart::rebuildKeysAndRects(const QRectF &area)
{
    m_barKeys = m_currentPlot.keys();
    if (m_sortMode == ByValue) {
        std::sort(m_barKeys.begin(), m_barKeys.end(),
                  [&](auto &a, auto &b){
                      return m_currentPlot[a] > m_currentPlot[b];
                  });
    } else {
        std::sort(m_barKeys.begin(), m_barKeys.end());
    }

    m_barRects.clear();
    qint64 maxv = 0;
    for (auto v : m_currentPlot.values())
        maxv = qMax(maxv, v);
    int n = m_barKeys.size();
    if (n == 0 || maxv <= 0) return;

    qreal barW = (area.width() * m_zoom) / (n * 1.5);
    for (int i = 0; i < n; ++i) {
        qreal x = area.left() + i * 1.5 * barW;
        qreal h = double(m_currentPlot[m_barKeys[i]]) / maxv * area.height();
        m_barRects.append({ x, area.bottom() - h, barW, h });
    }
}

void BarChart::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const int leftM = 60, bottomM = 40, rightM = 20, topM = 20;
    QRectF area(leftM, topM,
                width() - leftM - rightM,
                height() - topM - bottomM);

    // Axis titles
    p.setPen(Qt::black);
    p.drawText(0, topM, leftM - 5, 20,
               Qt::AlignRight | Qt::AlignVCenter, "Count");
    p.drawText(leftM, height() - bottomM + 5,
               area.width(), bottomM - 5,
               Qt::AlignHCenter | Qt::AlignTop,
               "Protocol");

    // Grid + ticks
    qint64 maxv = 0;
    for (auto v : m_currentPlot.values())
        maxv = qMax(maxv, v);
    for (int i = 1; i <= 4; ++i) {
        qreal y = area.bottom() - (i / 5.0) * area.height();
        p.setPen(QColor(200,200,200));
        p.drawLine(area.left(), y, area.right(), y);
        p.setPen(Qt::black);
        QString lbl = QString::number((i / 5.0) * maxv);
        p.drawText(0, y - 8, leftM - 5, 16,
                   Qt::AlignRight | Qt::AlignVCenter, lbl);
    }

    // Bars
    rebuildKeysAndRects(area);
    QColor col = Theme::barColor();
    for (int i = 0; i < m_barRects.size(); ++i) {
        p.setBrush(col);
        p.setPen(Qt::NoPen);
        p.drawRect(m_barRects[i]);

        p.setPen(Qt::black);
        p.drawText(m_barRects[i].x(),
                   area.bottom() + 5,
                   m_barRects[i].width(), 20,
                   Qt::AlignHCenter | Qt::AlignTop,
                   m_barKeys[i]);

        if (i == m_hoverIndex) {
            p.setBrush(QColor(255,255,255,80));
            p.drawRect(m_barRects[i]);
        }
    }

    // Axes lines
    p.setPen(Qt::black);
    p.drawLine(area.topLeft(), area.bottomLeft());
    p.drawLine(area.bottomLeft(), area.bottomRight());
}

void BarChart::mouseMoveEvent(QMouseEvent *ev)
{
    int old = m_hoverIndex;
    m_hoverIndex = -1;
    for (int i = 0; i < m_barRects.size(); ++i) {
        if (m_barRects[i].contains(ev->pos())) {
            m_hoverIndex = i;
            QString k = m_barKeys[i];
            qint64 v = m_currentPlot[k];
            double pct = m_totalCount > 0 ?
                    double(v) * 100.0 / double(m_totalCount) : 0.0;
            QPoint gp = ev->globalPosition().toPoint();
            QString tip = QString("%1: %2 (%3%)")
                              .arg(k)
                              .arg(v)
                              .arg(QString::number(pct, 'f', 1));
            QToolTip::showText(gp, tip, this);
            break;
        }
    }
    if (old != m_hoverIndex)
        update();
}
void BarChart::leaveEvent(QEvent *)
{
    m_hoverIndex = -1;
    update();
}

void BarChart::wheelEvent(QWheelEvent *ev)
{
    if (ev->modifiers() & Qt::ControlModifier) {
        double delta = ev->angleDelta().y() > 0 ? 1.1 : 0.9;
        m_zoom = qBound(0.2, m_zoom * delta, 5.0);
        update();
        ev->accept();
    } else {
        QWidget::wheelEvent(ev);
    }
}

QStringList BarChart::availableSessionLabels() const
{
    QStringList list;
    for (auto &s : m_sessions) {
        list << s.sessionStart.toString("yyyy-MM-dd hh:mm:ss")
              + " → "
              + s.sessionEnd.toString("hh:mm:ss");
    }
    return list;
}

QStringList BarChart::availableProtocols() const
{
    QSet<QString> set;
    for (auto &s : m_sessions)
        for (auto key : s.protocolCounts.keys())
            set.insert(key);
    auto l = set.values();
    std::sort(l.begin(), l.end());
    return l;
}
