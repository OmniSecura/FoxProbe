#include "GeoMap.h"

#include <QGraphicsScene>
#include <QPainter>
#include <QFont>

GeoMapWidget::GeoMapWidget(const QString &svgMapFile, QWidget *parent)
    : QGraphicsView(parent),
      scene(new QGraphicsScene(this)),
      svgRenderer(new QSvgRenderer(this)),
      mapItem(new QGraphicsSvgItem())
{
    QFile f(svgMapFile);
    if (f.open(QIODevice::ReadOnly)) {
        originalSvgData = f.readAll();
        originalDoc.setContent(originalSvgData);
        f.close();
    }

    svgRenderer->load(originalSvgData);
    mapItem->setSharedRenderer(svgRenderer);
    scene->addItem(mapItem);
    scene->setSceneRect(mapItem->boundingRect());

    setScene(scene);
    setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
    fitInView(mapItem->boundingRect(), Qt::KeepAspectRatio);
}

void GeoMapWidget::highlightCountries(const QStringList &countryIds)
{
    QDomDocument doc = originalDoc;
    QDomElement root = doc.documentElement();
    for (const QString &cid : countryIds) {
        QDomElement group = findElementById(root, cid);
        if (group.isNull())
            continue;

        QDomNodeList paths = group.elementsByTagName("path");
        for (int i = 0; i < paths.count(); ++i) {
            QDomElement path = paths.at(i).toElement();
            QString style = path.attribute("style");

            if (!style.isEmpty()) {
                if (style.contains("fill:")) {
                    style.replace(QRegularExpression("fill:[^;]+"),
                                  "fill:#FF6B6B");
                } else {
                    style += ";fill:#FF6B6B";
                }
                path.setAttribute("style", style);
            } else {
                path.setAttribute("fill", "#FF6B6B");
            }
        }
    }
    QByteArray newSvg = doc.toByteArray();
    svgRenderer->load(newSvg);
    mapItem->update();
}

void GeoMapWidget::clearOverlay()
{
    resetAnimation();
    currentFlightPath = QPainterPath();

    if (flightPathItem)
        flightPathItem->setVisible(false);
    if (planeItem)
        planeItem->setVisible(false);
    if (srcMarker)
        srcMarker->setVisible(false);
    if (dstMarker)
        dstMarker->setVisible(false);
    if (flightLabel)
        flightLabel->setVisible(false);
}

void GeoMapWidget::displayFlightPath(double srcLat, double srcLon,
                                     double dstLat, double dstLon,
                                     const QString &label,
                                     int durationMs)
{
    // guard against invalid coordinates
    if (!std::isfinite(srcLat) || !std::isfinite(srcLon) ||
        !std::isfinite(dstLat) || !std::isfinite(dstLon)) {
        clearOverlay();
        emit flightAnimationFinished();
        return;
    }

    ensureOverlayItems();

    QPointF srcPoint = geoToPoint(srcLat, srcLon);
    QPointF dstPoint = geoToPoint(dstLat, dstLon);

    // If the scene rect is empty (e.g. map failed to load) bail out gracefully
    if (scene->sceneRect().isEmpty()) {
        clearOverlay();
        emit flightAnimationFinished();
        return;
    }

    resetAnimation();

    // Compose a curved path between points for a "flight" arc
    QPainterPath path(srcPoint);
    QPointF mid = (srcPoint + dstPoint) / 2.0;
    QPointF diff = dstPoint - srcPoint;
    double length = std::hypot(diff.x(), diff.y());
    QPointF normal(0.0, 0.0);
    if (length > 0.0) {
        normal = QPointF(-diff.y() / length, diff.x() / length);
    }
    double curveStrength = qMin(scene->sceneRect().width(), scene->sceneRect().height()) * 0.15;
    QPointF control = mid + normal * curveStrength;
    path.quadTo(control, dstPoint);

    currentFlightPath = path;
    flightPathItem->setPath(currentFlightPath);
    flightPathItem->setVisible(true);

    srcMarker->setPos(srcPoint);
    srcMarker->setVisible(true);
    dstMarker->setPos(dstPoint);
    dstMarker->setVisible(true);

    planeItem->setPos(srcPoint);
    planeItem->setVisible(true);

    if (flightLabel) {
        flightLabel->setText(label);
        QPointF labelPoint = currentFlightPath.pointAtPercent(0.5);
        flightLabel->setPos(labelPoint + QPointF(10, -10));
        flightLabel->setVisible(!label.isEmpty());
    }

    if (durationMs <= 0 || currentFlightPath.length() == 0.0) {
        emit flightAnimationFinished();
        return;
    }

    flightAnimation = new QVariantAnimation(this);
    flightAnimation->setStartValue(0.0);
    flightAnimation->setEndValue(1.0);
    flightAnimation->setDuration(durationMs);
    flightAnimation->setEasingCurve(QEasingCurve::InOutSine);

    connect(flightAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant &value) {
        double t = value.toDouble();
        QPointF point = currentFlightPath.pointAtPercent(t);
        planeItem->setPos(point);
    });
    connect(flightAnimation, &QVariantAnimation::finished, this, [this]() {
        emit flightAnimationFinished();
    });

    flightAnimation->start();
}

void GeoMapWidget::stopFlightAnimation()
{
    resetAnimation();
}

void GeoMapWidget::resizeEvent(QResizeEvent *event)
{
    QGraphicsView::resizeEvent(event);
    fitInView(mapItem->boundingRect(), Qt::KeepAspectRatio);
}

QDomElement GeoMapWidget::findElementById(const QDomElement &parent,
                                          const QString &id)
{
    if (parent.attribute("id") == id)
        return parent;

    QDomElement child = parent.firstChildElement();
    while (!child.isNull()) {
        QDomElement found = findElementById(child, id);
        if (!found.isNull())
            return found;
        child = child.nextSiblingElement();
    }
    return QDomElement();
}

QPointF GeoMapWidget::geoToPoint(double lat, double lon) const
{
    // Clamp to map bounds
    lat = std::clamp(lat, -90.0, 90.0);
    lon = std::clamp(lon, -180.0, 180.0);

    QRectF rect = mapItem->boundingRect();
    double x = rect.left() + ((lon + 180.0) / 360.0) * rect.width();
    double y = rect.top() + ((90.0 - lat) / 180.0) * rect.height();

    return mapItem->mapToScene(QPointF(x, y));
}

void GeoMapWidget::ensureOverlayItems()
{
    if (!flightPathItem) {
        flightPathItem = new QGraphicsPathItem;
        flightPathItem->setZValue(5);
        QPen pen(QColor("#2196F3"));
        pen.setWidthF(2.0);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        flightPathItem->setPen(pen);
        scene->addItem(flightPathItem);
    }
    if (!planeItem) {
        planeItem = new QGraphicsEllipseItem(-6, -6, 12, 12);
        planeItem->setBrush(QColor("#FFD166"));
        planeItem->setPen(Qt::NoPen);
        planeItem->setZValue(6);
        planeItem->setVisible(false);
        scene->addItem(planeItem);
    }
    if (!srcMarker) {
        srcMarker = new QGraphicsEllipseItem(-4, -4, 8, 8);
        srcMarker->setBrush(QColor("#06D6A0"));
        srcMarker->setPen(Qt::NoPen);
        srcMarker->setZValue(6);
        srcMarker->setVisible(false);
        scene->addItem(srcMarker);
    }
    if (!dstMarker) {
        dstMarker = new QGraphicsEllipseItem(-4, -4, 8, 8);
        dstMarker->setBrush(QColor("#EF476F"));
        dstMarker->setPen(Qt::NoPen);
        dstMarker->setZValue(6);
        dstMarker->setVisible(false);
        scene->addItem(dstMarker);
    }
    if (!flightLabel) {
        flightLabel = new QGraphicsSimpleTextItem;
        QFont font = flightLabel->font();
        font.setPointSizeF(font.pointSizeF() + 2.0);
        flightLabel->setFont(font);
        flightLabel->setBrush(Qt::white);
        flightLabel->setZValue(7);
        flightLabel->setVisible(false);
        scene->addItem(flightLabel);
    }
}

void GeoMapWidget::resetAnimation()
{
    if (flightAnimation) {
        flightAnimation->stop();
        flightAnimation->deleteLater();
        flightAnimation = nullptr;
    }
}
