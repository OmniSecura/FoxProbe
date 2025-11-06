#ifndef GEOMAP_H
#define GEOMAP_H

#include <QGraphicsView>
#include <QtSvgWidgets/QGraphicsSvgItem>
#include <QtSvg/QSvgRenderer>
#include <QtXml/QDomDocument>
#include <QStringList>
#include <QByteArray>
#include <QFile>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QDomDocument>
#include <QDomElement>
#include <QDomNodeList>
#include <QGraphicsPathItem>
#include <QGraphicsEllipseItem>
#include <QGraphicsSimpleTextItem>
#include <QVariantAnimation>
#include <QEasingCurve>
#include <QPainterPath>
#include <QPen>
#include <QBrush>

#include <algorithm>
#include <cmath>

class GeoMapWidget : public QGraphicsView {
    Q_OBJECT
public:
    explicit GeoMapWidget(const QString &svgMapFile, QWidget *parent = nullptr);

    void highlightCountries(const QStringList &countryIds);
    void clearOverlay();
    void displayFlightPath(double srcLat, double srcLon,
                           double dstLat, double dstLon,
                           const QString &label,
                           int durationMs = 2500);
    void stopFlightAnimation();

signals:
    void flightAnimationFinished();

protected:
    void resizeEvent(QResizeEvent *event) override;

private:
    QDomElement findElementById(const QDomElement &parent, const QString &id);
    QPointF geoToPoint(double lat, double lon) const;
    void ensureOverlayItems();
    void resetAnimation();

    QGraphicsScene      *scene;
    QSvgRenderer        *svgRenderer;
    QGraphicsSvgItem    *mapItem;
    QByteArray           originalSvgData;
    QDomDocument         originalDoc;
    QGraphicsPathItem   *flightPathItem = nullptr;
    QGraphicsEllipseItem *planeItem = nullptr;
    QGraphicsEllipseItem *srcMarker = nullptr;
    QGraphicsEllipseItem *dstMarker = nullptr;
    QGraphicsSimpleTextItem *flightLabel = nullptr;
    QVariantAnimation   *flightAnimation = nullptr;
    QPainterPath         currentFlightPath;
};

#endif // GEOMAP_H
