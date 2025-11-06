#pragma once

#include <QWidget>
#include <QDateTime>
#include <QMap>
#include <QVector>
#include <QStringList>
#include <QFileSystemWatcher>
#include <QPointF>
#include <QPair>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QPainter>
#include <QPainterPath>
#include <QCoreApplication>
#include <QDebug>
#include <QToolTip>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QRectF>
#include <QSet>
#include <algorithm>
#include <QList>
#include <QString>
#include <QPaintEvent>
#include <QtMath>
#include <QDialog>
#include <QMenuBar>
#include <QPushButton>
#include <QStackedWidget>
#include <QComboBox>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QTextStream>
#include <QPixmap>
#include <QCheckBox>
#include <QDir>
#include <QFileInfo>
#include <limits>
#include <cmath>

namespace chart {
    enum class Mode { AllTime, CurrentSession, BySession };
    inline Mode currentTimeMode = Mode::AllTime;
}
