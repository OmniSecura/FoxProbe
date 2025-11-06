#ifndef PAYLOADFORMATTER_H
#define PAYLOADFORMATTER_H

#include <QByteArray>
#include <QString>

namespace PayloadFormatter {

enum class Mode {
    Ascii,
    Hex
};

QString toAscii(const QByteArray &payload);
QString toHex(const QByteArray &payload);
QString format(const QByteArray &payload, Mode mode);

}

#endif // PAYLOADFORMATTER_H
