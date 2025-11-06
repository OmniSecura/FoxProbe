#include "payloadformatter.h"

namespace PayloadFormatter {

static bool isPrintable(unsigned char ch)
{
    return (ch >= 0x20 && ch <= 0x7E) || ch == '\n' || ch == '\r' || ch == '\t';
}

QString toAscii(const QByteArray &payload)
{
    QString result;
    result.reserve(payload.size());
    for (unsigned char ch : payload) {
        if (isPrintable(ch)) {
            result.append(QChar::fromLatin1(static_cast<char>(ch)));
        } else {
            result.append(QChar::fromLatin1('.'));
        }
    }
    return result;
}

QString toHex(const QByteArray &payload)
{
    if (payload.isEmpty())
        return {};

    QByteArray hex = payload.toHex(' ');
    return QString::fromLatin1(hex).toUpper();
}

QString format(const QByteArray &payload, Mode mode)
{
    switch (mode) {
    case Mode::Ascii:
        return toAscii(payload);
    case Mode::Hex:
        return toHex(payload);
    }
    return {};
}

}
