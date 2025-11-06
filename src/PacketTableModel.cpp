#include "PacketTableModel.h"

#include "../packets/sniffing.h"
#include "../packets/packethelpers.h"

PacketTableModel::PacketTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_rows.size();
}

int PacketTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_headers.size();
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size())
        return {};

    const PacketTableRow &r = m_rows.at(index.row());

    if (role == Qt::DisplayRole) {
        return r.columns.value(index.column());
    }
    if (role == Qt::UserRole && index.column() == ColumnInfo) {
        return r.rawData;
    }
    if (role == Qt::BackgroundRole && r.background.isValid()) {
        return r.background;
    }

    return {};
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        return m_headers.value(section);
    }
    return QAbstractTableModel::headerData(section, orientation, role);
}

void PacketTableModel::addPacket(const PacketTableRow &row)
{
    beginInsertRows(QModelIndex(), m_rows.size(), m_rows.size());
    m_rows.append(row);
    endInsertRows();
}

PacketTableRow PacketTableModel::row(int index) const
{
    return m_rows.value(index);
}

QByteArray PacketTableModel::payloadForRow(int index) const
{
    if (index < 0 || index >= m_rows.size())
        return {};

    const PacketTableRow &r = m_rows.at(index);
    if (r.rawData.isEmpty())
        return {};

    const QByteArray &raw = r.rawData;
    const u_char *pkt = reinterpret_cast<const u_char*>(raw.constData());

    int offset = linkHdrLen(r.linkType);
    if (offset >= raw.size())
        return {};

    const uint16_t type = ethType(pkt, r.linkType);
    if (type == ETHERTYPE_IP) {
        offset += ipv4HdrLen(pkt, r.linkType);
    } else if (type == ETHERTYPE_IPV6) {
        offset += sizeof(sniff_ipv6);
    }

    if (offset < 0 || offset > raw.size())
        return {};

    return raw.mid(offset);
}

void PacketTableModel::clear()
{
    beginResetModel();
    m_rows.clear();
    endResetModel();
}

void PacketTableModel::setRowBackground(int index, const QColor &color)
{
    if (index < 0 || index >= m_rows.size())
        return;

    if (m_rows[index].background == color)
        return;

    m_rows[index].background = color;
    const QModelIndex left = createIndex(index, 0);
    const QModelIndex right = createIndex(index, ColumnCount - 1);
    emit dataChanged(left, right, {Qt::BackgroundRole});
}
