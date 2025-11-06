#ifndef PACKETTABLEMODEL_H
#define PACKETTABLEMODEL_H

#include <QAbstractTableModel>
#include <QColor>
#include <QByteArray>
#include <QStringList>
#include <QVector>

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

struct PacketTableRow {
    QStringList columns; // column texts: No., Time, Source, Destination, Protocol, Length, Info
    QByteArray rawData;  // packet raw bytes
    QColor background;   // background color
    int linkType = DLT_EN10MB;
};


enum PacketColumns {
    ColumnNumber = 0,
    ColumnTime,
    ColumnSource,
    ColumnDestination,
    ColumnProtocol,
    ColumnLength,
    ColumnInfo,
    ColumnCount
};

class PacketTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit PacketTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    void addPacket(const PacketTableRow &row);
    PacketTableRow row(int index) const;
    QByteArray payloadForRow(int index) const;
    void clear();
    void setRowBackground(int index, const QColor &color);

private:
    QVector<PacketTableRow> m_rows;
    const QStringList m_headers = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
};

#endif // PACKETTABLEMODEL_H
