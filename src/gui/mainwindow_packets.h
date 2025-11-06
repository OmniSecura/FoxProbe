#ifndef MAINWINDOW_PACKETS_H
#define MAINWINDOW_PACKETS_H
#include "../mainwindow.h"

// void onPacketClicked(int row, int col); //QTableWidget before QTableView
void onPacketClicked(const QModelIndex &index);
QStringList infoColumn(const QStringList &parts, const u_char *pkt, int linkType);
void onPacketTableContextMenu(const QPoint &pos);
void addLayerToTree(QTreeWidget *tree, const PacketLayer &lay);
void startNewSession();
void showColorizeCustomizer();
void toggleTheme();

#endif //MAINWINDOW_PACKETS_H
