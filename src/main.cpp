#include <QApplication>
#include <QIcon>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    const QIcon appIcon(QStringLiteral(":/icons/FoxProbe.ico"));
    a.setWindowIcon(appIcon);
    MainWindow w;
    w.setWindowIcon(appIcon);
    w.showMaximized();
    return a.exec();
}
