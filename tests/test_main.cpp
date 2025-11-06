#include <QTest>

#include "tst_sniffing.h"
#include "tst_appsettings.h"

int main(int argc, char **argv)
{
    int status = 0;

    {
        SniffingTest sniffing;
        status |= QTest::qExec(&sniffing, argc, argv);
    }

    {
        AppSettingsTest appSettings;
        status |= QTest::qExec(&appSettings, argc, argv);
    }

    return status;
}