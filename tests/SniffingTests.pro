QT += core testlib
CONFIG += console c++17
TEMPLATE = app
TARGET = SniffingTests

SOURCES += ../packets/sniffing.cpp \
           ../src/appsettings.cpp \
           tst_sniffing.cpp \
           tst_appsettings.cpp \
           test_main.cpp


HEADERS += tst_sniffing.h \
           tst_appsettings.h

INCLUDEPATH += .. \
               ../protocols \
               ../packets \
               ../src \
               ../devices \
               ../filter

LIBS += -lpcap