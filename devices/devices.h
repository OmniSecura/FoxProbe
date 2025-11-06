#ifndef DEVICES_H
#define DEVICES_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <QDebug>

class Devices {
public:
    Devices();
    ~Devices();
    char    error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* init_packet_capture(const char* interface, bool promiscuous);
};

#endif // DEVICES_H
