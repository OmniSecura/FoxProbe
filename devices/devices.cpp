#include "devices.h"

Devices::Devices() {
}

Devices::~Devices() {
}

pcap_t* Devices::init_packet_capture(const char* interface, bool promiscuous){
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, promiscuous, 1000, this->error_buffer);

    if (handle == nullptr){
        qWarning() << "Nie można otworzyć urządzenia:" << this->error_buffer;
        return nullptr;
    }
    else{
        qDebug() << "Sesja otwarta dla interfejsu:" << interface;
        return handle;
    }
        
}

