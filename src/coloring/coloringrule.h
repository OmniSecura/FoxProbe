#ifndef COLORINGRULE_H
#define COLORINGRULE_H
#include <QString>
#include <QColor>
#include <pcap.h>

struct ColoringRule {
    QString     bpfExpression; 
    QColor      color;       
    bpf_program prog;        

    bool compile(pcap_t* handle, bpf_u_int32 netmask) {
        if (pcap_compile(handle, &prog,
                         bpfExpression.toUtf8().constData(),
                         /*optimize=*/1, netmask) != 0)
            return false;
        return true;
    }

    bool matches(const pcap_pkthdr* hdr, const u_char* pkt) const {
        return pcap_offline_filter(&prog, hdr, pkt) != 0;
    }
};
#endif //COLORINGRULE_H