#include "filter.h"

#include <cstring>

Filters::Filters(){
    std::memset(&fp, 0, sizeof(fp));
}

Filters::~Filters(){
    releaseFilterProgram();
}

void Filters::netmask_lookup(const std::string& device, char* error) {
    if (pcap_lookupnet(device.c_str(), &net, &mask, error) == -1) {
        std::cerr << "pcap_lookupnet() failed: " << error << std::endl;
        net = 0;
        mask = 0;
    }
}

bool Filters::filter_processing(pcap_t *handle, const char *filter_exp, int optimize, bpf_u_int32 netmask) {
    if (pcap_compile(handle, &fp, filter_exp, optimize, netmask) == -1) {
        std::cerr << "pcap_compile() failed: " << pcap_geterr(handle) << std::endl;
        return false;
    }
    m_filterCompiled = true;
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter() failed: " << pcap_geterr(handle) << std::endl;
        releaseFilterProgram();
        return false;
    }
    releaseFilterProgram();
    return true;
}

bpf_u_int32 Filters::get_net(){
    return net;
}

bpf_u_int32 Filters::get_mask()
{
    return mask;
}

void Filters::releaseFilterProgram()
{
    if (m_filterCompiled) {
        pcap_freecode(&fp);
        m_filterCompiled = false;
        std::memset(&fp, 0, sizeof(fp));
    }
}
