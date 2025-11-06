#ifndef FILTER_H
#define FILTER_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string>

class Filters {
public:
    Filters();
    ~Filters();

    void netmask_lookup(const std::string& device, char* error);
    bool filter_processing(pcap_t *handle,
                           const char *filter_exp,
                           int optimize,
                           bpf_u_int32 netmask);
    bpf_u_int32 get_net();
    bpf_u_int32 get_mask();

protected:
    pcap_t           *handle;
    std::string       dev;
    struct bpf_program fp;
    bpf_u_int32       mask;
    bpf_u_int32       net;
    bool              m_filterCompiled = false;

    void releaseFilterProgram();
};

#endif // FILTER_H
