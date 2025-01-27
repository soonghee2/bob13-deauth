#ifndef MAC_ADDRESS_H
#define MAC_ADDRESS_H

#include <cstdint>
#include <iostream>
#include <iomanip>

// 맥 주소 구조체
struct MacAddress {
    uint8_t addr[6];
};

// MAC 주소를 생성하는 함수
inline MacAddress make_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
    MacAddress mac = {{a, b, c, d, e, f}};
    return mac;
}

// MAC 주소 출력 함수
inline void print_mac(const MacAddress& mac) {
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac.addr[i]);
        if (i < 5) std::cout << ":";
    }
}

// 문자열을 MAC 주소로 변환하는 함수
MacAddress parse_mac(const char* mac_str) {
    MacAddress mac{};
    int values[6];

    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2], 
               &values[3], &values[4], &values[5]) != 6) {
        std::cerr << "Invalid MAC address format: " << mac_str << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 6; i++) {
        mac.addr[i] = static_cast<uint8_t>(values[i]);
    }
    return mac;
}

#endif
