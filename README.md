# bob13-deauth
![image](https://github.com/user-attachments/assets/fc354135-7008-41a4-a50c-ceda5f770cd4)

# 1. 이 코드가 하는 일

**무선 인터페이스(mon0 등)로 Deauth / Auth / Assoc 패킷을 전송하여
AP ↔ Station 간 연결을 끊거나 혼란을 발생시키는 공격 툴.**

* 특정 AP → 특정 스테이션을 Deauth
* 스테이션 → AP 방향 Deauth
* 브로드캐스트 Deauth (근처 모든 기기 날아감)
* 혹은 `-auth` 옵션으로 Auth/AUSSO(Association?) 메시지 스팸


---

# 2. 핵심 기능 분석

## ✓ Radiotap + 802.11 Management Frame 구조 직접 생성

`make_packet()`에서 Radiotap 헤더와 802.11 프레임을 수동 조립:

```cpp
frame.subtype = subtype;         // DEAUTH / AUTH
frame.address1 = dest_mac;       // 목적지
frame.address2 = src_mac;        // 출발지
frame.address3 = src_mac;        // BSSID처럼 사용
```

---

# 3. 공격 방식 분기

### ① AP → Station Deauth

```
./deauth wlan0mon <ap-mac> <station-mac>
```

→ AP가 해당 스테이션을 강제로 연결 해제시키는 공격
(실제 WPA/WPA2 재연결 유도 공격에서 자주 사용)

---

### ② Station → AP 방향 Deauth

(양방향 다 전송함)

```cpp
make_packet(packet1, ap_mac, station_mac, DEAUTH);
make_packet(packet2, station_mac, ap_mac, DEAUTH);
```

두 방향 모두 보내서 더 확실하게 연결을 끊어버리는 방식.

---

### ③ 브로드캐스트 Deauth

```
./deauth wlan0mon <ap-mac>
```

→ `ff:ff:ff:ff:ff:ff` 향해 Deauth 스팸
→ AP 주변 모든 기기 네트워크 끊김

---

### ④ Authentication/Association 공격

```
./deauth wlan0mon <ap> <station> -auth
```

여기서는:

* AUTH 패킷 스팸
* AUSSO(Association?) 패킷 스팸

이 두 개를 스레드 2개로 무한 반복 전송함.

실제로 일부 AP에서는 Auth/Assoc 스팸이 연결 장애나 혼선 유발 가능.

---

# 4. 멀티스레드로 스팸 공격 수행

`send_packets()`:

* 스레드 2개를 생성
* 각각 50만 번 반복 전송
* 10ms 간격

즉:

**두 방향(또는 두 종류) 패킷을 동시에 무한 폭격**

---

# 5. 전체 요약

**이 프로그램은 pcap을 이용해 Radiotap + 802.11 Deauth/Auth 패킷을 생성하여
AP–클라이언트 연결을 끊어버리는 공격 툴이다.**

기능:

* AP → Station Deauth
* Station → AP Deauth
* Broadcast Deauth
* Authentication / Association 스팸
* 두 패킷을 멀티스레드로 동시에 무한 전송

전형적인 **WiFi Deauth 공격기** 구조.
