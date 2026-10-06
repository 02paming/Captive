#include "pcap_project.h"

// 디바이스와 핸들을 하나로 묶어 관리
typedef struct Device
{
    pcap_if_t *dev;
    pcap_t *handle;
} Device;

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "tcp port 80";

    pcap_if_t *alldevs, *target;
    Device devices[2] = {
        0,
    };

    // 1. 전체 디바이스 목록 검색 (alldevs에는 다 이시점에서 들어감 순회로)
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 2. 버퍼 누수 이슈로 하나 대신해서 할당시킬 target지정
    target = alldevs;

    // eno2부터니까 일단 for문대신 두번 next
    target = target->next;
    target = target->next;

    // 3. 만든 구조체 배열에 디바이스 정보 할당
    for (int i = 0; i < 2; i++)
    {
        if (target == NULL)
        {
            fprintf(stderr, "Error: Not enough devices found!\n");
            pcap_freealldevs(alldevs);
            return 1;
        }
        devices[i].dev = target;
        target = target->next;
    }

    printf("mirror(캡쳐용) Device : %s\n", devices[0].dev->name);
    printf("Inject(인젝션용) Device  : %s\n", devices[1].dev->name);

    // 4. 배열을 활용한 지정한 디바이스를통한 핸들세션 열기
    devices[0].handle = pcap_open_live(devices[0].dev->name, BUFSIZ, 1, 1, errbuf); // rx (Promisc) 패킷을 들어오게끔만
    devices[1].handle = pcap_open_live(devices[1].dev->name, BUFSIZ, 0, 0, errbuf); // tx 패킷이 나가게만

    if (devices[0].handle == NULL || devices[1].handle == NULL)
    {
        fprintf(stderr, "Couldn't open devices.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_setdirection(devices[0].handle, PCAP_D_IN);  // rx
    pcap_setdirection(devices[1].handle, PCAP_D_OUT); // tx

    // 5. 캡처 디바이스의 데이터링크 검증
    if (pcap_datalink(devices[0].handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Error: Device %s 은 이더넷이 아닙니다!\n", devices[0].dev->name);
        pcap_close(devices[0].handle);
        pcap_close(devices[1].handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 6. 필터 컴파일 적용
    // setfilter는 컴파일함수와 한세트이므로 그냥 || 으로 묶고 자원반납구문 줄임
    if (pcap_compile(devices[0].handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(devices[0].handle, &filter) == -1)
    {
        fprintf(stderr, "Filter setup failed.\n");
        pcap_close(devices[0].handle);
        pcap_close(devices[1].handle);
        pcap_freealldevs(alldevs);
        return 1;
    }
    pcap_freecode(&filter);

    // 7. 루프시작(인젝트는 args로 넘김)
    pcap_loop(devices[0].handle, 0, packet_handler, (u_char *)devices[1].handle);

    // 8. 자원반납(역순)
    pcap_close(devices[0].handle);
    pcap_close(devices[1].handle);
    pcap_freealldevs(alldevs);

    return 0;
}