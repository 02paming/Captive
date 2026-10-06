#include "pcap_project.h"

void* uds_server_thread(void* arg) {
    int server_fd, client_fd;
    struct sockaddr_un addr;
    char buffer[32];

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("UDS 소켓 생성 실패");
        return NULL;
    }

    unlink(SOCKET_PATH); // 기존에 남아있는 소켓 파일 찌꺼기 삭제

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("UDS 바인드 실패");
        close(server_fd);
        return NULL;
    }

    if(listen(server_fd, 5) < 0){
        perror("UDS 리슨 실패");
        close(server_fd);
        return NULL;
    }

    while(1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            
            //파이썬에서 얻은 값, 리드받아서
            int read_bytes = read(client_fd, buffer, sizeof(buffer) - 1);
            if (read_bytes > 0) {
                buffer[read_bytes] = '\0';
                

                //받은값 문자열을 정수로 바꿈 예를들어 "55\n" 이렇게 받은걸 50 으로
                int host_id = atoi(buffer); 

                // 배열 범위 초과 방지 및 뮤텍스 락 걸고 업데이트
                if (host_id >= 0 && host_id <= 254) { //게이트웨이와 브로드캐스트는 제외

                    //뮤텍스라는 개념을 공부함
                    //여러스레드가 하나뿐인 공용장소를(지금으로썬 화이트리스트배열) 동시에 건드려 데이터가 꼬이는걸 방지 
                    //지금 uds스레드에선 인증완료(1)라고 적는곳
                    //pcap스레드에선 계속지나가는 패킷을 검수하며 화이트리스트배열을 읽는곳
                    //이때 적고있는중에 읽는다면 오작동이날수있음 이를 방지하기위해 
                    //배열의 값을 변경하거나 읽어오는 그 아주 짧은 찰나의 순간에, 절대 두 스레드가 동시에 접근하지 못하도록 방지하는 개념
                    //공용으로읽을메모리는 보관함에넣어두고 필요할때는 열쇠를 들고갓다가 반납해라는 개념
                    
                    pthread_mutex_lock(&lock);
                    whitelist[host_id] = 1; 
                    pthread_mutex_unlock(&lock);
                    
                    printf("[UDS 스레드] Host ID %d 인증 완료. 화이트리스트 등록.\n", host_id);
                }
            }
            close(client_fd);
        }
    }
    close(server_fd);
    return NULL;
}