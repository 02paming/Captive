#include "pcap_common.h"
#include "hash_manager.h"


// =========================
// 해시 방패 매니저 
// =========================

// 1. djb2 알고리즘 (글자를 수학 공식에 넣어 0~100002 사이의 방 번호로 즉시 뱉어냄)
unsigned long hash_djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % HASH_SIZE; // 10만 개의 방 안으로 번호 우겨넣기
}

// 2. 방패 깎기 (서버 켜질 때 & RELOAD 될 때 사용)
HashTable* create_hash_table() {
    HashTable *ht = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < HASH_SIZE; i++) {
        ht->table[i] = NULL; // 처음에 모든 방은 비워둠
    }
    pthread_mutex_init(&ht->shield_lock, NULL);
    return ht;
}

// 3. 도메인 쑤셔넣기 (AI가 차단했거나, 처음 txt 파일 읽어올 때)
void insert_hash_table(HashTable *ht, const char *domain, int block_type, double score) {
    if (!ht || !domain) return;
    
    pthread_mutex_lock(&ht->shield_lock);

    unsigned long index = hash_djb2(domain); // 방 번호 찾기 (0초컷)
    
    // 이미 같은 도메인이 꽂혀있는지 확인 (중복 방지)
    HashNode *current = ht->table[index];
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) {
            current->block_type = block_type; // 상태 덮어쓰기!
            current->ai_score = score;

    pthread_mutex_unlock(&ht->shield_lock);
            return; 
        }
        current = current->next;
    }
    
    // 새로운 도메인 노드 생성해서 그 방 맨 앞에 꽂기 (0.000001초 컷)
    HashNode *new_node = (HashNode*)malloc(sizeof(HashNode));
    strncpy(new_node->domain, domain, sizeof(new_node->domain) - 1);
    new_node->domain[sizeof(new_node->domain) - 1] = '\0';
    

    new_node->block_type = block_type;
    new_node->ai_score = score;

    new_node->next = ht->table[index];
    ht->table[index] = new_node;

    pthread_mutex_unlock(&ht->shield_lock);
}

// 4. 특정도메인(노드) 찾아서 삭제
int delete_from_hash_table(HashTable *ht, const char *domain) {
    if (!ht || !domain) return 0; // 실패(삭제할 내용 없음)

    // pthread_mutex_lock(&ht->shield_lock);

    unsigned long index = hash_djb2(domain); // 삭제할 방 번호 찾기
    HashNode *current = ht->table[index];
    HashNode *prev = NULL;

    // 해당 방의 연결 리스트를 순회하며 도메인 찾기
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) { 
            // 🎯 찾았다! 
            
            // 1. 앞뒤 노드 연결줄 끊고 이어붙이기
            if (prev == NULL) {
                // 맨 앞 노드(Head)를 삭제하는 경우
                ht->table[index] = current->next;
            } else {
                // 중간이나 끝 노드를 삭제하는 경우
                prev->next = current->next;
            }

            // 2. 메모리 해제 (C언어 메모리 누수 방지)
            // (※ 주의: insert 하실 때 domain을 strdup나 malloc으로 동적 할당하셨다면
            // 여기서 free(current->domain); 도 반드시 해주셔야 합니다.)
            free(current); // 노드 자체를 메모리에서 완전히 날림

            // 3. 카운트 차감 (ht->count 가 있다면 추가)
            // ht->count--; 
            // pthread_mutex_unlock(&ht->shield_lock);
            return 1; // 삭제 성공! (true)
        }
        
        // 못 찾았으면 다음 노드로 이동
        prev = current;
        current = current->next;
    }

    // pthread_mutex_unlock(&ht->shield_lock);
    return 0; // 해당 도메인이 방패에 없음 (false)
}

// 4. 초고속 탐색 (패킷이 들어올 때마다 검사하는 제일 중요한 함수)
HashNode* lookup_hash_table(HashTable *ht, const char *domain) {
    if (!ht || !domain) return 0; // 0은 false를 의미
    
    // pthread_mutex_lock(&shield_lock);

    unsigned long index = hash_djb2(domain); // 수학 공식 돌려서 방 번호 즉시 도출
    HashNode *current = ht->table[index];
    
    // 그 방에 가서 도메인이 맞는지 딱 확인
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) {
            // pthread_mutex_unlock(&shield_lock);
            return current; // 찾음! (true = 차단해라!)
        }
        current = current->next;
    }

    // pthread_mutex_unlock(&shield_lock);
    return NULL; // 못 찾음 (false = 미지의 도메인이니 AI한테 넘겨라!)
}

void clear_hash_table(HashTable* ht) {
    if (ht == NULL) return;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        HashNode* current = ht->table[i];
        while (current != NULL) {
            HashNode* temp = current;
            current = current->next;
            free(temp); // ★ 이 free가 없으면 RELOAD 때마다 메모리가 터집니다!
        }
        ht->table[i] = NULL; // 다 지우고 나면 다시 빈 포인터로 초기화 (댕글린방지)
    }
}

// 5. 방패 폐기 (RELOAD 스위칭 후 쓸모없어진 옛날 방패를 메모리에서 날려버림)
void free_hash_table(HashTable *ht) {
    pthread_mutex_destroy(&ht->shield_lock);
    if (!ht) return;

    clear_hash_table(ht);
    pthread_mutex_destroy(&ht->shield_lock);
    free(ht); // 방패 본체 해제
}

// txt 파일을 한 줄씩 읽어서 방패에 무자비하게 꽂아 넣는 함수
void load_domains_from_txt(HashTable *ht, const char *filepath,int block_type, double score) {
    if (!ht || !filepath) return;

    FILE *file = fopen(filepath, "r");
    if (!file) {
        printf("[경고] %s 파일을 찾을 수 없습니다. (빈 방패로 시작합니다)\n", filepath);
        return;
    }

    char line[256];
    int count = 0;
    
    // 파일 끝까지 한 줄씩 읽기
    while (fgets(line, sizeof(line), file)) {
        // 뒤에 붙은 엔터바(\n, \r) 깔끔하게 제거
        line[strcspn(line, "\r\n")] = 0; 
        
        // 빈 줄이면 패스
        if (strlen(line) == 0) continue; 
        
        // 해시 테이블에 0초 컷 인서트
        insert_hash_table(ht, line,block_type,score);
        count++;
    }
    
    fclose(file);
    printf("[SYSTEM] %s 파일에서 %d개의 도메인을 방패에 장전 완료!\n", filepath, count);
}