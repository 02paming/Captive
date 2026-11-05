#ifndef HASH_MANAGER_H
#define HASH_MANAGER_H

#include "pcap_common.h"

// 해시 테이블
unsigned long hash_djb2(const char *str);
HashTable* create_hash_table();
void insert_hash_table(HashTable *ht, const char *domain, int block_type, double score);
int delete_from_hash_table(HashTable *ht, const char *domain);
HashNode* lookup_hash_table(HashTable *ht, const char *domain);
void free_hash_table(HashTable *ht);
void clear_hash_table(HashTable* ht);
void load_domains_from_txt(HashTable *ht, const char *filepath, int block_type, double score);

#endif 