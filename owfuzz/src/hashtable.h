#pragma once

#define CAPACITY 50000 // Size of the HashTable.

// Defines the HashTable item.
typedef struct Ht_item
{
    char *key;
    char *value;
} Ht_item;

// Defines the HashTable.
typedef struct HashTable
{
    // Contains an array of pointers to items.
    Ht_item **items;
    int size;
    int count;
} HashTable;

unsigned long hash_function(char *str);
Ht_item *create_item(char *key, char *value);
HashTable *create_table(int size);
void free_item(Ht_item* item);
void free_table(HashTable* table);
void print_table(HashTable* table);
char* ht_search(HashTable* table, char* key);
void ht_insert(HashTable *table, char *key, char *value);
