/* A message format negotiated mid-run (docs/trace-fixtures.md, spec 14.5).
   usage: layouts.exe [stream file]      (default layouts.bin in the current directory)
   Sends 3 messages in layout 1, a negotiation message, then 3 messages in layout 2, through fx_send; fx_receive
   decodes each with the layout in force and fx_negotiate switches it. All integers are little-endian.
     layout 1 (type 1, 12 bytes):  u16 type, u16 length, u32 id, u32 amount
     negotiation (type 0xF0, 6):   u16 type, u16 length, u16 version
     layout 2 (type 2, 21 bytes):  u16 type, u16 length, u64 id, u32 amount, u16 flags, u8 ext[3]
   A reader that knows layout 2 only up to `flags` (18 bytes) leaves ext (3 bytes) unconsumed. */
#include "trace_common.h"

static unsigned char g_stream[512];
static int g_stream_size;
static int g_layout = 1;
static FILE *g_out;

static void put16(unsigned char *p, unsigned v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32(unsigned char *p, unsigned long v) { put16(p, (unsigned)(v & 0xffff)); put16(p + 2, (unsigned)(v >> 16)); }
static void put64(unsigned char *p, unsigned __int64 v) { put32(p, (unsigned long)(v & 0xffffffffu)); put32(p + 4, (unsigned long)(v >> 32)); }
static unsigned get16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static unsigned long get32(const unsigned char *p) { return get16(p) | ((unsigned long)get16(p + 2) << 16); }
static unsigned __int64 get64(const unsigned char *p) { return get32(p) | ((unsigned __int64)get32(p + 4) << 32); }

FX int fx_encode_v1(unsigned char *out, unsigned id, unsigned amount) {
    put16(out, 1); put16(out + 2, 12); put32(out + 4, id); put32(out + 8, amount);
    return 12;
}

FX int fx_encode_negotiation(unsigned char *out, unsigned version) {
    put16(out, 0xF0); put16(out + 2, 6); put16(out + 4, version);
    return 6;
}

FX int fx_encode_v2(unsigned char *out, unsigned __int64 id, unsigned amount, unsigned flags) {
    put16(out, 2); put16(out + 2, 21); put64(out + 4, id); put32(out + 12, amount); put16(out + 16, flags);
    out[18] = 0xE0; out[19] = 0xE1; out[20] = 0xE2;
    return 21;
}

FX void fx_negotiate(unsigned version) { g_layout = (int)version; }

FX int fx_receive(const unsigned char *message, int length) {
    unsigned type = get16(message);
    if (type == 0xF0) {
        fx_negotiate(get16(message + 4));
        say("recv negotiated version=%u", get16(message + 4));
    } else if (type == 1 && g_layout == 1) {
        say("recv v1 id=%lu amount=%lu", get32(message + 4), get32(message + 8));
    } else if (type == 2 && g_layout == 2) {
        say("recv v2 id=%I64u amount=%lu flags=0x%04x ext=%02x%02x%02x", get64(message + 4), get32(message + 12),
            get16(message + 16), message[18], message[19], message[20]);
    } else {
        say("recv unsupported type=%u layout=%d", type, g_layout);
        return 0;
    }
    return length;
}

FX int fx_send(const unsigned char *message, int length) {
    memcpy(g_stream + g_stream_size, message, (size_t)length);
    g_stream_size += length;
    if (g_out) fwrite(message, 1, (size_t)length, g_out);
    return fx_receive(message, length);
}

int main(int argc, char **argv) {
    unsigned char buffer[32];
    fx_arm_watchdog(20);
    g_out = fopen(argc > 1 ? argv[1] : "layouts.bin", "wb");
    for (unsigned i = 0; i < 3; ++i) fx_send(buffer, fx_encode_v1(buffer, 100 + i, 1000 + i * 7));
    fx_send(buffer, fx_encode_negotiation(buffer, 2));
    for (unsigned i = 0; i < 3; ++i) fx_send(buffer, fx_encode_v2(buffer, 5000000000ull + i, 2000 + i * 13, 0x8001 + i));
    if (g_out) fclose(g_out);
    say("stream_bytes=%d", g_stream_size);
    return g_stream_size == 3 * 12 + 6 + 3 * 21 ? 0 : 1;
}
