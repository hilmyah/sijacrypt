/*
 * MFCIPHER - Ternary Huffman Cipher dengan Secret Key
 * Alfabet output: 'm' (0), 'f' (1), ' ' (2)
 *
 * Alur enkripsi:
 *   1. Build FREQ dari key (FNV-1a + Fisher-Yates) untuk 256 simbol byte
 *   2. Bangun pohon Huffman terner dari FREQ
 *   3. Prepend header (magic + ekstensi asli) ke plaintext
 *   4. Encode byte stream -> digit terner (via Huffman)
 *   5. XOR terner: (digit + keystream) mod 3   <- stream cipher
 *
 * Penggunaan: ./mfcipher [enc/dec] [input] [output] [key]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Frekuensi dasar untuk 256 simbol byte */
static const double FREQ_BASE[256] = {
    /* 0x00-0x0F */
    1,1,1,1,1,1,1,1,1,2,5,1,1,2,1,1,
    /* 0x10-0x1F */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    /* 0x20-0x2F */
    15,2,3,1,1,1,2,2,2,2,1,1,3,2,3,1,
    /* 0x30-0x3F */
    4,3,3,3,3,3,3,3,3,3,2,2,1,1,1,1,
    /* 0x40-0x4F */
    1,6,3,4,4,7,3,3,4,6,2,2,4,4,6,6,
    /* 0x50-0x5F */
    4,1,5,6,5,4,3,3,2,3,1,1,1,1,1,1,
    /* 0x60-0x6F */
    1,9,2,5,6,12,3,3,5,9,1,1,6,4,8,8,
    /* 0x70-0x7F */
    4,1,7,8,7,5,3,3,2,3,1,1,1,1,1,1,
    /* 0x80-0xFF: byte biner, distribusi flat */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
};

/* Header magic untuk identifikasi format dan pemulihan ekstensi */
static const uint8_t HEADER_MAGIC[4] = { 'M','F','C','I' };
#define HEADER_VERSION 1


/* ========== PRNG ========== */

static uint64_t fnv1a_hash(const char *key) {
    uint64_t h = 14695981039346656037ULL;
    while (*key) { h ^= (uint8_t)(*key++); h *= 1099511628211ULL; }
    return h;
}

static uint64_t prng_next(uint64_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static void build_freq(double freq[256], const char *key) {
    memcpy(freq, FREQ_BASE, sizeof(FREQ_BASE));
    uint64_t state = fnv1a_hash(key);
    if (!state) state = 1;
    for (int i = 255; i > 0; i--) {
        int j = (int)(prng_next(&state) % (uint64_t)(i + 1));
        double t = freq[i]; freq[i] = freq[j]; freq[j] = t;
    }
}

static uint64_t ks_init(const char *key) {
    uint64_t s = fnv1a_hash(key) ^ 0xdeadbeefcafeULL;
    return s ? s : 0xdeadbeefcafeULL;
}


/* ========== Pohon Huffman ========== */

typedef struct Node {
    int    symbol;
    double freq;
    long   order;
    struct Node *child[3];
} Node;

typedef struct { int8_t d[256]; int len; } Code;
static Code CODES[256];

#define HMAX 900
static Node *H[HMAX];
static int   Hn = 0;
static long  g_order = 0;

static int lt(const Node *a, const Node *b) {
    if (a->freq != b->freq) return a->freq < b->freq;
    return a->order < b->order;
}

static void hpush(Node *n) {
    int i = Hn++;
    H[i] = n;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (lt(H[i], H[p])) { Node *t = H[p]; H[p] = H[i]; H[i] = t; i = p; }
        else break;
    }
}

static Node *hpop(void) {
    Node *top = H[0]; H[0] = H[--Hn];
    int i = 0;
    for (;;) {
        int s = i, l = 2*i+1, r = 2*i+2;
        if (l < Hn && lt(H[l], H[s])) s = l;
        if (r < Hn && lt(H[r], H[s])) s = r;
        if (s == i) break;
        Node *t = H[i]; H[i] = H[s]; H[s] = t; i = s;
    }
    return top;
}

static Node *mknode(int sym, double fv) {
    Node *n = calloc(1, sizeof(Node));
    n->symbol = sym; n->freq = fv; n->order = g_order++;
    return n;
}

static void freetree(Node *n) {
    if (!n) return;
    for (int d = 0; d < 3; d++) freetree(n->child[d]);
    free(n);
}

static Node *build_tree(const double freq[256]) {
    Hn = 0; g_order = 0;
    for (int i = 0; i < 256; i++) hpush(mknode(i, freq[i]));
    while ((Hn - 1) % 2 != 0) hpush(mknode(-2, 0.0));
    while (Hn > 1) {
        Node *p = mknode(-1, 0.0);
        for (int d = 0; d < 3; d++) {
            p->child[d] = hpop();
            p->freq    += p->child[d]->freq;
        }
        hpush(p);
    }
    return hpop();
}

static void extract(Node *n, int8_t *path, int depth) {
    if (!n) return;
    if (n->symbol >= 0 && n->symbol < 256) {
        memcpy(CODES[n->symbol].d, path, depth);
        CODES[n->symbol].len = depth;
        return;
    }
    for (int d = 0; d < 3; d++) {
        path[depth] = (int8_t)d;
        extract(n->child[d], path, depth + 1);
    }
}


/* ========== Header ========== */

/* Tulis header ke buf, kembalikan panjang header dalam bytes.
 * Format: MAGIC(4) | VERSION(1) | EXT_LEN(1) | EXT(n)
 */
static int write_header(uint8_t *buf, const char *ext) {
    /* Lewati titik awal ekstensi jika ada */
    if (ext && ext[0] == '.') ext++;
    int ext_len = ext ? (int)strlen(ext) : 0;
    if (ext_len > 31) ext_len = 31;

    memcpy(buf, HEADER_MAGIC, 4);
    buf[4] = HEADER_VERSION;
    buf[5] = (uint8_t)ext_len;
    if (ext_len > 0) memcpy(buf + 6, ext, ext_len);
    return 6 + ext_len;
}

/* Parse header dari decoded data.
 * Jika valid, isi ext_out (null-terminated, max 32 bytes) dan kembalikan offset payload.
 * Jika tidak valid, kembalikan 0 dan ext_out[0] = '\0'.
 */
static size_t parse_header(const uint8_t *data, size_t len, char *ext_out) {
    ext_out[0] = '\0';
    if (len < 6) return 0;
    if (memcmp(data, HEADER_MAGIC, 4) != 0) return 0;
    if (data[4] != HEADER_VERSION) return 0;
    uint8_t ext_len = data[5];
    if (len < (size_t)(6 + ext_len)) return 0;
    memcpy(ext_out, data + 6, ext_len);
    ext_out[ext_len] = '\0';
    return 6 + ext_len;
}


/* ========== Encoder & Decoder ========== */

static void encode(const uint8_t *src, size_t len, FILE *out, const char *key) {
    uint64_t ks = ks_init(key);
    for (size_t i = 0; i < len; i++) {
        int sym = (unsigned char)src[i];
        const Code *c = &CODES[sym];
        for (int j = 0; j < c->len; j++) {
            int ks_digit = (int)(prng_next(&ks) % 3);
            int digit    = ((int)c->d[j] + ks_digit) % 3;
            fputc(digit == 0 ? 'm' : digit == 1 ? 'f' : ' ', out);
        }
    }
}

static uint8_t *decode_to_mem(const uint8_t *src, size_t len, Node *root,
                               const char *key, size_t *out_len) {
    uint64_t ks  = ks_init(key);
    size_t   cap = len / 4 + 64;
    uint8_t *out = malloc(cap);
    size_t   sz  = 0;
    Node    *cur = root;

    for (size_t i = 0; i < len; i++) {
        int raw;
        if      (src[i] == 'm') raw = 0;
        else if (src[i] == 'f') raw = 1;
        else if (src[i] == ' ') raw = 2;
        else continue;

        int ks_digit = (int)(prng_next(&ks) % 3);
        int d        = (raw - ks_digit + 3) % 3;
        cur = cur->child[d];
        if (!cur) {
            fprintf(stderr, "[-] Data korup pada posisi %zu.\n", i);
            *out_len = sz;
            return out;
        }
        if (cur->symbol >= 0 && cur->symbol < 256) {
            if (sz == cap) {
                cap *= 2;
                out  = realloc(out, cap);
            }
            out[sz++] = (uint8_t)cur->symbol;
            cur = root;
        }
    }
    *out_len = sz;
    return out;
}


/* ========== Entry Point ========== */

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr,
            "MFCIPHER - Ternary Huffman Cipher\n"
            "Penggunaan: %s [enc/dec] [input] [output] [key]\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1], *fin_p = argv[2], *fout_p = argv[3], *key = argv[4];
    if (strcmp(mode, "enc") != 0 && strcmp(mode, "dec") != 0) {
        fprintf(stderr, "[-] Mode tidak valid. Gunakan 'enc' atau 'dec'.\n");
        return 1;
    }

    FILE *fin = fopen(fin_p, "rb");
    if (!fin) { perror("[-] Gagal membuka input"); return 1; }
    fseek(fin, 0, SEEK_END);
    long sz = ftell(fin);
    rewind(fin);
    uint8_t *data = malloc(sz);
    if ((long)fread(data, 1, sz, fin) != sz) {
        fprintf(stderr, "[-] Baca gagal.\n");
        return 1;
    }
    fclose(fin);

    double freq[256];
    build_freq(freq, key);
    Node *root = build_tree(freq);
    int8_t path[512] = {0};
    extract(root, path, 0);

    if (strcmp(mode, "enc") == 0) {
        /* Ambil ekstensi dari nama file input */
        const char *dot = strrchr(fin_p, '.');
        const char *ext = (dot && dot != fin_p) ? dot : "";

        /* Buat payload: header + data asli */
        uint8_t hdr[38];
        int hdr_len  = write_header(hdr, ext);
        size_t total = (size_t)hdr_len + (size_t)sz;
        uint8_t *payload = malloc(total);
        memcpy(payload, hdr, hdr_len);
        memcpy(payload + hdr_len, data, sz);

        FILE *fout = fopen(fout_p, "wb");
        if (!fout) { free(data); free(payload); freetree(root); perror("[-] Gagal membuka output"); return 1; }
        encode(payload, total, fout, key);
        fclose(fout);
        free(payload);
        fprintf(stderr, "[+] Enkripsi selesai -> %s\n", fout_p);

    } else {
        size_t  raw_len = 0;
        uint8_t *raw    = decode_to_mem(data, (size_t)sz, root, key, &raw_len);

        char    ext_out[33]   = {0};
        size_t  payload_off   = parse_header(raw, raw_len, ext_out);
        uint8_t *payload      = raw + payload_off;
        size_t   payload_len  = raw_len - payload_off;

        /* Tentukan nama file output; jika ekstensi ditemukan dan output tidak punya ekstensi, terapkan */
        char out_path[4096];
        strncpy(out_path, fout_p, sizeof(out_path) - 1);
        out_path[sizeof(out_path) - 1] = '\0';

        if (ext_out[0] != '\0') {
            const char *out_dot = strrchr(out_path, '.');
            if (!out_dot) {
                /* Tidak ada ekstensi pada nama output: tempel ekstensi asli */
                size_t base_len = strlen(out_path);
                if (base_len + strlen(ext_out) + 2 < sizeof(out_path)) {
                    out_path[base_len] = '.';
                    strcpy(out_path + base_len + 1, ext_out);
                }
            }
            fprintf(stderr, "[+] Ekstensi asli dipulihkan: .%s\n", ext_out);
        }

        FILE *fout = fopen(out_path, "wb");
        if (!fout) { free(data); free(raw); freetree(root); perror("[-] Gagal membuka output"); return 1; }
        fwrite(payload, 1, payload_len, fout);
        fclose(fout);
        free(raw);
        fprintf(stderr, "[+] Dekripsi selesai -> %s\n", out_path);
    }

    freetree(root);
    free(data);
    return 0;
}