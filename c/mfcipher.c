/*
 * MFCIPHER - Ternary Huffman Cipher
 * Alfabet output: 'm' (0), 'f' (1), ' ' (2)
 *
 * Tie-breaking berdasarkan insertion_order untuk kompatibilitas lintas bahasa.
 * Penggunaan: ./mfcipher [enc/dec] [input] [output]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const double FREQ[128] = {
    1,1,1,1,1,1,1,1,1,2,5,1,1,2,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    15,2,3,1,1,1,2,2,2,2,1,1,3,2,3,1,
    4,3,3,3,3,3,3,3,3,3,2,2,1,1,1,1,
    1,6,3,4,4,7,3,3,4,6,2,2,4,4,6,6,
    4,1,5,6,5,4,3,3,2,3,1,1,1,1,1,1,
    1,9,2,5,6,12,3,3,5,9,1,1,6,4,8,8,
    4,1,7,8,7,5,3,3,2,3,1,1,1,1,1,1,
};

typedef struct Node {
    int    symbol;
    double freq;
    long   order;
    struct Node *child[3];
} Node;

typedef struct { int8_t d[128]; int len; } Code;
static Code CODES[128];

#define HMAX 600
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
        int p = (i-1)/2;
        if (lt(H[i], H[p])) { Node *t=H[p]; H[p]=H[i]; H[i]=t; i=p; }
        else break;
    }
}

static Node *hpop(void) {
    Node *top = H[0];
    H[0] = H[--Hn];
    int i = 0;
    for (;;) {
        int s=i, l=2*i+1, r=2*i+2;
        if (l<Hn && lt(H[l],H[s])) s=l;
        if (r<Hn && lt(H[r],H[s])) s=r;
        if (s==i) break;
        Node *t=H[i]; H[i]=H[s]; H[s]=t; i=s;
    }
    return top;
}

static Node *mknode(int sym, double freq) {
    Node *n = calloc(1, sizeof(Node));
    n->symbol = sym; n->freq = freq; n->order = g_order++;
    return n;
}

static void freetree(Node *n) {
    if (!n) return;
    for (int d=0;d<3;d++) freetree(n->child[d]);
    free(n);
}

static Node *build_tree(void) {
    Hn = 0; g_order = 0;
    for (int i=0;i<128;i++) hpush(mknode(i, FREQ[i]));
    while ((Hn-1)%2 != 0) hpush(mknode(-2, 0.0));
    while (Hn > 1) {
        Node *p = mknode(-1, 0.0);
        for (int d=0;d<3;d++) { p->child[d]=hpop(); p->freq+=p->child[d]->freq; }
        hpush(p);
    }
    return hpop();
}

static void extract(Node *n, int8_t *path, int depth) {
    if (!n) return;
    if (n->symbol >= 0 && n->symbol < 128) {
        memcpy(CODES[n->symbol].d, path, depth);
        CODES[n->symbol].len = depth;
        return;
    }
    for (int d=0;d<3;d++) { path[depth]=(int8_t)d; extract(n->child[d],path,depth+1); }
}

static void encode(const uint8_t *src, size_t len, FILE *out) {
    for (size_t i=0;i<len;i++) {
        int sym = src[i]<128 ? src[i] : '?';
        const Code *c = &CODES[sym];
        for (int j=0;j<c->len;j++) fputc(c->d[j]==0?'m':(c->d[j]==1?'f':' '), out);
    }
}

static void decode_stream(const uint8_t *src, size_t len, FILE *out, Node *root) {
    Node *cur = root;
    for (size_t i=0;i<len;i++) {
        int d;
        if (src[i]=='m') d=0; else if (src[i]=='f') d=1; else if (src[i]==' ') d=2; else continue;
        cur = cur->child[d];
        if (!cur) { fprintf(stderr,"[-] Data korup pada posisi %zu.\n",i); return; }
        if (cur->symbol>=0 && cur->symbol<128) { fputc(cur->symbol,out); cur=root; }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr,"MFCIPHER - Ternary Huffman Cipher\nPenggunaan: %s [enc/dec] [input] [output]\n",argv[0]);
        return 1;
    }
    const char *mode=argv[1], *fin_p=argv[2], *fout_p=argv[3];
    if (strcmp(mode,"enc")!=0 && strcmp(mode,"dec")!=0) {
        fprintf(stderr,"[-] Mode tidak valid.\n"); return 1;
    }

    FILE *fin = fopen(fin_p,"rb");
    if (!fin) { perror("[-] Gagal membuka input"); return 1; }
    fseek(fin,0,SEEK_END); long sz=ftell(fin); rewind(fin);
    uint8_t *data = malloc(sz);
    if ((long)fread(data,1,sz,fin) != sz) { fprintf(stderr,"[-] Baca gagal.\n"); return 1; }
    fclose(fin);

    Node *root = build_tree();
    int8_t path[128]={0};
    extract(root,path,0);

    FILE *fout = fopen(fout_p,"wb");
    if (!fout) { free(data); freetree(root); perror("[-] Gagal membuka output"); return 1; }

    if (strcmp(mode,"enc")==0) {
        encode(data,(size_t)sz,fout);
        fprintf(stderr,"[+] Enkripsi selesai -> %s\n",fout_p);
    } else {
        decode_stream(data,(size_t)sz,fout,root);
        fprintf(stderr,"[+] Dekripsi selesai -> %s\n",fout_p);
    }

    fclose(fout); freetree(root); free(data);
    return 0;
}
