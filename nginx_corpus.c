#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int current_seed_id = 1;

static void die_perror(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void ensure_corpus_environment(void) {
    if (mkdir("nginx_corpus", 0777) != 0 && errno != EEXIST) {
        die_perror("mkdir");
    }
}

static void emit_seed(const char *payload, size_t size) {
    char filepath[256];
    FILE *f = NULL;

    if (snprintf(filepath, sizeof(filepath), "nginx_corpus/seed_%05d.raw", current_seed_id++) >= (int)sizeof(filepath)) {
        exit(EXIT_FAILURE);
    }

    f = fopen(filepath, "wb");
    if (!f) {
        die_perror("fopen");
    }

    if (fwrite(payload, 1, size, f) != size) {
        die_perror("fwrite");
    }

    if (fclose(f) != 0) {
        die_perror("fclose");
    }
}

static void generate_uri_mutations(void) {
    char buffer[16384];
    
    memset(buffer, 'A', 8192);
    memcpy(buffer, "GET /", 5);
    memcpy(buffer + 8100, " HTTP/1.1\r\n\r\n", 13);
    emit_seed(buffer, 8113);

    emit_seed("GET /%00%00%00%00 HTTP/1.1\r\n\r\n", 29);
    emit_seed("GET /%u0000%u000a HTTP/1.1\r\n\r\n", 29);
    emit_seed("GET /..%c0%af..%c0%af..%c0%afetc/passwd HTTP/1.1\r\n\r\n", 51);
    emit_seed("GET /%252e%252e%252f HTTP/1.1\r\n\r\n", 33);
    emit_seed("GET /%2e%2e%2f%2e%2e%2f%2e%2e%2f HTTP/1.1\r\n\r\n", 45);
    
    memset(buffer, '?', 4096);
    memcpy(buffer, "GET /", 5);
    memcpy(buffer + 4000, " HTTP/1.1\r\n\r\n", 13);
    emit_seed(buffer, 4013);
    
    emit_seed("GET /\r\nHTTP/1.1\r\n\r\n", 18);
    emit_seed("GET /\x01\x02\x03\x7f\xff HTTP/1.1\r\n\r\n", 23);
    emit_seed("OPTIONS * HTTP/1.1\r\n\r\n", 22);
    emit_seed("PROPFIND / HTTP/1.1\r\nDepth: infinity\r\n\r\n", 39);
}

static void generate_header_mutations(void) {
    char buffer[16384];
    
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\0X-Injected: true\r\n\r\n", 73);
    
    memset(buffer, 'a', 8192);
    memcpy(buffer, "GET / HTTP/1.1\r\n", 16);
    buffer[4000] = ':';
    buffer[4001] = ' ';
    memcpy(buffer + 8000, "\r\n\r\n", 4);
    emit_seed(buffer, 8004);
    
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\r\n Header-Folded: true\r\n\tTabbed: true\r\n\r\n", 73);
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\r\nConnection\x85: keep-alive\r\n\r\n", 61);
    emit_seed("GET / HTTP/1.1\r\nHost : localhost\r\n\r\n", 36);
    emit_seed("GET / HTTP/1.1\r\nHost\t: localhost\r\n\r\n", 36);
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\r\nX-Custom-Header: \r\n\r\n", 54);
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\r\n\r\n\r\n", 40);
    emit_seed("GET / HTTP/1.1\r\nHost: localhost\nConnection: close\n\n", 50);
}

static void generate_te_cl_smuggling(void) {
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST ", 85);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\nPOST ", 85);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999999999999999999999\r\n\r\n", 71);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", 49);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \nchunked\r\n\r\n0\r\n\r\n", 63);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n", 63);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding\x0b: chunked\r\n\r\n0\r\n\r\n", 63);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n", 70);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n", 66);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nfffff\r\n", 63);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: val\r\n\r\n", 76);
    emit_seed("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: cow\r\n\r\n0\r\n\r\n", 56);
}

static void generate_h2_and_binary(void) {
    emit_seed("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00", 33);
    emit_seed("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x01\x0f\x00\x00\x00\x00\x00", 33);
    emit_seed("\x00\x00\x12\x01\x04\x00\x00\x00\x01\x88\x5f\x87\x49\x7c\xa5\x89\xe3\x4d\x1f\x43\xae\xba\x0c\x41\xa4\xc7\xa9\x8f\x33\xa6\x9a\x3f\xdf\x9a\x68\xfa\x1d\x75\xd0\x62\x0d\x26\x3d\x4c\x4d\x65\x64", 48);
    emit_seed("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x08\x06\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00", 41);
    emit_seed("\x00\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00", 13);
    emit_seed("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\xff\xff\xff\xff\x00\x00\x00\x00\x00", 33);
}

static void generate_pipeline_and_fragmentation(void) {
    emit_seed("GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: b\r\n\r\n", 55);
    emit_seed("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n1234567890GET / HTTP/1.1\r\n\r\n", 75);
    emit_seed("G", 1);
    emit_seed("GET / HTT", 9);
    emit_seed("GET / HTTP/1.1\r\n", 16);
    emit_seed("GET / HTTP/1.1\r\nHost: a\r", 24);
    emit_seed("GET / HTTP/1.1\r\nHost: a\n\n", 25);
}

int main(int argc, char **argv) {
    ensure_corpus_environment();
    generate_uri_mutations();
    generate_header_mutations();
    generate_te_cl_smuggling();
    generate_h2_and_binary();
    generate_pipeline_and_fragmentation();
    return 0;
}
