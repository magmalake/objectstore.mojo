/*
 * objectstore.mojo — minimal libcurl wrapper for Mojo FFI.
 *
 * Why libcurl at all: as of 2026-08 no Mojo HTTP client resolves from conda
 * on either of this repo's toolchains (floki / flare / lightbug-http /
 * fire-http all report "No candidates were found"), and an Iceberg storage
 * layer is useless without HTTPS. conda-forge's `libcurl` brings TLS and a CA
 * bundle on every platform we target, and pixi-build-cmake is already proven
 * (zstd.mojo, lz4.mojo) to find a C compiler on the ubuntu and macos runners.
 *
 * Why a shim rather than calling libcurl directly: curl_easy_setopt is a C
 * variadic, and while Mojo 1.0's `external_call` can express variadics via
 * `num_fixed_args`, an `OwnedDLHandle`-dlopened symbol cannot. Everything here
 * is therefore a fixed-arity, ABI-hygienic function. Buffers that cross the
 * boundary are malloc'd here and freed here (os_http_result_free).
 *
 * Build: shim/pixi.toml (pixi-build-cmake) -> $CONDA_PREFIX/lib/libobjectstoremojo.so
 */

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------------ */
/* Growable byte buffer                                                      */
/* ------------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    int oom;
} os_buf;

static void buf_init(os_buf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->oom = 0;
}

static int buf_append(os_buf *b, const void *src, size_t n) {
    if (b->oom) return 0;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1) cap *= 2;
        unsigned char *p = (unsigned char *)realloc(b->data, cap);
        if (!p) { b->oom = 1; return 0; }
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    b->data[b->len] = 0; /* keep NUL-terminated so header text is a C string */
    return 1;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    os_buf *b = (os_buf *)userdata;
    size_t n = size * nmemb;
    if (!buf_append(b, ptr, n)) return 0;
    return n;
}

/* ------------------------------------------------------------------------ */
/* Result object — opaque to Mojo, read through accessors                    */
/* ------------------------------------------------------------------------ */

typedef struct {
    int rc;               /* 0 = transport OK, else the CURLcode */
    long status;          /* HTTP status, 0 if the request never completed */
    os_buf body;
    os_buf headers;       /* raw response header block(s), CRLF separated */
    char err[CURL_ERROR_SIZE + 64];
} os_http_result;

long os_http_result_rc(const os_http_result *r) { return r ? (long)r->rc : -1; }
long os_http_result_status(const os_http_result *r) { return r ? r->status : 0; }
const unsigned char *os_http_result_body(const os_http_result *r) {
    return (r && r->body.data) ? r->body.data : (const unsigned char *)"";
}
size_t os_http_result_body_len(const os_http_result *r) { return r ? r->body.len : 0; }
const char *os_http_result_headers(const os_http_result *r) {
    return (r && r->headers.data) ? (const char *)r->headers.data : "";
}
size_t os_http_result_headers_len(const os_http_result *r) { return r ? r->headers.len : 0; }
const char *os_http_result_error(const os_http_result *r) { return r ? r->err : "null result"; }

void os_http_result_free(os_http_result *r) {
    if (!r) return;
    free(r->body.data);
    free(r->headers.data);
    free(r);
}

/* ------------------------------------------------------------------------ */
/* Request                                                                   */
/* ------------------------------------------------------------------------ */

static int g_inited = 0;

/*
 * Headers arrive as one '\n'-separated blob of "Name: Value" lines. HTTP
 * header values cannot contain a bare LF, so this is lossless, and it spares
 * the Mojo side from building a char*[] across the FFI boundary.
 */
static struct curl_slist *build_headers(const char *blob) {
    struct curl_slist *list = NULL;
    if (!blob || !*blob) return NULL;
    const char *p = blob;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n > 0) {
            char *line = (char *)malloc(n + 1);
            if (!line) break;
            memcpy(line, p, n);
            line[n] = 0;
            struct curl_slist *next = curl_slist_append(list, line);
            free(line);
            if (!next) break;
            list = next;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return list;
}

/*
 * One HTTP request. `method` is GET/PUT/POST/DELETE/HEAD (anything else is
 * sent verbatim as a custom method). `range_start`/`range_end` < 0 mean "no
 * Range header"; a negative `range_end` with a non-negative start emits an
 * open-ended "start-". Redirects are OFF unless `follow_redirects` is set —
 * a presigned URL must never be silently re-issued somewhere else. TLS
 * verification is ON unless explicitly disabled (test servers with
 * self-signed certs). Proxies come from the environment via CURLOPT_NETRC-
 * free default behaviour (`http_proxy`/`https_proxy`/`no_proxy`).
 *
 * Returns a malloc'd result the caller must pass to os_http_result_free.
 */
os_http_result *os_http_request(const char *method,
                                const char *url,
                                const char *headers_blob,
                                const void *body,
                                size_t body_len,
                                long long range_start,
                                long long range_end,
                                long timeout_ms,
                                int follow_redirects,
                                int verify_tls) {
    os_http_result *r = (os_http_result *)calloc(1, sizeof(os_http_result));
    if (!r) return NULL;
    buf_init(&r->body);
    buf_init(&r->headers);
    r->rc = (int)CURLE_OK;
    r->err[0] = 0;

    if (!g_inited) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        g_inited = 1;
    }

    CURL *h = curl_easy_init();
    if (!h) {
        r->rc = (int)CURLE_FAILED_INIT;
        snprintf(r->err, sizeof(r->err), "curl_easy_init failed");
        return r;
    }

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, (void *)&r->body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, (void *)&r->headers);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, ""); /* let curl negotiate */
    curl_easy_setopt(h, CURLOPT_USERAGENT, "objectstore.mojo/0.1");
    if (timeout_ms > 0) {
        curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS,
                         timeout_ms < 10000 ? timeout_ms : 10000L);
    }
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, follow_redirects ? 1L : 0L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, verify_tls ? 1L : 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, verify_tls ? 2L : 0L);

    int is_head = (method && strcmp(method, "HEAD") == 0);
    if (is_head) {
        curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
    } else if (method && strcmp(method, "GET") != 0) {
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, method);
    }

    /*
     * A body is uploaded with POSTFIELDS regardless of method: it makes curl
     * set Content-Length and send the bytes, while CUSTOMREQUEST keeps the
     * verb (PUT/POST/…) intact. CURLOPT_UPLOAD would need a read callback and
     * would add an unwanted `Expect: 100-continue`.
     */
    if (body && body_len > 0 && !is_head) {
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    } else if (method && (strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0)) {
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)0);
    }

    char range[64];
    if (range_start >= 0) {
        if (range_end >= 0)
            snprintf(range, sizeof(range), "%lld-%lld", range_start, range_end);
        else
            snprintf(range, sizeof(range), "%lld-", range_start);
        curl_easy_setopt(h, CURLOPT_RANGE, range);
    }

    struct curl_slist *hdrs = build_headers(headers_blob);
    /*
     * curl adds `Expect: 100-continue` for large POST bodies, which S3 and
     * MinIO answer but which costs a round trip; disable it unless the caller
     * asked for it explicitly (an empty-valued header removes curl's own).
     */
    hdrs = curl_slist_append(hdrs, "Expect:");
    if (hdrs) curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(h);
    r->rc = (int)rc;
    if (rc != CURLE_OK) {
        snprintf(r->err, sizeof(r->err), "%s%s%s",
                 curl_easy_strerror(rc),
                 errbuf[0] ? ": " : "",
                 errbuf[0] ? errbuf : "");
    } else {
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &r->status);
        if (r->body.oom || r->headers.oom) {
            r->rc = (int)CURLE_OUT_OF_MEMORY;
            snprintf(r->err, sizeof(r->err), "out of memory buffering response");
        }
    }

    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    return r;
}

/* Diagnostics: "libcurl/8.x.y OpenSSL/3.x ..." */
const char *os_http_curl_version(void) { return curl_version(); }

/* Percent-decoding is not needed on the Mojo side, but URL escaping by curl's
 * own rules is handy for building query strings in tests. */
long os_http_shim_abi(void) { return 1; }
