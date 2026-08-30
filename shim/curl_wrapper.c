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
 * Connection reuse: a request used to create and destroy a curl easy handle,
 * so every request paid a fresh TCP (and TLS) handshake — ~2.9 ms on loopback,
 * far more against a real endpoint. Handles now persist in an `os_http_client`
 * and are reset (not destroyed) between requests, because curl_easy_reset
 * explicitly keeps the live connections, the DNS cache and the TLS session
 * cache while clearing the options.
 *
 * Thread safety: an os_http_client is NOT thread safe, and neither is the
 * process-wide default client. Mojo has no threads today, and the share handle
 * below deliberately carries no lock callbacks for the same reason; if Mojo
 * ever grows threads, each thread needs its own client and the share handle
 * needs CURLSHOPT_LOCKFUNC.
 *
 * Build: shim/pixi.toml (pixi-build-cmake) -> $CONDA_PREFIX/lib/libobjectstoremojo.so
 */

#ifndef _WIN32
/*
 * dladdr, Dl_info and RTLD_NODELETE are GNU extensions on glibc: <dlfcn.h>
 * hides them behind __USE_GNU unless this is defined before any header is
 * included. macOS declares them unconditionally, so only Linux notices.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#endif

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#ifndef _WIN32
#include <dlfcn.h>
/* Absent on a platform without it: dlopen alone still pins us, because the
   reference taken below is never released. */
#ifndef RTLD_NODELETE
#define RTLD_NODELETE 0
#endif
#endif

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

/* ------------------------------------------------------------------------ */
/* Clients: a persistent easy handle, so TCP+TLS is set up once per host     */
/* ------------------------------------------------------------------------ */

typedef struct {
    CURL *easy;
    long requests;   /* requests performed on this client */
    long connects;   /* connections curl actually had to open */
} os_http_client;

static CURLSH *g_share = NULL;
static os_http_client *g_default = NULL;

/*
 * Mojo opens this library through an OwnedDLHandle and closes it when that
 * value dies — which, if the loader honoured the dlclose(), would unmap the
 * pooled connections along with everything else and make reuse a no-op. Take a
 * permanent reference to ourselves the first time we are called; it is never
 * released, which is the point.
 */
static void pin_self(void) {
#ifndef _WIN32
    Dl_info info;
    if (dladdr((void *)(size_t)&pin_self, &info) && info.dli_fname) {
        void *self = dlopen(info.dli_fname, RTLD_LAZY | RTLD_NODELETE);
        (void)self;
    }
#endif
}

static void ensure_global(void) {
    if (g_inited) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    pin_self();
    /*
     * DNS and TLS sessions are shared across clients: a resolver round trip
     * and a TLS resumption are worth more than the (single-threaded) locking
     * they would otherwise need. Connections are deliberately NOT shared —
     * CURL_LOCK_DATA_CONNECT hands connections between handles, which is only
     * safe with locking callbacks this build does not install.
     */
    g_share = curl_share_init();
    if (g_share) {
        curl_share_setopt(g_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(g_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    }
    g_inited = 1;
}

os_http_client *os_http_client_new(void) {
    ensure_global();
    os_http_client *c = (os_http_client *)calloc(1, sizeof(os_http_client));
    if (!c) return NULL;
    c->easy = curl_easy_init();
    if (!c->easy) {
        free(c);
        return NULL;
    }
    if (g_share) curl_easy_setopt(c->easy, CURLOPT_SHARE, g_share);
    return c;
}

void os_http_client_free(os_http_client *c) {
    if (!c) return;
    if (c == g_default) return; /* the process-wide client outlives callers */
    if (c->easy) curl_easy_cleanup(c->easy);
    free(c);
}

/* NULL means the process-wide default client. */
static os_http_client *client_or_default(os_http_client *c) {
    if (c) return c;
    ensure_global();
    if (!g_default) g_default = os_http_client_new();
    return g_default;
}

long os_http_client_requests(os_http_client *c) {
    os_http_client *cl = client_or_default(c);
    return cl ? cl->requests : 0;
}

/*
 * How many TCP connections curl had to open for this client. The whole point
 * of the pool is that this stays at 1 while `requests` climbs: the tests
 * assert exactly that.
 */
long os_http_client_connects(os_http_client *c) {
    os_http_client *cl = client_or_default(c);
    return cl ? cl->connects : 0;
}

void os_http_client_reset_stats(os_http_client *c) {
    os_http_client *cl = client_or_default(c);
    if (cl) {
        cl->requests = 0;
        cl->connects = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* Request                                                                   */
/* ------------------------------------------------------------------------ */

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
 * One HTTP request on `client` (NULL = the process-wide client). `method` is
 * GET/PUT/POST/DELETE/HEAD (anything else is sent verbatim as a custom
 * method). `range_start`/`range_end` < 0 mean "no Range header"; a negative
 * `range_end` with a non-negative start emits an open-ended "start-".
 * Redirects are OFF unless `follow_redirects` is set — a presigned URL must
 * never be silently re-issued somewhere else. TLS verification is ON unless
 * explicitly disabled (test servers with self-signed certs). Proxies come from
 * the environment (`http_proxy`/`https_proxy`/`no_proxy`).
 *
 * Returns a malloc'd result the caller must pass to os_http_result_free.
 */
os_http_result *os_http_request_ex(os_http_client *client,
                                   const char *method,
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

    os_http_client *cl = client_or_default(client);
    if (!cl || !cl->easy) {
        r->rc = (int)CURLE_FAILED_INIT;
        snprintf(r->err, sizeof(r->err), "curl_easy_init failed");
        return r;
    }
    CURL *h = cl->easy;

    /*
     * Reset rather than recreate: curl_easy_reset clears every option set
     * below (so nothing leaks from the previous request) but explicitly keeps
     * the live connections, the DNS cache, the TLS session cache and the
     * share handle — which is the entire reason this handle is persistent.
     */
    curl_easy_reset(h);

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, (void *)&r->body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, (void *)&r->headers);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    if (g_share) curl_easy_setopt(h, CURLOPT_SHARE, g_share);
    /*
     * Keep the socket alive between requests and keep enough of them cached
     * that alternating hosts — an Iceberg REST catalog and an S3 endpoint, say
     * — do not evict each other. FORBID_REUSE and FRESH_CONNECT stay off
     * (their defaults), which is what makes the pool a pool.
     */
    curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(h, CURLOPT_TCP_KEEPIDLE, 30L);
    curl_easy_setopt(h, CURLOPT_TCP_KEEPINTVL, 15L);
    curl_easy_setopt(h, CURLOPT_MAXCONNECTS, 16L);
    /*
     * Deliberately no CURLOPT_ACCEPT_ENCODING: transparent gzip would make
     * Content-Length describe the compressed body, so a HEAD would report the
     * wrong object size and a Range would address the wrong bytes. Object
     * stores serve bytes, not documents.
     */
    curl_easy_setopt(h, CURLOPT_USERAGENT, "objectstore.mojo/0.2");
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
    cl->requests += 1;
    {
        long opened = 0;
        if (curl_easy_getinfo(h, CURLINFO_NUM_CONNECTS, &opened) == CURLE_OK)
            cl->connects += opened;
    }
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

    /*
     * The handle outlives this frame now, so nothing of this frame may stay
     * reachable from it: errbuf is on the stack and POSTFIELDS/WRITEDATA point
     * at buffers the caller is about to free. curl_easy_reset at the top of
     * the next request would do this too, but a persistent handle holding
     * dangling pointers in the meantime is not worth the saved lines.
     */
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, (void *)NULL);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, (void *)NULL);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, (void *)NULL);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, (void *)NULL);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, (void *)NULL);
    if (hdrs) curl_slist_free_all(hdrs);
    return r;
}

/*
 * The pre-0.2 entry point, kept byte-compatible on purpose: a consumer whose
 * lock file pins an older `objectstore-shim` build still links against this
 * symbol while compiling against newer Mojo sources. It is the same request on
 * the process-wide client.
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
    return os_http_request_ex(NULL, method, url, headers_blob, body, body_len,
                              range_start, range_end, timeout_ms,
                              follow_redirects, verify_tls);
}

/* Diagnostics: "libcurl/8.x.y OpenSSL/3.x ..." */
const char *os_http_curl_version(void) { return curl_version(); }

/*
 * Seconds since the Unix epoch. SigV4 stamps every request with a UTC
 * timestamp and AWS rejects anything more than 15 minutes out of skew, but
 * Mojo's std.time only exposes a monotonic clock — there is no wall clock in
 * the standard library at all. Rather than add a second FFI shim for one
 * libc call, it rides along here: HTTP is the only reason this tin ever needs
 * to know the time.
 */
long long os_time_epoch(void) { return (long long)time(NULL); }

/* 1 = 0.1.x (one easy handle per request); 2 = pooled clients. */
long os_http_shim_abi(void) { return 2; }
