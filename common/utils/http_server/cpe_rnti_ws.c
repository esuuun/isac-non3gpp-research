/*
 * CPE RNTI WebSocket-style notification server  (port 8891)
 *
 * This is a minimal HTTP long-poll endpoint (NOT full WebSocket RFC 6455).
 * A real WebSocket implementation requires a handshake + framing library
 * which is out of scope for embedded OAI C code.  Long-poll is functionally
 * equivalent for the one-shot RNTI notification use case.
 *
 * CPE_UE flow:
 *   1. CPE_UE connects to the CU via WiFi (CPE LAN) and calls:
 *        GET http://<CU_IP>:8891/wait_rnti?imsi=<IMSI>  HTTP/1.1
 *   2. The server blocks until rrc_gNB_allocate_rnti_for_cpe_ue() has
 *      populated the RNTI in the CPE_UE mapping table.
 *   3. Responds with: {"imsi":"<IMSI>","rnti":"0x1A2B"}
 *   4. CPE_UE uses the RNTI to initiate a Contention-Free RACH.
 *
 * Thread model: one connection = one thread (detached).
 * Max simultaneous pending clients: CPE_UE_MAX_ENTRIES.
 *
 * Build: compiled as part of GTPV1U via CMakeLists.txt.
 */

#include "cpe_rnti_ws.h"
#include "openair2/RRC/NR/cpe_ue_context.h"
#include "common/utils/LOG/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define _POSIX_C_SOURCE 199309L
#include <time.h>

#define CPE_RNTI_WS_PORT   8891
#define CPE_RNTI_POLL_MS   100   /* poll interval while waiting for RNTI */
#define CPE_RNTI_TIMEOUT_S 30    /* max wait before returning 408 */

/* ── Connection handler ─────────────────────────────────────────────────── */

static void send_http(int fd, int status, const char *body)
{
  const char *sc = status == 200 ? "200 OK"
                 : status == 400 ? "400 Bad Request"
                 : status == 408 ? "408 Request Timeout"
                 : "404 Not Found";
  char hdr[256];
  int hlen = snprintf(hdr, sizeof(hdr),
    "HTTP/1.1 %s\r\nContent-Type: application/json\r\n"
    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
    sc, strlen(body));
  send(fd, hdr,  hlen,         0);
  send(fd, body, strlen(body), 0);
}

typedef struct {
  int     fd;
  uint64_t imsi;
} conn_arg_t;

static void *handle_wait_rnti(void *arg)
{
  conn_arg_t *ca = (conn_arg_t *)arg;
  int     fd   = ca->fd;
  uint64_t imsi = ca->imsi;
  free(ca);

  cpe_ue_table_t *tbl = cpe_ue_table_get();
  int elapsed_ms = 0;
  uint16_t rnti = 0;

  while (elapsed_ms < CPE_RNTI_TIMEOUT_S * 1000) {
    cpe_ue_lock(tbl);
    cpe_ue_entry_t *e = cpe_ue_find_by_imsi_locked(tbl, imsi);
    if (e && e->rnti != 0) {
      rnti = e->rnti;
    }
    cpe_ue_unlock(tbl);

    if (rnti) break;

    struct timespec ts = { .tv_nsec = CPE_RNTI_POLL_MS * 1000000L };
    nanosleep(&ts, NULL);
    elapsed_ms += CPE_RNTI_POLL_MS;
  }

  if (rnti == 0) {
    send_http(fd, 408,
      "{\"status\":\"timeout\",\"msg\":\"RNTI not allocated within timeout\"}");
  } else {
    char body[128];
    snprintf(body, sizeof(body),
             "{\"status\":\"ok\",\"imsi\":\"%llu\",\"rnti\":\"0x%04x\"}",
             (unsigned long long)imsi, rnti);
    send_http(fd, 200, body);
    LOG_I(NR_RRC,
          "[CPE RNTI WS] Sent RNTI 0x%04x to CPE_UE imsi=%llu\n",
          rnti, (unsigned long long)imsi);
  }

  close(fd);
  return NULL;
}

/* Extract query param from "GET /path?key=val HTTP/1.1" */
static bool get_query_param(const char *req, const char *key,
                             char *out, size_t out_len)
{
  char search[64];
  snprintf(search, sizeof(search), "%s=", key);
  const char *p = strstr(req, search);
  if (!p) return false;
  p += strlen(search);
  size_t i = 0;
  while (*p && *p != '&' && *p != ' ' && *p != '\r' && i < out_len - 1)
    out[i++] = *p++;
  out[i] = '\0';
  return i > 0;
}

/* ── Accept loop ─────────────────────────────────────────────────────────── */

static void *cpe_rnti_ws_thread(void *arg)
{
  (void)arg;

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) { perror("[CPE RNTI WS] socket"); return NULL; }
  int reuse = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  struct sockaddr_in sa = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = INADDR_ANY,
    .sin_port        = htons(CPE_RNTI_WS_PORT),
  };
  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("[CPE RNTI WS] bind"); close(srv); return NULL;
  }
  listen(srv, 16);
  LOG_I(NR_RRC,
        "[CPE RNTI WS] long-poll server on :%d  GET /wait_rnti?imsi=<IMSI>\n",
        CPE_RNTI_WS_PORT);

  while (1) {
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) continue;

    char buf[1024] = {0};
    recv(cli, buf, sizeof(buf) - 1, 0);

    char method[8] = {0}, path[256] = {0};
    sscanf(buf, "%7s %255s", method, path);

    if (strcmp(method, "GET") != 0 || strncmp(path, "/wait_rnti", 10) != 0) {
      send_http(cli, 404, "{\"msg\":\"GET /wait_rnti?imsi=<IMSI>\"}");
      close(cli);
      continue;
    }

    char imsi_str[CPE_UE_IMSI_STRLEN] = {0};
    if (!get_query_param(buf, "imsi", imsi_str, sizeof(imsi_str))) {
      send_http(cli, 400, "{\"msg\":\"missing imsi param\"}");
      close(cli);
      continue;
    }

    uint64_t imsi = (uint64_t)strtoull(imsi_str, NULL, 10);
    if (imsi == 0) {
      send_http(cli, 400, "{\"msg\":\"invalid imsi\"}");
      close(cli);
      continue;
    }

    conn_arg_t *ca = malloc(sizeof(*ca));
    if (!ca) { close(cli); continue; }
    ca->fd   = cli;
    ca->imsi = imsi;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, handle_wait_rnti, ca) != 0) {
      free(ca);
      close(cli);
    }
    pthread_attr_destroy(&attr);
  }

  close(srv);
  return NULL;
}

/* ── Public init ─────────────────────────────────────────────────────────── */

void cpe_rnti_ws_start(void)
{
  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&tid, &attr, cpe_rnti_ws_thread, NULL) != 0)
    LOG_E(NR_RRC, "[CPE RNTI WS] failed to start server thread\n");
  pthread_attr_destroy(&attr);
}
