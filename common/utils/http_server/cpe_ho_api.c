/*
 * CPE Handover REST API  (port 8890)
 *
 * POST /api/cpe_handover
 * {
 *   "imsi":         "460001234567890",
 *   "cpe_mac":      "AA:BB:CC:DD:EE:FF",
 *   "cpe_outer_ip": "203.0.113.5",
 *   "cpe_nat_port": 12345,
 *   "cpe_inner_ip": "192.168.1.100"
 * }
 *
 * Response (success):  {"status":"ok","rnti":"0x1A2B"}
 * Response (error):    {"status":"error","msg":"..."}
 *
 * Handler steps:
 *   1. Parse JSON body
 *   2. Find CPE's own RNTI from RRC UE tree via rrc_gNB_find_rnti_by_imsi()
 *   3. Allocate a new RNTI for CPE_UE via rrc_gNB_allocate_rnti_for_cpe_ue()
 *   4. Insert into cpe_ue_table with state = HO_IN_PROGRESS
 *   5. Return allocated RNTI in JSON
 */

#include "cpe_ho_api.h"

#include "openair2/RRC/NR/cpe_ue_context.h"
#include "openair2/RRC/NR/nr_rrc_proto.h"   /* rrc_gNB_find_rnti_by_imsi,
                                               rrc_gNB_allocate_rnti_for_cpe_ue */
#include "common/utils/LOG/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#define CPE_HO_API_PORT 8890
#define CPE_HO_BACKLOG  8
#define CPE_HO_BUF_SZ   4096

/* ── Minimal JSON field extractor ──────────────────────────────────────── */

/*
 * Extract the string value of "key" from a JSON object (no nesting).
 * Writes at most (out_len-1) bytes into *out and NUL-terminates.
 * Returns true on success.
 */
static bool json_get_str(const char *json, const char *key,
                         char *out, size_t out_len)
{
  char srch[64];
  snprintf(srch, sizeof(srch), "\"%s\"", key);
  const char *p = strstr(json, srch);
  if (!p) return false;
  p += strlen(srch);
  while (*p == ' ' || *p == ':') p++;
  if (*p == '"') {
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1)
      out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
  }
  /* numeric without quotes */
  size_t i = 0;
  while ((*p >= '0' && *p <= '9') && i < out_len - 1)
    out[i++] = *p++;
  out[i] = '\0';
  return i > 0;
}

/* ── MAC address parser  "AA:BB:CC:DD:EE:FF" → uint8_t[6] ─────────────── */

static bool parse_mac(const char *s, uint8_t mac[6])
{
  unsigned v[6] = {0};
  if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
             &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
    return false;
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
  return true;
}

/* ── HTTP helpers ──────────────────────────────────────────────────────── */

static void send_json(int fd, int http_status, const char *body)
{
  const char *status_str =
    http_status == 200 ? "200 OK" :
    http_status == 400 ? "400 Bad Request" : "500 Internal Server Error";

  char hdr[256];
  int hlen = snprintf(hdr, sizeof(hdr),
    "HTTP/1.1 %s\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n\r\n",
    status_str, strlen(body));

  send(fd, hdr,  hlen,         0);
  send(fd, body, strlen(body), 0);
}

static void handle_table_request(int cli_fd)
{
  char body[16384];
  size_t off = 0;
  int host_count = 0;

  cpe_ue_table_t *tbl = cpe_ue_table_get();
  cpe_ue_lock(tbl);

  off += snprintf(body + off, sizeof(body) - off,
                  "{\"status\":\"ok\",\"entries\":[");
  bool first = true;
  for (int i = 0; i < CPE_UE_MAX_ENTRIES && off < sizeof(body); i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (!e->valid)
      continue;
    off += snprintf(body + off, sizeof(body) - off,
                    "%s{\"slot\":%d,\"imsi\":\"%llu\",\"rnti\":\"0x%04x\","
                    "\"cpe_rnti\":\"0x%04x\",\"cpe_outer_ip\":\"%s\","
                    "\"cpe_nat_port\":%u,\"cpe_inner_ip\":\"%s\","
                    "\"pdu_session_ip\":\"%s\",\"state\":\"%s\","
                    "\"active_path\":\"%s\",\"icmp_nat\":{\"valid\":%s,"
                    "\"last_id\":%u,\"nat_id\":%u},"
                    "\"gtp\":{\"ue_id\":%u,\"n3_incoming_teid\":\"0x%08x\","
                    "\"instance\":%d,\"outgoing_teid\":\"0x%08x\","
                    "\"remote_ipv4\":\"%s\",\"ready\":%s},"
                    "\"counters\":{\"ul_packets\":%llu,\"dl_packets\":%llu}}",
                    first ? "" : ",",
                    i,
                    (unsigned long long)e->imsi,
                    e->rnti,
                    e->cpe_rnti,
                    e->cpe_outer_ip,
                    e->cpe_nat_port,
                    e->cpe_inner_ip,
                    e->pdu_session_ip,
                    cpe_ue_state_name(e->state),
                    cpe_ue_path_name(e->active_path),
                    e->has_icmp_nat ? "true" : "false",
                    e->last_icmp_id,
                    e->last_icmp_nat_id,
                    e->gtp_ue_id,
                    e->gtp_n3_incoming_teid,
                    e->gtp_instance,
                    e->gtp_outgoing_teid,
                    e->gtp_remote_ipv4,
                    e->gtp_ready ? "true" : "false",
                    (unsigned long long)e->ul_packets,
                    (unsigned long long)e->dl_packets);
    first = false;
  }

  off += snprintf(body + off, sizeof(body) - off, "],\"cpe_hosts\":[");
  char seen[CPE_UE_MAX_ENTRIES][INET_ADDRSTRLEN] = {{0}};
  first = true;
  for (int i = 0; i < CPE_UE_MAX_ENTRIES && off < sizeof(body); i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (!e->valid || e->cpe_outer_ip[0] == '\0')
      continue;

    bool known = false;
    for (int s = 0; s < host_count; s++) {
      if (strncmp(seen[s], e->cpe_outer_ip, INET_ADDRSTRLEN) == 0) {
        known = true;
        break;
      }
    }
    if (known || host_count >= CPE_UE_MAX_ENTRIES)
      continue;

    snprintf(seen[host_count++], INET_ADDRSTRLEN, "%s", e->cpe_outer_ip);
    int total = 0;
    int ru = 0;
    int cpe = 0;
    for (int j = 0; j < CPE_UE_MAX_ENTRIES; j++) {
      cpe_ue_entry_t *x = &tbl->entries[j];
      if (!x->valid || strncmp(x->cpe_outer_ip, e->cpe_outer_ip, INET_ADDRSTRLEN) != 0)
        continue;
      total++;
      if (x->active_path == CPE_UE_PATH_RU)
        ru++;
      else
        cpe++;
    }

    off += snprintf(body + off, sizeof(body) - off,
                    "%s{\"cpe_outer_ip\":\"%s\",\"total_cpe_ues\":%d,"
                    "\"active_on_cpe\":%d,\"active_on_ru\":%d}",
                    first ? "" : ",", e->cpe_outer_ip, total, cpe, ru);
    first = false;
  }
  snprintf(body + off, sizeof(body) - off, "]}");

  cpe_ue_unlock(tbl);
  send_json(cli_fd, 200, body);
}

/* ── Per-connection handler ─────────────────────────────────────────────── */

static void handle_connection(int cli_fd)
{
  char buf[CPE_HO_BUF_SZ] = {0};
  ssize_t nr = recv(cli_fd, buf, sizeof(buf) - 1, 0);
  if (nr <= 0) goto done;

  char method[8] = {0}, path[128] = {0};
  sscanf(buf, "%7s %127s", method, path);

  if (strcmp(method, "GET") == 0
      && (strcmp(path, "/api/cpe_table") == 0
          || strcmp(path, "/api/cpe_handover/table") == 0)) {
    handle_table_request(cli_fd);
    goto done;
  }

  /* Handle POST /api/cpe_handover */
  if (strcmp(method, "POST") != 0 || strcmp(path, "/api/cpe_handover") != 0) {
    send_json(cli_fd, 400,
      "{\"status\":\"error\",\"msg\":\"endpoints: POST /api/cpe_handover, GET /api/cpe_table\"}");
    goto done;
  }

  const char *body = strstr(buf, "\r\n\r\n");
  if (!body) { send_json(cli_fd, 400, "{\"status\":\"error\",\"msg\":\"no body\"}"); goto done; }
  body += 4;

  /* ── Step 1: parse JSON ─────────────────────────────────────────────── */
  char imsi_str[CPE_UE_IMSI_STRLEN] = {0};
  char mac_str[20]                  = {0};
  char outer_ip[INET_ADDRSTRLEN]    = {0};
  char nat_port_str[8]              = {0};
  char inner_ip[INET_ADDRSTRLEN]    = {0};

  bool ok = true;
  ok &= json_get_str(body, "imsi",         imsi_str,    sizeof(imsi_str));
  json_get_str(body, "cpe_mac",      mac_str,     sizeof(mac_str)); /* optional */
  ok &= json_get_str(body, "cpe_outer_ip", outer_ip,    sizeof(outer_ip));
  ok &= json_get_str(body, "cpe_nat_port", nat_port_str,sizeof(nat_port_str));
  ok &= json_get_str(body, "cpe_inner_ip", inner_ip,    sizeof(inner_ip));

  if (!ok || !imsi_str[0]) {
    send_json(cli_fd, 400,
      "{\"status\":\"error\",\"msg\":\"missing required fields\"}");
    goto done;
  }

  uint64_t imsi      = (uint64_t)strtoull(imsi_str, NULL, 10);
  uint16_t nat_port  = (uint16_t)atoi(nat_port_str);
  uint8_t  mac[6]    = {0};
  if (mac_str[0] && !parse_mac(mac_str, mac)) {
    send_json(cli_fd, 400,
      "{\"status\":\"error\",\"msg\":\"invalid cpe_mac format\"}");
    goto done;
  }

  LOG_I(NR_RRC,
        "[CPE HO] request: imsi=%llu outer=%s port=%u inner=%s mac=%s\n",
        (unsigned long long)imsi, outer_ip, nat_port, inner_ip, mac_str);

  /* ── Step 2: insert into mapping table ──────────────────────────────── */
  /* RNTI allocation is deferred — CPE_UE gets its RNTI via normal RACH.
   * The CU intercepts the Registration Request by matching IMSI. */
  cpe_ue_table_t *tbl = cpe_ue_table_get();
  cpe_ue_entry_t *entry = cpe_ue_add(tbl, imsi, mac, outer_ip, nat_port, inner_ip);
  if (!entry) {
    send_json(cli_fd, 500,
      "{\"status\":\"error\",\"msg\":\"cpe_ue table full\"}");
    goto done;
  }
  entry->state = CPE_UE_STATE_HO_IN_PROGRESS;

  /* Sync immediately to CU-UP so cpe_tun_dl_one can route DL via the outer
   * CPE's DRB even before the CPE_UE has done RACH and its own DRB is ready.
   * cpe_ue_add() already copied cpe_outer_gtp_ue_id from a sibling entry. */
  cpe_ue_sync_to_cuup(entry);

  LOG_I(NR_RRC,
        "[CPE HO] registered CPE_UE imsi=%llu — waiting for RACH\n",
        (unsigned long long)imsi);

  /* ── Step 3: respond ─────────────────────────────────────────────────── */
  char resp[128];
  snprintf(resp, sizeof(resp),
           "{\"status\":\"ok\",\"imsi\":\"%llu\"}", (unsigned long long)imsi);
  send_json(cli_fd, 200, resp);

done:
  close(cli_fd);
}

/* ── Listener thread ────────────────────────────────────────────────────── */

static void *cpe_ho_api_thread(void *arg)
{
  (void)arg;

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) { perror("[CPE HO API] socket"); return NULL; }

  int reuse = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in sa = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = INADDR_ANY,
    .sin_port        = htons(CPE_HO_API_PORT),
  };
  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("[CPE HO API] bind"); close(srv); return NULL;
  }
  listen(srv, CPE_HO_BACKLOG);
  LOG_I(NR_RRC,
        "[CPE HO API] listening on :%d  POST /api/cpe_handover\n",
        CPE_HO_API_PORT);

  while (1) {
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) continue;
    handle_connection(cli);
  }

  close(srv);
  return NULL;
}

/* ── Public init ────────────────────────────────────────────────────────── */

void cpe_ho_api_start(void)
{
  /* Init the global CPE UE mapping table once */
  cpe_ue_table_init(cpe_ue_table_get());

  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&tid, &attr, cpe_ho_api_thread, NULL) != 0)
    LOG_E(NR_RRC, "[CPE HO API] failed to start listener thread\n");
  pthread_attr_destroy(&attr);
}
