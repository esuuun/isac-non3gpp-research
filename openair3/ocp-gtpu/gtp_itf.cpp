#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <pthread.h>
#include <mysql/mysql.h>
#include <atomic>
#include "openair2/RRC/NR/cpe_ue_context.h"
#include <map>
using namespace std;

/* CPE/CPE_UE forwarding uses the normal GTP-U bearer path plus the
 * CPE LAN local-switch logic below. Legacy LBO/cpe0 control is disabled. */
#define CU_REST_PORT  8888   /* xApp HO API: /cpe/register, /cpe_route/update, /cpe/list */
#define LBO_REST_PORT 8887   /* xApp LBO API: /lbo/control, /lbo/status */

static std::atomic<int> s_lbo_enabled{0};

extern "C" int lbo_is_enabled(void) { return s_lbo_enabled.load(); }

static void http_send_json(int cli, int status, const char *reason, const char *json)
{
  char resp[512];
  size_t json_len = strlen(json);
  int len = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     status, reason, json_len, json);
  send(cli, resp, len, 0);
}

static void *lbo_rest_thread(void *arg)
{
  (void)arg;
  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) { perror("[LBO REST] socket"); return NULL; }
  int opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  struct sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(LBO_REST_PORT);
  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("[LBO REST] bind"); close(srv); return NULL;
  }
  listen(srv, 16);
  printf("[LBO REST] API on :%d  (POST /lbo/control, GET /lbo/status)\n",
         LBO_REST_PORT);
  fflush(stdout);

  while (1) {
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) continue;

    char buf[2048] = {};
    recv(cli, buf, sizeof(buf) - 1, 0);
    char method[8] = {}, path[128] = {};
    sscanf(buf, "%7s %127s", method, path);

    char *body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : (char *)"";

    if (strcmp(method, "POST") == 0 && strcmp(path, "/lbo/control") == 0) {
      if (strstr(body, "\"enable\"") && strstr(body, "1")) {
        s_lbo_enabled.store(1);
        printf("[LBO] enabled by xApp REST\n");
        http_send_json(cli, 200, "OK", "{\"enabled\":1}");
      } else if (strstr(body, "\"enable\"") && strstr(body, "0")) {
        s_lbo_enabled.store(0);
        printf("[LBO] disabled by xApp REST\n");
        http_send_json(cli, 200, "OK", "{\"enabled\":0}");
      } else {
        http_send_json(cli, 400, "Bad Request", "{\"error\":\"expected enable 0 or 1\"}");
      }
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/lbo/status") == 0) {
      char json[32];
      snprintf(json, sizeof(json), "{\"enabled\":%d}", lbo_is_enabled());
      http_send_json(cli, 200, "OK", json);
    } else {
      http_send_json(cli, 404, "Not Found",
                     "{\"endpoints\":[\"POST /lbo/control\",\"GET /lbo/status\"]}");
    }
    close(cli);
  }
  close(srv);
  return NULL;
}

/* Shared state: defined here (C++ scope), used in both cu_rest_thread
 * and the extern "C" functions below.  One definition, no duplicates. */
#define MAX_IPS 256
static char *ip_list[MAX_IPS];
static int   IP_active[MAX_IPS];
/* oai_ue_ip[idx]: the OAI UE pdu_address (10.60.0.x) on the same DU
 * as the CPE UE ip_list[idx].  Set by /cpe_route/update when active=0. */
static char  oai_ue_ip[MAX_IPS][INET_ADDRSTRLEN];
static int cpe_gtpu_table_initialized = 0;

/* ── In-memory UE GTP context cache ───────────────────────────────────────
 * Indexed by ue_id (same as ue_context MySQL table).
 * Written only on bearer setup/teardown (state-change events, not per-packet).
 * Read on every UL packet by the CPE LAN local-switch — zero DB overhead.
 * On startup, populated from MySQL so a CU-UP restart recovers state. */
typedef struct {
  uint32_t outgoing_teid;
  uint32_t incoming_teid;
  char     remote_ipv4[INET_ADDRSTRLEN];
  char     pdu_address[INET_ADDRSTRLEN];
  int      instance;
  bool     ready;
} ue_gtp_ctx_t;

static ue_gtp_ctx_t s_ue_gtp_ctx[CPE_UE_MAX_ENTRIES];

/* Load existing rows from MySQL ue_context into the in-memory cache.
 * Called once at GTP-U init so a restart doesn't lose routing state. */
static void ue_gtp_ctx_load_from_db(void)
{
  MYSQL *conn = mysql_init(NULL);
  if (!conn) return;
  if (!mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0)) {
    mysql_close(conn); return;
  }
  const char *q = "SELECT ue_id,outgoing_teid,remote_ipv4,instance,"
                  "incoming_teid,pdu_address,ready FROM ue_context";
  if (!mysql_query(conn, q)) {
    MYSQL_RES *res = mysql_store_result(conn);
    MYSQL_ROW row;
    while (res && (row = mysql_fetch_row(res))) {
      uint64_t uid = row[0] ? (uint64_t)strtoull(row[0], NULL, 10) : 0;
      if (uid == 0 || uid >= CPE_UE_MAX_ENTRIES) continue;
      ue_gtp_ctx_t *c = &s_ue_gtp_ctx[uid];
      if (row[1]) c->outgoing_teid = (uint32_t)strtoul(row[1], NULL, 10);
      if (row[2]) strncpy(c->remote_ipv4, row[2], INET_ADDRSTRLEN - 1);
      if (row[3]) c->instance      = atoi(row[3]);
      if (row[4]) c->incoming_teid = (uint32_t)strtoul(row[4], NULL, 10);
      if (row[5]) strncpy(c->pdu_address, row[5], INET_ADDRSTRLEN - 1);
      if (row[6]) c->ready = atoi(row[6]) != 0;
    }
    if (res) mysql_free_result(res);
  }
  mysql_close(conn);
  fprintf(stderr, "[UE_CTX] in-memory cache loaded from ue_context\n");
}

/* Expose in-memory cache as JSON (used by GET /ue_context/table). */
static void ue_gtp_ctx_to_json(char *buf, size_t bufsz)
{
  size_t off = 0;
  off += snprintf(buf + off, bufsz - off, "{\"ue_context\":[");
  bool first = true;
  for (int i = 0; i < CPE_UE_MAX_ENTRIES && off < bufsz; i++) {
    const ue_gtp_ctx_t *c = &s_ue_gtp_ctx[i];
    if (!c->ready && !c->outgoing_teid && !c->remote_ipv4[0]) continue;
    off += snprintf(buf + off, bufsz - off,
                    "%s{\"ue_id\":%d,\"outgoing_teid\":\"0x%08x\","
                    "\"remote_ipv4\":\"%s\",\"instance\":%d,"
                    "\"incoming_teid\":\"0x%08x\","
                    "\"pdu_address\":\"%s\",\"ready\":%s}",
                    first ? "" : ",", i,
                    c->outgoing_teid, c->remote_ipv4, c->instance,
                    c->incoming_teid, c->pdu_address,
                    c->ready ? "true" : "false");
    first = false;
  }
  snprintf(buf + off, bufsz - off, "]}");
}

static void ensure_cpe_gtpu_table(void)
{
  if (!cpe_gtpu_table_initialized) {
    cpe_ue_table_init(cpe_ue_table_get());
    cpe_gtpu_table_initialized = 1;
  }
}

/* find_or_add_ip is defined inside extern "C" — declare with matching linkage */
extern "C" int find_or_add_ip(const char *ip);

/* =========================================================
 * cu_rest_thread — port 8888
 * Called by xApp hetnet HO (xapp_hetnet_ho) to register CPE UEs
 * and update GTP-U routing on handover.
 *
 * POST /cpe/register        {"ue_ip":"...","cpe_ip":"..."}
 * POST /cpe_route/update    {"ip":"...","du_ip":"...","active":0|1}
 * GET  /cpe/list
 * GET  /cpe_route/list
 * ========================================================= */
static void *cu_rest_thread(void *arg)
{
  (void)arg;
  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) { perror("[CU REST] socket"); return NULL; }
  int opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  struct sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(CU_REST_PORT);
  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("[CU REST] bind"); close(srv); return NULL;
  }
  listen(srv, 16);
  printf("[CU REST] API on :%d  (POST /cpe_ue/update, GET /cpe_ue/table)\n",
         CU_REST_PORT);
  fflush(stdout);

  while (1) {
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) continue;
    char buf[2048] = {};
    recv(cli, buf, sizeof(buf)-1, 0);

    char method[8] = {}, path[128] = {};
    sscanf(buf, "%7s %127s", method, path);
    char *body = strstr(buf, "\r\n\r\n");
    char jbody[512] = {};
    if (body) {
      body += 4;
      strncpy(jbody, body, sizeof(jbody)-1);
      /* trim trailing whitespace */
      for (int i=(int)strlen(jbody)-1;
           i>=0 && (jbody[i]=='\r'||jbody[i]=='\n'||jbody[i]==' '); i--)
        jbody[i] = '\0';
    }

    const char *ok200 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length:15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
    const char *bad400 = "HTTP/1.1 400 Bad Request\r\nContent-Length:0\r\n\r\n";
    const char *err500 = "HTTP/1.1 500 Internal Server Error\r\nContent-Length:0\r\n\r\n";
    const char *gone410 =
      "HTTP/1.1 410 Gone\r\nContent-Type: application/json\r\n"
      "Content-Length:67\r\nConnection: close\r\n\r\n"
      "{\"status\":\"error\",\"msg\":\"legacy LBO endpoint disabled; use cpe_ue\"}";

    /* helper: extract "key":"val" or "key":num from JSON */
    #define CU_JSON_GET(json, key, out, outlen) do { \
      char _srch[64]; snprintf(_srch, sizeof(_srch), "\"%s\"", key); \
      char *_p = strstr((json), _srch); \
      if (_p) { _p += strlen(_srch); \
        while (*_p==' '||*_p==':') _p++; \
        if (*_p=='"') { _p++; int _i=0; \
          while (*_p&&*_p!='"'&&_i<(int)(outlen)-1) (out)[_i++]=*_p++; \
          (out)[_i]='\0'; } \
        else { int _i=0; \
          while ((*_p>='0'&&*_p<='9')&&_i<(int)(outlen)-1) (out)[_i++]=*_p++; \
          (out)[_i]='\0'; } } } while(0)

    /* ---- POST /cpe/register ---- */
    if (strcmp(method,"POST")==0 && strcmp(path,"/cpe/register")==0) {
      send(cli, gone410, strlen(gone410), 0);

    /* ---- POST /cpe_route/update ---- */
    } else if (strcmp(method,"POST")==0 && strcmp(path,"/cpe_route/update")==0) {
      send(cli, gone410, strlen(gone410), 0);

    /* ---- POST /cpe_ue/update ----
     * Synchronize the CU-CP CPE_UE table into the CU-UP/GTP-U process.
     * body:
     * {"imsi":"208930000022222","rnti":"0xb8f8","cpe_outer_ip":"10.60.0.38",
     *  "cpe_nat_port":12345,"cpe_inner_ip":"192.168.1.100",
     *  "pdu_session_ip":"192.168.1.100","active_path":"RU"}
     */
    } else if (strcmp(method,"POST")==0 && strcmp(path,"/cpe_ue/update")==0) {
      char imsi_s[32]={}, rnti_s[16]={}, outer_ip[32]={}, nat_s[16]={}, cpe_rnti_s[16]={};
      char inner_ip[32]={}, pdu_ip[32]={}, active_path[16]={}, gtp_ue_id_s[16]={};
      char outer_gtp_ue_id_s[16]={};
      CU_JSON_GET(jbody, "imsi", imsi_s, sizeof(imsi_s));
      CU_JSON_GET(jbody, "rnti", rnti_s, sizeof(rnti_s));
      CU_JSON_GET(jbody, "cpe_outer_ip", outer_ip, sizeof(outer_ip));
      CU_JSON_GET(jbody, "cpe_nat_port", nat_s, sizeof(nat_s));
      CU_JSON_GET(jbody, "cpe_rnti", cpe_rnti_s, sizeof(cpe_rnti_s));
      CU_JSON_GET(jbody, "cpe_inner_ip", inner_ip, sizeof(inner_ip));
      CU_JSON_GET(jbody, "pdu_session_ip", pdu_ip, sizeof(pdu_ip));
      CU_JSON_GET(jbody, "active_path", active_path, sizeof(active_path));
      CU_JSON_GET(jbody, "gtp_ue_id", gtp_ue_id_s, sizeof(gtp_ue_id_s));
      CU_JSON_GET(jbody, "cpe_outer_gtp_ue_id", outer_gtp_ue_id_s, sizeof(outer_gtp_ue_id_s));
      if (!imsi_s[0] || !outer_ip[0] || !nat_s[0] || !inner_ip[0]) {
        send(cli,bad400,strlen(bad400),0);
        close(cli);
        continue;
      }

      ensure_cpe_gtpu_table();
      uint64_t imsi = (uint64_t)strtoull(imsi_s, NULL, 10);
      uint16_t nat_port = (uint16_t)atoi(nat_s);
      cpe_ue_table_t *tbl = cpe_ue_table_get();
      cpe_ue_entry_t *entry = cpe_ue_add(tbl, imsi, NULL, outer_ip, nat_port, inner_ip);
      if (!entry) {
        send(cli,err500,strlen(err500),0);
        close(cli);
        continue;
      }

      cpe_ue_lock(tbl);
      entry = cpe_ue_find_by_imsi_locked(tbl, imsi);
      if (entry) {
        if (rnti_s[0])
          entry->rnti = (uint16_t)strtoul(rnti_s, NULL, 0);
        if (cpe_rnti_s[0])
          entry->cpe_rnti = (uint16_t)strtoul(cpe_rnti_s, NULL, 0);
        if (pdu_ip[0])
          snprintf(entry->pdu_session_ip, sizeof(entry->pdu_session_ip), "%s", pdu_ip);
        entry->state = pdu_ip[0] ? CPE_UE_STATE_NR_CONNECTED : CPE_UE_STATE_HO_IN_PROGRESS;
        entry->active_path = strcmp(active_path, "RU") == 0 ? CPE_UE_PATH_RU : CPE_UE_PATH_CPE;
        if (gtp_ue_id_s[0])
          entry->gtp_ue_id = (uint32_t)strtoul(gtp_ue_id_s, NULL, 10);
        if (outer_gtp_ue_id_s[0])
          entry->cpe_outer_gtp_ue_id = (uint32_t)strtoul(outer_gtp_ue_id_s, NULL, 10);
        if (entry->cpe_outer_gtp_ue_id != 0 && entry->cpe_outer_ip[0])
          cpe_ue_table_upsert_ue_context(entry->cpe_outer_gtp_ue_id,
                                          entry->cpe_rnti,
                                          entry->cpe_outer_ip,
                                          "CPE_HOST");
        cpe_ue_table_persist_locked(tbl);
      }
      cpe_ue_unlock(tbl);

      printf("[CU-UP CPE_UE] update imsi=%s inner=%s outer=%s port=%u pdu=%s path=%s gtp_ue_id=%s cpe_outer_gtp_ue_id=%s\n",
             imsi_s, inner_ip, outer_ip, nat_port, pdu_ip,
             active_path[0] ? active_path : "CPE",
             gtp_ue_id_s[0] ? gtp_ue_id_s : "0",
             outer_gtp_ue_id_s[0] ? outer_gtp_ue_id_s : "0");
      fflush(stdout);
      send(cli, ok200, strlen(ok200), 0);

    /* ---- GET /cpe_ue/table ---- */
    } else if (strcmp(method,"GET")==0 && strcmp(path,"/cpe_ue/table")==0) {
      ensure_cpe_gtpu_table();
      char result[8192];
      size_t off = 0;
      cpe_ue_table_t *tbl = cpe_ue_table_get();
      cpe_ue_lock(tbl);
      off += snprintf(result + off, sizeof(result) - off, "{\"entries\":[");
      bool first = true;
      for (int i = 0; i < CPE_UE_MAX_ENTRIES && off < sizeof(result); i++) {
        cpe_ue_entry_t *e = &tbl->entries[i];
        if (!e->valid)
          continue;
        off += snprintf(result + off, sizeof(result) - off,
                        "%s{\"imsi\":\"%llu\",\"rnti\":\"0x%04x\","
                        "\"inner\":\"%s\",\"outer\":\"%s\",\"port\":%u,"
                        "\"pdu\":\"%s\",\"state\":\"%s\",\"path\":\"%s\","
                        "\"gtp\":{\"ue_id\":%u,\"n3_incoming_teid\":\"0x%08x\","
                        "\"instance\":%d,\"outgoing_teid\":\"0x%08x\","
                        "\"remote_ipv4\":\"%s\",\"ready\":%s},"
                        "\"ul\":%llu,\"dl\":%llu,\"icmp_nat\":%s}",
                        first ? "" : ",",
                        (unsigned long long)e->imsi,
                        e->rnti,
                        e->cpe_inner_ip,
                        e->cpe_outer_ip,
                        e->cpe_nat_port,
                        e->pdu_session_ip,
                        cpe_ue_state_name(e->state),
                        cpe_ue_path_name(e->active_path),
                        e->gtp_ue_id,
                        e->gtp_n3_incoming_teid,
                        e->gtp_instance,
                        e->gtp_outgoing_teid,
                        e->gtp_remote_ipv4,
                        e->gtp_ready ? "true" : "false",
                        (unsigned long long)e->ul_packets,
                        (unsigned long long)e->dl_packets,
                        e->has_icmp_nat ? "true" : "false");
        first = false;
      }
      snprintf(result + off, sizeof(result) - off, "]}");
      cpe_ue_unlock(tbl);

      char resp[8192+128];
      int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(result), result);
      send(cli, resp, rlen, 0);

    /* ---- GET /ue_context/table — in-memory UE GTP context cache ---- */
    } else if (strcmp(method,"GET")==0 && strcmp(path,"/ue_context/table")==0) {
      char result[4096];
      ue_gtp_ctx_to_json(result, sizeof(result));
      char resp[4200];
      int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(result), result);
      send(cli, resp, rlen, 0);

    /* ---- GET /cpe/list  or  GET /cpe_route/list ---- */
    } else if (strcmp(method,"GET")==0 &&
               (strcmp(path,"/cpe/list")==0 || strcmp(path,"/cpe_route/list")==0)) {
      send(cli, gone410, strlen(gone410), 0);

    } else {
      const char *info = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
        "Content-Length:81\r\nConnection: close\r\n\r\n"
        "{\"endpoints\":[\"POST /cpe_ue/update\","
        "\"GET /cpe_ue/table\",\"GET /ue_context/table\"]}";
      send(cli, info, strlen(info), 0);
    }
    #undef CU_JSON_GET
    close(cli);
  }
  close(srv);
  return NULL;
}

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>

// add---------------------------------------
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
//#include <cJSON.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
//----------------------------------------

#include "common/platform_types.h"
#include <openair3/UTILS/conversions.h>
#include "common/utils/LOG/log.h"
#include <common/utils/ocp_itti/intertask_interface.h>
#include <openair2/COMMON/gtpv1_u_messages_types.h>
#include <openair3/ocp-gtpu/gtp_itf.h>
#include <openair2/LAYER2/PDCP_v10.1.0/pdcp.h>
#include <openair2/LAYER2/nr_pdcp/nr_pdcp_oai_api.h>
#include <openair2/LAYER2/nr_rlc/nr_rlc_oai_api.h>
#include "openair2/SDAP/nr_sdap/nr_sdap.h"
#include "sim.h"

//add -------------------------------------
#include <pthread.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
/* Rename MySQL's randominit to avoid conflict with OAI sim.h */
#define randominit __mysql_randominit
#include <mysql/mysql.h>
#undef randominit
#include <stdbool.h>
#include <openair3/NGAP/ngap_gNB_handlers.h>
#include "openair2/RRC/NR/cpe_ue_context.h"
//-----------------------------------------

//static int IP_active = 0;

//-----------------------------------------
// dhcp define
#define MAX_LEASES 128
#define DHCP_SERVER_IP {192, 168, 1, 1}
#define DHCP_LEASE_TIME 86400 // 1 day

typedef struct Lease {
    uint8_t mac[6];
    uint8_t ip[4];
    time_t lease_start;
    int active;
} Lease;

Lease leases[MAX_LEASES];

// �M��{������
Lease* find_lease(uint8_t* mac) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (leases[i].active && memcmp(leases[i].mac, mac, 6) == 0) {
            return &leases[i];
        }
    }
    return NULL;
}

// ���t�s IP
Lease* assign_new_ip(uint8_t* mac) {
    for (int i = 100; i <= 200; i++) {
        uint8_t ip[4] = {192, 168, 1, (uint8_t)i};
        int used = 0;
        for (int j = 0; j < MAX_LEASES; j++) {
            if (leases[j].active && memcmp(leases[j].ip, ip, 4) == 0) {
                used = 1;
                break;
            }
        }

        if (!used) {
            for (int j = 0; j < MAX_LEASES; j++) {
                if (!leases[j].active) {
                    memcpy(leases[j].mac, mac, 6);
                    memcpy(leases[j].ip, ip, 4);
                    leases[j].lease_start = time(NULL);
                    leases[j].active = 1;
                    return &leases[j];
                }
            }
        }
    }
    return NULL;
}

//---------------------------------------------------------------

#pragma pack(1)

typedef struct Gtpv1uMsgHeader {
  uint8_t PN:1;
  uint8_t S:1;
  uint8_t E:1;
  uint8_t spare:1;
  uint8_t PT:1;
  uint8_t version:3;
  uint8_t msgType;
  uint16_t msgLength;
  teid_t teid;
} __attribute__((packed)) Gtpv1uMsgHeaderT;

//TS 38.425, Figure 5.5.2.2-1
typedef struct DlDataDeliveryStatus_flags {
  uint8_t LPR:1;                    //Lost packet report
  uint8_t FFI:1;                    //Final Frame Ind
  uint8_t deliveredPdcpSn:1;        //Highest Delivered NR PDCP SN Ind
  uint8_t transmittedPdcpSn:1;      //Highest Transmitted NR PDCP SN Ind
  uint8_t pduType:4;                //PDU type
  uint8_t CR:1;                     //Cause Report
  uint8_t deliveredReTxPdcpSn:1;    //Delivered retransmitted NR PDCP SN Ind
  uint8_t reTxPdcpSn:1;             //Retransmitted NR PDCP SN Ind
  uint8_t DRI:1;                    //Data Rate Indication
  uint8_t deliveredPdcpSnRange:1;   //Delivered NR PDCP SN Range Ind
  uint8_t spare:3;
  uint32_t drbBufferSize;            //Desired buffer size for the data radio bearer
} __attribute__((packed)) DlDataDeliveryStatus_flagsT;

typedef struct Gtpv1uMsgHeaderOptFields {
  uint8_t seqNum1Oct;
  uint8_t seqNum2Oct;
  uint8_t NPDUNum;
  uint8_t NextExtHeaderType;    
} __attribute__((packed)) Gtpv1uMsgHeaderOptFieldsT;

#define DL_PDU_SESSION_INFORMATION 0
#define UL_PDU_SESSION_INFORMATION 1

  typedef struct PDUSessionContainer {
  uint8_t spare:4;
  uint8_t PDU_type:4;
  uint8_t QFI:6;
  uint8_t Reflective_QoS_activation:1;
  uint8_t Paging_Policy_Indicator:1;
} __attribute__((packed)) PDUSessionContainerT;

typedef struct Gtpv1uExtHeader {
  uint8_t ExtHeaderLen;
  PDUSessionContainerT pdusession_cntr;
  uint8_t NextExtHeaderType;
}__attribute__((packed)) Gtpv1uExtHeaderT;

#pragma pack()

// TS 29.281, fig 5.2.1-3
#define PDU_SESSION_CONTAINER       (0x85)
#define NR_RAN_CONTAINER            (0x84)

/* Compatibility typedefs for LBO code (older OAI API) */
typedef int pdusessionid_t;
typedef struct {
  uint8_t  *buffer;
  uint32_t  offset;
  uint32_t  length;
  ue_id_t   ue_id;
  int       bearer_id;
} gtpv1u_tunnel_data_req_t;

// TS 29.281, 5.2.1
#define EXT_HDR_LNTH_OCTET_UNITS    (4)
#define NO_MORE_EXT_HDRS            (0)

// TS 29.060, table 7.1 defines the possible message types
// here are all the possible messages (3GPP R16)
#define GTP_ECHO_REQ                                         (1)
#define GTP_ECHO_RSP                                         (2)
#define GTP_ERROR_INDICATION                                 (26)
#define GTP_SUPPORTED_EXTENSION_HEADER_INDICATION            (31)
#define GTP_END_MARKER                                       (254)
#define GTP_GPDU                                             (255)

typedef struct gtpv1u_bearer_s {
  /* TEID used in dl and ul */
  teid_t          teid_incoming;                ///< eNB TEID
  teid_t          teid_outgoing;                ///< Remote TEID
  in_addr_t       outgoing_ip_addr;
  struct in6_addr outgoing_ip6_addr;
  tcp_udp_port_t  outgoing_port;
  uint16_t        seqNum;
  uint8_t         npduNum;
  int outgoing_qfi;
} gtpv1u_bearer_t;

typedef struct {
  map<ue_id_t, gtpv1u_bearer_t> bearers;
  teid_t outgoing_teid;
} teidData_t;

typedef struct {
  ue_id_t ue_id;
  ebi_t incoming_rb_id;
  gtpCallback callBack;
  teid_t outgoing_teid;
  gtpCallbackSDAP callBackSDAP;
  int pdusession_id;
} ueidData_t;

class gtpEndPoint {
 public:
  openAddr_t addr;
  uint8_t foundAddr[20];
  int foundAddrLen;
  int ipVersion;
  map<uint64_t, teidData_t> ue2te_mapping;
  // we use the same port number for source and destination address
  // this allow using non standard gtp port number (different from 2152)
  // and so, for example tu run 4G and 5G cores on one system
  tcp_udp_port_t get_dstport() {
    return (tcp_udp_port_t)atol(addr.destinationService);
  }
};

class gtpEndPoints {
 public:
  pthread_mutex_t gtp_lock=PTHREAD_MUTEX_INITIALIZER;
  // the instance id will be the Linux socket handler, as this is uniq
  map<uint64_t, gtpEndPoint> instances;
  map<uint64_t, ueidData_t> te2ue_mapping;
  gtpEndPoints() {
    unsigned int seed;
    fill_random(&seed, sizeof(seed));
    srandom(seed);
  }

  ~gtpEndPoints() {
    // automatically close all sockets on quit
    for (const auto &p : instances)
      close(p.first);
  }
};

gtpEndPoints globGtp;

// note TEid 0 is reserved for specific usage: echo req/resp, error and supported extensions
static  teid_t gtpv1uNewTeid(void) {
#ifdef GTPV1U_LINEAR_TEID_ALLOCATION
  g_gtpv1u_teid = g_gtpv1u_teid + 1;
  return g_gtpv1u_teid;
#else
  return random() + random() % (RAND_MAX - 1) + 1;
#endif
}

instance_t legacyInstanceMapping=0;
#define compatInst(a) ((a)==0 || (a)==INSTANCE_DEFAULT ? legacyInstanceMapping:a)

#define getInstRetVoid(insT)                                    \
  auto instChk=globGtp.instances.find(compatInst(insT));    \
  if (instChk == globGtp.instances.end()) {                        \
    LOG_E(GTPU,"try to get a gtp-u not existing output\n");     \
    pthread_mutex_unlock(&globGtp.gtp_lock);                    \
    return;                                                     \
  }                                                             \
  gtpEndPoint * inst=&instChk->second;
  
#define getInstRetInt(insT)                                    \
  auto instChk=globGtp.instances.find(compatInst(insT));    \
  if (instChk == globGtp.instances.end()) {                        \
    LOG_E(GTPU,"try to get a gtp-u not existing output\n");     \
    pthread_mutex_unlock(&globGtp.gtp_lock);                    \
    return GTPNOK;                                                     \
  }                                                             \
  gtpEndPoint * inst=&instChk->second;


#define getUeRetVoid(insT, Ue)                                            \
    auto ptrUe=insT->ue2te_mapping.find(Ue);                        \
                                                                        \
  if (  ptrUe==insT->ue2te_mapping.end() ) {                          \
    LOG_E(GTPU, "[%ld] gtpv1uSend failed: while getting ue id %ld in hashtable ue_mapping\n", instance, ue_id); \
    pthread_mutex_unlock(&globGtp.gtp_lock);                            \
    return;                                                             \
  }
  
#define getUeRetInt(insT, Ue)                                            \
    auto ptrUe=insT->ue2te_mapping.find(Ue);                        \
                                                                        \
  if (  ptrUe==insT->ue2te_mapping.end() ) {                          \
    LOG_E(GTPU, "[%ld] gtpv1uSend failed: while getting ue id %ld in hashtable ue_mapping\n", instance, ue_id); \
    pthread_mutex_unlock(&globGtp.gtp_lock);                            \
    return GTPNOK;                                                             \
  }
//------------------------------------------------------------------------
// add dump
void dump_data(uint8_t *data, int len)
{
  int     i;
  int     j;
  int     k;
  for(i=0;i<len;i+=16) {
    printf("%8.8x ", i);
    k = len - i;
    if (k > 16)
            k = 16;
    k += i;
    for(j=i; j<(i+16); j++) {
            if (j < k)
                    printf("%2.2x ", data[j] );
            else
                    printf("   ");
    }
    printf("  ");
    for(j=i; j<k; j++) {
            printf("%c", isprint(data[j]) ? data[j] : '.' );
    }
    printf("\n");
  }
}
//------------------------------------------------------------------------ 
#define HDR_MAX 256 // 256 is supposed to be larger than any gtp header
static int gtpv1uCreateAndSendMsg(int h,
                                  uint32_t peerIp,
                                  uint16_t peerPort,
                                  int msgType,
                                  teid_t teid,
                                  uint8_t *Msg,
                                  int msgLen,
                                  bool seqNumFlag,
                                  bool npduNumFlag,
                                  int seqNum,
                                  int npduNum,
                                  int extHdrType,
                                  uint8_t *extensionHeader_buffer,
                                  uint8_t extensionHeader_length) {
/* char ip_str[INET_ADDRSTRLEN];
struct in_addr ip_addr;
ip_addr.s_addr = peerIp;  // ���A htonl()
inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
printf("[GTPU] Peer IP: %s, Peer Port: %u, Outgoing TEID: %u\n", ip_str, peerPort, teid); */                              
  LOG_D(GTPU, "Peer IP:%u peer port:%u outgoing teid:%u \n", peerIp, peerPort, teid);
//  printf("[GTPU] Peer IP: %u, Peer Port: %u, Outgoing TEID: %u\n", peerIp, peerPort, teid);
  //struct timespec start, end;
  //clock_gettime(CLOCK_MONOTONIC, &start);
  uint8_t buffer[msgLen+HDR_MAX]; 
  uint8_t *curPtr=buffer;
  Gtpv1uMsgHeaderT      *msgHdr = (Gtpv1uMsgHeaderT *)buffer ;
  // N should be 0 for us (it was used only in 2G and 3G)
  msgHdr->PN=npduNumFlag;
  msgHdr->S=seqNumFlag;
  msgHdr->E = extHdrType != NO_MORE_EXT_HDRS;
  msgHdr->spare=0;
  //PT=0 is for GTP' TS 32.295 (charging)
  msgHdr->PT=1;
  msgHdr->version=1;
  msgHdr->msgType=msgType;
  msgHdr->teid=htonl(teid);

  curPtr+=sizeof(Gtpv1uMsgHeaderT);

  if (seqNumFlag || (extHdrType != NO_MORE_EXT_HDRS) || npduNumFlag) {
    *(uint16_t *)curPtr = seqNumFlag ? seqNum : 0x0000;
    curPtr+=sizeof(uint16_t);
    *(uint8_t *)curPtr = npduNumFlag ? npduNum : 0x00;
    curPtr++;
    *(uint8_t *)curPtr = extHdrType;
    curPtr++;
  }

  // Bug: if there is more than one extension, infinite loop on extensionHeader_buffer
  while (extHdrType != NO_MORE_EXT_HDRS) {
    if (extensionHeader_length > 0) {
      memcpy(curPtr, extensionHeader_buffer, extensionHeader_length);
      curPtr += extensionHeader_length;
      LOG_D(GTPU, "Extension Header for DDD added. The length is: %d, extension header type is: %x \n", extensionHeader_length, *((uint8_t *)(buffer + 11)));
      extHdrType = extensionHeader_buffer[extensionHeader_length - 1];
      LOG_D(GTPU, "Next extension header type is: %x \n", *((uint8_t *)(buffer + 11)));
    } else {
      LOG_W(GTPU, "Extension header type not supported, returning... \n");
    }
  }

  if (Msg!= NULL){
    memcpy(curPtr, Msg, msgLen);
    curPtr+=msgLen;
  }

  msgHdr->msgLength = htons(curPtr-(buffer+sizeof(Gtpv1uMsgHeaderT)));
  AssertFatal(curPtr-(buffer+msgLen) < HDR_MAX, "fixed max size of all headers too short");
  // Fix me: add IPv6 support, using flag ipVersion
  struct sockaddr_in to= {0};
  to.sin_family      = AF_INET;
  to.sin_port        = htons(peerPort);
  to.sin_addr.s_addr = peerIp ;
  LOG_D(GTPU,"sending packet size: %ld to %s\n",curPtr-buffer, inet_ntoa(to.sin_addr) );
  //LOG_I(GTPU,"sending packet size: %ld to %s\n",curPtr-buffer, inet_ntoa(to.sin_addr) );
  //printf("sending packet size: %ld to %s\n", curPtr - buffer, inet_ntoa(to.sin_addr));
  //dump_data(buffer, curPtr - buffer);
  int ret;

  if ((ret=sendto(h, (void *)buffer, curPtr-buffer, 0,(struct sockaddr *)&to, sizeof(to) )) != curPtr-buffer ) {
    LOG_E(GTPU, "[SD %d] Failed to send data to " IPV4_ADDR " on port %d, buffer size %lu, ret: %d, errno: %d\n",
          h, IPV4_ADDR_FORMAT(peerIp), peerPort, curPtr-buffer, ret, errno);
    return GTPNOK;
  }
  //clock_gettime(CLOCK_MONOTONIC, &end);
  //printf("Elapsed time = %.3f ms\n", 
  //     (end.tv_sec - start.tv_sec) * 1000.0 + 
  //    (end.tv_nsec - start.tv_nsec) / 1000000.0);
  return  !GTPNOK;
}



//------------------------------------------------------------------------
//check sum
static uint16_t checksum(uint16_t *buf, int len) {
  uint32_t sum = 0;
  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) {
    sum += *(uint8_t *)buf;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (uint16_t)~sum;
}
//-------------------------------------------------------------------------
// === checksum utility ===
uint16_t ip_checksum(void* vdata, size_t length) {
  uint8_t* data = (uint8_t*)vdata;
  uint32_t sum = 0;

  for (size_t i = 0; i + 1 < length; i += 2) {
      sum += (data[i] << 8) + data[i + 1];
  }
  if (length & 1) {
      sum += data[length - 1] << 8;
  }

  while (sum >> 16)
      sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}
//-------------------------------------------------------------------------
// get ens19 MAC
void get_mac_address(const char *interface, uint8_t *mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    } else {
        perror("ioctl failed");
    }
    close(sock);
}

//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// arp
int get_mac_address_by_ip(uint32_t ip, uint8_t *mac) {
    char cmd[100];
    FILE *fp;
    unsigned int ip1, ip2, ip3, ip4;
    unsigned int mac1, mac2, mac3, mac4, mac5, mac6;

    ip1 = (ip >> 24) & 0xFF;
    ip2 = (ip >> 16) & 0xFF;
    ip3 = (ip >> 8) & 0xFF;
    ip4 = ip & 0xFF;

    // Use the arp command to query the MAC address corresponding to the IP
    sprintf(cmd, "arp -n %d.%d.%d.%d | awk '/%d.%d.%d.%d/ {print $3}'", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to execute arp command");
        return -1;
    }

    if (fscanf(fp, "%x:%x:%x:%x:%x:%x", &mac1, &mac2, &mac3, &mac4, &mac5, &mac6) == 6) {
        mac[0] = mac1;
        mac[1] = mac2;
        mac[2] = mac3;
        mac[3] = mac4;
        mac[4] = mac5;
        mac[5] = mac6;
    } else {
        printf("Unable to obtain MAC address\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

#define ETH_P_ARP 0x0806

// ARP �Y�����c
struct arp_header {
    uint16_t htype;   // �w������
    uint16_t ptype;   // ��ĳ����
    uint8_t hlen;     // �w��a�}����
    uint8_t plen;     // ��ĳ�a�}����
    uint16_t oper;    // �ާ@�X (1 = request, 2 = reply)
    uint8_t sha[6];   // �o�e�� MAC �a�}
    uint8_t spa[4];   // �o�e�� IP �a�}
    uint8_t tha[6];   // �ؼ� MAC �a�}
    uint8_t tpa[4];   // �ؼ� IP �a�}
};
//-------------------------------------------------------------------------
//-------------------------------------------------------------------------
/*
static void gtpv1uSend(instance_t instance, gtpv1u_tunnel_data_req_t *req, bool seqNumFlag, bool npduNumFlag) {
  uint8_t *buffer=req->buffer+req->offset;

  size_t length=req->length;
  // [perf] dump_data(buffer, length);

  ue_id_t ue_id=req->ue_id;
  int  bearer_id=req->bearer_id;
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetVoid(compatInst(instance));
  getUeRetVoid(inst, ue_id);

  auto ptr2=ptrUe->second.bearers.find(bearer_id);

  if ( ptr2 == ptrUe->second.bearers.end() ) {
    LOG_E(GTPU,"[%ld] GTP-U instance: sending a packet to a non existant UE:RAB: %lx/%x\n", instance, ue_id, bearer_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return;
  }

  LOG_D(GTPU,"[%ld] sending a packet to UE:RAB:teid %lx/%x/%x, len %lu, oldseq %d, oldnum %d\n",
        instance, ue_id, bearer_id,ptr2->second.teid_outgoing,length, ptr2->second.seqNum,ptr2->second.npduNum );

  if(seqNumFlag)
    ptr2->second.seqNum++;

  if(npduNumFlag)
    ptr2->second.npduNum++;

  // copy to release the mutex
  gtpv1u_bearer_t tmp=ptr2->second;
  pthread_mutex_unlock(&globGtp.gtp_lock);

  if (tmp.outgoing_qfi != -1) {
    Gtpv1uExtHeaderT ext = { 0 };
    ext.ExtHeaderLen = 1; // in quad bytes  EXT_HDR_LNTH_OCTET_UNITS
    ext.pdusession_cntr.spare = 0;
    ext.pdusession_cntr.PDU_type = UL_PDU_SESSION_INFORMATION;
    ext.pdusession_cntr.QFI = tmp.outgoing_qfi;
    ext.pdusession_cntr.Reflective_QoS_activation = false;
    ext.pdusession_cntr.Paging_Policy_Indicator = false;
    ext.NextExtHeaderType = NO_MORE_EXT_HDRS;

    gtpv1uCreateAndSendMsg(compatInst(instance),
                           tmp.outgoing_ip_addr,
                           tmp.outgoing_port,
                           GTP_GPDU,
                           tmp.teid_outgoing,
                           buffer,
                           length,
                           seqNumFlag,
                           npduNumFlag,
                           tmp.seqNum,
                           tmp.npduNum,
                           PDU_SESSION_CONTAINER,
                           (uint8_t *)&ext,
                           sizeof(ext));
  } else {
    gtpv1uCreateAndSendMsg(
        compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port, GTP_GPDU, tmp.teid_outgoing, buffer, length, seqNumFlag, npduNumFlag, tmp.seqNum, tmp.npduNum, NO_MORE_EXT_HDRS, NULL, 0);
  }
}
*/
//------------------------------------------------------------------
//gtp_u send modify
/*static void gtpv1uSend(instance_t instance, gtpv1u_tunnel_data_req_t *req, bool seqNumFlag, bool npduNumFlag) {
    uint8_t *buffer = req->buffer + req->offset;
    size_t length = req->length;

    // [perf] dump_data(buffer, length);

    ue_id_t ue_id = req->ue_id;
    int bearer_id = req->bearer_id;
    // [perf] printf("ue_id: %lu\n", ue_id);  // �ϥ� %lu �ӿ�X�����

    // ��������� MAC �a�}
    uint8_t src_mac[6];
    get_mac_address("ens18", src_mac);  // �ϥ�ens19���MAC�a�}

    // ���]�ت� MAC �a�}�O�q�ʥ]���Y�Ǧa�责�����A�Ҧp�b�H�Ӻ����Y��
    uint8_t dst_mac[6];
    memcpy(dst_mac, buffer + 30, 6);

    // ���L������ MAC �a�}
    // [perf] printf("SRC MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", src_mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    // ���L�ت� MAC �a�}
    // [perf] printf("DST MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", dst_mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    pthread_mutex_lock(&globGtp.gtp_lock);
    getInstRetVoid(compatInst(instance));
    getUeRetVoid(inst, ue_id);

    auto ptr2 = ptrUe->second.bearers.find(bearer_id);

    if (ptr2 == ptrUe->second.bearers.end()) {
        LOG_E(GTPU,"[%ld] GTP-U instance: sending a packet to a non existant UE:RAB: %lx/%x\n", instance, ue_id, bearer_id);
        pthread_mutex_unlock(&globGtp.gtp_lock);
        return;
    }

    LOG_D(GTPU,"[%ld] sending a packet to UE:RAB:teid %lx/%x/%x, len %lu, oldseq %d, oldnum %d\n",
          instance, ue_id, bearer_id, ptr2->second.teid_outgoing, length, ptr2->second.seqNum, ptr2->second.npduNum );

    if (seqNumFlag)
        ptr2->second.seqNum++;

    if (npduNumFlag)
        ptr2->second.npduNum++;

    // copy to release the mutex
    gtpv1u_bearer_t tmp = ptr2->second;
    pthread_mutex_unlock(&globGtp.gtp_lock);

    // Check for GRE packet and process specific conditions
    if (buffer[22] == 0x65 && buffer[23] == 0x58) { // Confirm GRE packet
        if ((buffer[59] == 0x44 && buffer[61] == 0x43) || (buffer[36] == 0x08 && buffer[37] == 0x06)) { // DHCP & ARP to IND Box
            // [perf] printf("Is ARP packet\n");
            unsigned char packet[1024];
            memset(packet, 0, 1024);

            // Ethernet header
            struct ether_header *eth_header = (struct ether_header *)packet;
            memcpy(eth_header->ether_dhost, dst_mac, ETH_ALEN);
            memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
            eth_header->ether_type = htons(ETH_P_IP);

            memcpy(packet + sizeof(struct ether_header), buffer, length);

            int packet_len = sizeof(struct ether_header) + length;

            int rawsockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));  // �Ыح�l�M���r
            if (rawsockfd == -1) {
                perror("socket");
                exit(EXIT_FAILURE);
            }

            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_protocol = htons(ETH_P_IP);  // �]�w��ĳ�����]�Ҧp IP�^
            sll.sll_ifindex = if_nametoindex("ens18");  // �]�w���f���ޡA�o�̰��]�ϥ� ens19

            if (sendto(rawsockfd, packet, packet_len, 0, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
                perror("sendto");
                close(rawsockfd);
                exit(EXIT_FAILURE);
            }

            close(rawsockfd);
        }
    }

    if (tmp.outgoing_qfi != -1) {
        Gtpv1uExtHeaderT ext = { 0 };
        ext.ExtHeaderLen = 1; // in quad bytes  EXT_HDR_LNTH_OCTET_UNITS
        ext.pdusession_cntr.spare = 0;
        ext.pdusession_cntr.PDU_type = UL_PDU_SESSION_INFORMATION;
        ext.pdusession_cntr.QFI = tmp.outgoing_qfi;
        ext.pdusession_cntr.Reflective_QoS_activation = false;
        ext.pdusession_cntr.Paging_Policy_Indicator = false;
        ext.NextExtHeaderType = NO_MORE_EXT_HDRS;

        gtpv1uCreateAndSendMsg(compatInst(instance),
                               tmp.outgoing_ip_addr,
                               tmp.outgoing_port,
                               GTP_GPDU,
                               tmp.teid_outgoing,
                               buffer,
                               length,
                               seqNumFlag,
                               npduNumFlag,
                               tmp.seqNum,
                               tmp.npduNum,
                               PDU_SESSION_CONTAINER,
                               (uint8_t *)&ext,
                               sizeof(ext));
    } else {
        gtpv1uCreateAndSendMsg(
            compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port, GTP_GPDU, tmp.teid_outgoing, buffer, length, seqNumFlag, npduNumFlag, tmp.seqNum, tmp.npduNum, NO_MORE_EXT_HDRS, NULL, 0);
    }
}
*/
//---------------------------------------------------------------------------------
void parse_packet(unsigned char *buffer, int length) {
    // 1. �ѪR IPv4 �Y�� (20 �r�`)
    struct ip *ip_hdr = (struct ip *)buffer;
    
    // �T�{�O���O IPv4
    if (ip_hdr->ip_v == 4) {
        // [perf] printf("IPv4 Header\n");
        printf("  Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("  Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
    } else {
        // [perf] printf("Not an IPv4 packet.\n");
        return;
    }

    // 2. �ˬd�O�_�O GRE �ʥ]
    if (ip_hdr->ip_p == IPPROTO_GRE) {
        // [perf] printf("GRE Packet\n");

        // 3. �ѪR GRE �Y�� (4 �r�`)
        unsigned char *gre_hdr = buffer + sizeof(struct ip); // ���L IPv4 �Y�� (20 �r�`)
        // [perf] printf("GRE Header\n");
        printf("  Flags: 0x%02x\n", gre_hdr[0]);
        printf("  Protocol: 0x%02x%02x\n", gre_hdr[1], gre_hdr[2]);

        // 4. �ѪR L2 ��ơ]���] L2 �O�@�� ARP �ʥ]�^
        unsigned char *l2_hdr = gre_hdr + 4;  // ���L GRE �Y�� (4 �r�`)
        // [perf] printf("L2 Layer Data\n");

        // 5. �ˬd�O�_�� ARP �ʥ] (�q�` ARP ��ĳ�� 0x0806)
        if (l2_hdr[12] == 0x08 && l2_hdr[13] == 0x06) {
            // [perf] printf("ARP Packet\n");

            // 6. �ѪR ARP �Y��
            struct arp_header *arp_hdr = (struct arp_header *)(l2_hdr + 14);  // ���L L2 header (14 �r�`)

            printf("  Hardware Type: 0x%04x\n", ntohs(arp_hdr->htype));
            printf("  Protocol Type: 0x%04x\n", ntohs(arp_hdr->ptype));
            printf("  Hardware Address Length: %d\n", arp_hdr->hlen);
            printf("  Protocol Address Length: %d\n", arp_hdr->plen);
            printf("  Operation: %d\n", ntohs(arp_hdr->oper));

            printf("  Sender MAC Address: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", arp_hdr->sha[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            printf("  Sender IP Address: ");
            for (int i = 0; i < 4; i++) {
                printf("%d", arp_hdr->spa[i]);
                if (i < 3) printf(".");
            }
            printf("\n");

            printf("  Target MAC Address: ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", arp_hdr->tha[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            printf("  Target IP Address: ");
            for (int i = 0; i < 4; i++) {
                printf("%d", arp_hdr->tpa[i]);
                if (i < 3) printf(".");
            }
            printf("\n");
        } else {
            // [perf] printf("Not an ARP packet.\n");
        }
    } else {
        // [perf] printf("Not a GRE packet.\n");
    }
}
//---------------------------------------------------------------------------------
// �o�e GTP-U �]
static void gtpv1uSend(instance_t instance, gtpv1u_tunnel_data_req_t *req, bool seqNumFlag, bool npduNumFlag) {

    uint8_t *buffer = req->buffer + req->offset;
    size_t length = req->length;
    ue_id_t ue_id = req->ue_id;
    int bearer_id = req->bearer_id;

    uint8_t src_mac[6];
    get_mac_address("ens18", src_mac);

    uint8_t dst_mac[6];
    memcpy(dst_mac, buffer + 30, 6); // ���]�ت� MAC �a�}�b�ʥ]��

    /*printf("SRC MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", src_mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");*/

    /*printf("DST MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", dst_mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");*/
    
    // [perf] printf("instance value: %ld\n", (long)instance);
    // [perf] printf("compatInst(instance) value: %ld\n", (long)compatInst(instance));
    
    pthread_mutex_lock(&globGtp.gtp_lock);
    getInstRetVoid(compatInst(instance));
    getUeRetVoid(inst, ue_id);

    auto ptr2 = ptrUe->second.bearers.find(bearer_id);

    if (ptr2 == ptrUe->second.bearers.end()) {
        LOG_E(GTPU,"[%ld] GTP-U instance: sending a packet to a non existant UE:RAB: %lx/%x\n", instance, ue_id, bearer_id);
        pthread_mutex_unlock(&globGtp.gtp_lock);
        return;
    }

    LOG_D(GTPU,"[%ld] sending a packet to UE:RAB:teid %lx/%x/%x, len %lu, oldseq %d, oldnum %d\n",
          instance, ue_id, bearer_id, ptr2->second.teid_outgoing, length, ptr2->second.seqNum, ptr2->second.npduNum );

    if (seqNumFlag)
        ptr2->second.seqNum++;

    if (npduNumFlag)
        ptr2->second.npduNum++;

    gtpv1u_bearer_t tmp = ptr2->second;
    pthread_mutex_unlock(&globGtp.gtp_lock);

    // ARP �ШD�B�z
    if (buffer[36] == 0x08 && buffer[37] == 0x06) { // ARP Request
        // [perf] printf("Received ARP Request, sending ARP Reply\n");

        unsigned char arp_packet[42];  // ARP Reply ���שT�w 42 �r�`
        memset(arp_packet, 0, sizeof(arp_packet));

        struct ether_header *eth_hdr = (struct ether_header *)arp_packet;
        struct arp_header *arp_hdr = (struct arp_header *)(arp_packet + sizeof(struct ether_header));

        // �H�Ӻ��Y��
        memcpy(eth_hdr->ether_dhost, dst_mac, ETH_ALEN);  // �ؼ� MAC
        memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);  // ���� MAC
        eth_hdr->ether_type = htons(ETH_P_ARP);          // ARP ��ĳ

        // ARP �Y��
        arp_hdr->htype = htons(1);            // �w�������G�H�Ӻ�
        arp_hdr->ptype = htons(ETH_P_IP);     // ��ĳ�����GIPv4
        arp_hdr->hlen = 6;                    // �w��a�}����
        arp_hdr->plen = 4;                    // ��ĳ�a�}����
        arp_hdr->oper = htons(2);             // �ާ@�X�GARP Reply (2)

        memcpy(arp_hdr->sha, src_mac, 6);     // �� MAC �a�}�]�����^
        memcpy(arp_hdr->spa, buffer + 62, 4); // �� IP�]���� IP�A�Y ARP �ؼ� IP�^
        memcpy(arp_hdr->tha, dst_mac, 6);     // �ؼ� MAC �a�}�]�ШD�誺 MAC�^
        memcpy(arp_hdr->tpa, buffer + 52, 4); // �ؼ� IP �a�}�]�ШD�誺 IP�^
        /*
        // === �[�W GRE header (4 bytes) ===
        unsigned char gre_packet[4 + 42];
        gre_packet[0] = buffer[20];
        gre_packet[1] = buffer[21];
        gre_packet[2] = buffer[22]; // Protocol type: ARP
        gre_packet[3] = buffer[23];
        memcpy(gre_packet + 4, arp_packet, 42);
        
         // === �[�W IPv4 header (20 bytes) ===
        unsigned char ip_packet[20 + sizeof(gre_packet)];
        memset(ip_packet, 0, sizeof(ip_packet));

        struct iphdr *ip_hdr = (struct iphdr *)ip_packet;
        ip_hdr->version = 4;
        ip_hdr->ihl = 5;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = htons(sizeof(ip_packet));
        ip_hdr->id = htons(1);
        ip_hdr->frag_off = 0;
        ip_hdr->ttl = 64;
        ip_hdr->protocol = IPPROTO_GRE;  // GRE
        ip_hdr->check = 0;      // ���M�s��A�p��
        memcpy(&ip_hdr->saddr, buffer + 62, 4); // src IP = �쥻�ʥ] dst
        memcpy(&ip_hdr->daddr, buffer + 52, 4); // dst IP = �쥻�ʥ] src
 
        // �p�� IP checksum
        unsigned int sum = 0;
        unsigned short *ptr = (unsigned short *)ip_hdr;
        for (int i = 0; i < 10; i++) {
         sum += ptr[i];  // ? ���n�� ntohs
         }
        while (sum >> 16) {
              sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ip_hdr->check = ~sum;

        // �[�W GRE + ARP payload
        memcpy(ip_packet + 20, gre_packet, sizeof(gre_packet));
        */
        // [perf] printf("Sending ARP Reply:\n");
    for (size_t i = 0; i < sizeof(arp_packet); i++) {
        if (i % 16 == 0 && i != 0) {
            printf("\n");
        }
        printf("%02x ", arp_packet[i]);
    }
    printf("\n");
         
        int rawsockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawsockfd == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = if_nametoindex("ens18");  // �ϥ� ens19 ����

        if (sendto(rawsockfd, arp_packet, sizeof(arp_packet), 0, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
            perror("sendto");
            close(rawsockfd);
            exit(EXIT_FAILURE);
        }

        close(rawsockfd);
    }
     if (length > 308 && buffer[306] == 0x35 && buffer[308] == 0x01) { //confirm DHCP discover
        printf("Received DHCP discover, sending DHCP offer\n");
        uint8_t* client_mac = &buffer[30];
        printf("Received from MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
       client_mac[0], client_mac[1], client_mac[2],
       client_mac[3], client_mac[4], client_mac[5]);
            Lease* lease = find_lease(client_mac);
            if (!lease || (time(NULL) - lease->lease_start > DHCP_LEASE_TIME)) {
                lease = assign_new_ip(client_mac);
            }

            if (!lease) {
                // [perf] printf("No IP available\n");
            }

            // �ǳ� Offer �ʥ]
            uint8_t offer[548];
            memset(offer, 0, sizeof(offer));

            offer[0] = 2; // BOOTREPLY
            offer[1] = 1; // Ethernet
            offer[2] = 6; // MAC ����
            memcpy(&offer[4], &buffer[70], 4); // xid
            memcpy(&offer[28], client_mac, 6); // MAC
            memcpy(&offer[16], lease->ip, 4); // yiaddr

            offer[236] = 0x63; offer[237] = 0x82;
            offer[238] = 0x53; offer[239] = 0x63;

            int idx = 240;
            offer[idx++] = 53; offer[idx++] = 1; offer[idx++] = 2; // DHCP Offer
            offer[idx++] = 1;  offer[idx++] = 4; offer[idx++] = 255; offer[idx++] = 255; offer[idx++] = 255; offer[idx++] = 0;
            offer[idx++] = 3;  offer[idx++] = 4; offer[idx++] = 192; offer[idx++] = 168; offer[idx++] = 1; offer[idx++] = 1;
            offer[idx++] = 51; offer[idx++] = 4; offer[idx++] = 0x00; offer[idx++] = 0x01; offer[idx++] = 0x51; offer[idx++] = 0x80;
            offer[idx++] = 54; offer[idx++] = 4; offer[idx++] = 192; offer[idx++] = 168; offer[idx++] = 1; offer[idx++] = 1;
            offer[idx++] = 255;

            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_port = htons(68);
            dst.sin_addr.s_addr = INADDR_BROADCAST;
            //memcpy(&dst.sin_addr.s_addr, lease->ip, 4);
            
            // �}�� UDP socket
            int udpsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (udpsockfd == -1) {
                perror("socket");
               }
               
            int broadcast = 1;
            if (setsockopt(udpsockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1) {
             perror("setsockopt SO_BROADCAST");
                  close(udpsockfd);
                  return;
               }
            
            // Bind the socket to the specific interface (ens19)
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "ens18", IFNAMSIZ-1); // Set interface name
            if (ioctl(udpsockfd, SIOCGIFADDR, &ifr) == -1) {
                  perror("ioctl SIOCGIFADDR");
                  close(udpsockfd);
                  return;
                }

            struct sockaddr_in local_address;
            memcpy(&local_address, &ifr.ifr_addr, sizeof(struct sockaddr_in));
            local_address.sin_port = htons(68); // DHCP client port
            if (bind(udpsockfd, (struct sockaddr*)&local_address, sizeof(local_address)) == -1) {
                 perror("bind");
                 close(udpsockfd);
                 return;
                }

            // �o�e DHCP Offer
            if (sendto(udpsockfd, offer, sizeof(offer), 0, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
                perror("sendto");
               } else {
                printf("Sent DHCP Offer to %d.%d.%d.%d\n",
               lease->ip[0], lease->ip[1], lease->ip[2], lease->ip[3]);
               }

           // ���� socket
           close(udpsockfd);
       }
       if (length > 308 && buffer[306] == 0x35 && buffer[308] == 0x03) { // DHCP Request
    // [perf] printf("Received DHCP request, sending DHCP ACK\n");
    
    uint8_t* client_mac = &buffer[30]; // chaddr ����m
    printf("Received request from MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        client_mac[0], client_mac[1], client_mac[2],
        client_mac[3], client_mac[4], client_mac[5]);

    Lease* lease = find_lease(client_mac);
    if (!lease) {
        printf("No lease found for client\n");
        return;
    }

    // �ǳ� ACK �ʥ]
    uint8_t ack[548];
    memset(ack, 0, sizeof(ack));

    ack[0] = 2; // BOOTREPLY
    ack[1] = 1; // Ethernet
    ack[2] = 6; // MAC ����
    memcpy(&ack[4], &buffer[70], 4); // xid
    memcpy(&ack[28], client_mac, 6); // chaddr
    memcpy(&ack[16], lease->ip, 4); // yiaddr

    ack[236] = 0x63; ack[237] = 0x82;
    ack[238] = 0x53; ack[239] = 0x63;

    int idx = 240;
    ack[idx++] = 53; ack[idx++] = 1; ack[idx++] = 5; // DHCP ACK
    ack[idx++] = 1;  ack[idx++] = 4; ack[idx++] = 255; ack[idx++] = 255; ack[idx++] = 255; ack[idx++] = 0; // Subnet mask
    ack[idx++] = 3;  ack[idx++] = 4; ack[idx++] = 192; ack[idx++] = 168; ack[idx++] = 1; ack[idx++] = 1;   // Gateway
    ack[idx++] = 51; ack[idx++] = 4; ack[idx++] = 0x00; ack[idx++] = 0x01; ack[idx++] = 0x51; ack[idx++] = 0x80; // Lease time
    ack[idx++] = 54; ack[idx++] = 4; ack[idx++] = 192; ack[idx++] = 168; ack[idx++] = 1; ack[idx++] = 1;   // DHCP server
    ack[idx++] = 255;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(68);
    dst.sin_addr.s_addr = INADDR_BROADCAST;

    int udp2sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp2sockfd == -1) {
        perror("socket");
        return;
    }

    int broadcast = 1;
    if (setsockopt(udp2sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1) {
        perror("setsockopt SO_BROADCAST");
        close(udp2sockfd);
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "ens18", IFNAMSIZ-1);
    if (ioctl(udp2sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFADDR");
        close(udp2sockfd);
        return;
    }

    struct sockaddr_in local_address;
    memcpy(&local_address, &ifr.ifr_addr, sizeof(struct sockaddr_in));
    local_address.sin_port = htons(68);
    if (bind(udp2sockfd, (struct sockaddr*)&local_address, sizeof(local_address)) == -1) {
        perror("bind");
        close(udp2sockfd);
        return;
    }

    if (sendto(udp2sockfd, ack, sizeof(ack), 0, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
        perror("sendto");
    } else {
        /* [perf] printf("Sent DHCP ACK to %d.%d.%d.%d\n",
            lease->ip[0], lease->ip[1], lease->ip[2], lease->ip[3]); */
    }

    close(udp2sockfd);
}
// [perf] printf("compatInst(instance) = %ld\n", (long)compatInst(instance));
printf("tmp.outgoing_ip_addr = 0x%08X\n", tmp.outgoing_ip_addr);
printf("tmp.outgoing_port = %u\n", tmp.outgoing_port);
printf("GTP_GPDU = %u\n", GTP_GPDU);
printf("tmp.teid_outgoing = 0x%08X\n", tmp.teid_outgoing);
printf("seqNumFlag = %d\n", seqNumFlag);
printf("npduNumFlag = %d\n", npduNumFlag);
printf("tmp.seqNum = %u\n", tmp.seqNum);
printf("tmp.npduNum = %u\n", tmp.npduNum);
    // ��l�� GTP-U �޿�
    if (tmp.outgoing_qfi != -1) {
        Gtpv1uExtHeaderT ext = { 0 };
        ext.ExtHeaderLen = 1; // in quad bytes
        ext.pdusession_cntr.spare = 0;
        ext.pdusession_cntr.PDU_type = UL_PDU_SESSION_INFORMATION;
        ext.pdusession_cntr.QFI = tmp.outgoing_qfi;
        ext.pdusession_cntr.Reflective_QoS_activation = false;
        ext.pdusession_cntr.Paging_Policy_Indicator = false;
        ext.NextExtHeaderType = NO_MORE_EXT_HDRS;

        gtpv1uCreateAndSendMsg(compatInst(instance),
                               tmp.outgoing_ip_addr,
                               tmp.outgoing_port,
                               GTP_GPDU,
                               tmp.teid_outgoing,
                               buffer,
                               length,
                               seqNumFlag,
                               npduNumFlag,
                               tmp.seqNum,
                               tmp.npduNum,
                               PDU_SESSION_CONTAINER,
                               (uint8_t *)&ext,
                               sizeof(ext));
    } else {
        gtpv1uCreateAndSendMsg(
            compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port, GTP_GPDU, tmp.teid_outgoing, buffer, length, seqNumFlag, npduNumFlag, tmp.seqNum, tmp.npduNum, NO_MORE_EXT_HDRS, NULL, 0);
    }
}
//---------------------------------------------------------------------------------
static void fillDlDeliveryStatusReport(extensionHeader_t *extensionHeader, uint32_t RLC_buffer_availability, uint32_t NR_PDCP_PDU_SN){

  extensionHeader->buffer[0] = (1+sizeof(DlDataDeliveryStatus_flagsT)+(NR_PDCP_PDU_SN>0?3:0)+(NR_PDCP_PDU_SN>0?1:0)+1)/4;
  DlDataDeliveryStatus_flagsT DlDataDeliveryStatus;
  DlDataDeliveryStatus.deliveredPdcpSn = 0;
  DlDataDeliveryStatus.transmittedPdcpSn= NR_PDCP_PDU_SN>0?1:0;
  DlDataDeliveryStatus.pduType = 1;
  DlDataDeliveryStatus.drbBufferSize = htonl(RLC_buffer_availability);
  memcpy(extensionHeader->buffer+1, &DlDataDeliveryStatus, sizeof(DlDataDeliveryStatus_flagsT));
  uint8_t offset = sizeof(DlDataDeliveryStatus_flagsT)+1;

  if(NR_PDCP_PDU_SN>0){
    extensionHeader->buffer[offset] =   (NR_PDCP_PDU_SN >> 16) & 0xff;
    extensionHeader->buffer[offset+1] = (NR_PDCP_PDU_SN >> 8) & 0xff;
    extensionHeader->buffer[offset+2] = NR_PDCP_PDU_SN & 0xff;
    LOG_D(GTPU, "Octets reporting NR_PDCP_PDU_SN, extensionHeader->buffer[offset]: %u, extensionHeader->buffer[offset+1]:%u, extensionHeader->buffer[offset+2]:%u \n", extensionHeader->buffer[offset], extensionHeader->buffer[offset+1],extensionHeader->buffer[offset+2]);
    extensionHeader->buffer[offset+3] = 0x00; //Padding octet
    offset = offset+3;
  }
  extensionHeader->buffer[offset] = 0x00; //No more extension headers
  /*Total size of DDD_status PDU = size of mandatory part +
   * 3 octets for highest transmitted/delivered PDCP SN +
   * 1 octet for padding + 1 octet for next extension header type,
   * according to TS 38.425: Fig. 5.5.2.2-1 and section 5.5.3.24*/
  extensionHeader->length  = 1+sizeof(DlDataDeliveryStatus_flagsT)+
                              (NR_PDCP_PDU_SN>0?3:0)+
                              (NR_PDCP_PDU_SN>0?1:0)+1;
}

static void gtpv1uSendDlDeliveryStatus(instance_t instance, gtpv1u_DU_buffer_report_req_t *req){
  ue_id_t ue_id=req->ue_id;
  int  bearer_id=req->pdusession_id;
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetVoid(compatInst(instance));
  getUeRetVoid(inst, ue_id);

  auto ptr2=ptrUe->second.bearers.find(bearer_id);

  if ( ptr2 == ptrUe->second.bearers.end() ) {
    LOG_D(GTPU,"GTP-U instance: %ld sending a packet to a non existant UE ID:RAB: %lu/%x\n", instance, ue_id, bearer_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return;
  }

  extensionHeader_t *extensionHeader;
  extensionHeader = (extensionHeader_t *) calloc(1, sizeof(extensionHeader_t));
  fillDlDeliveryStatusReport(extensionHeader, req->buffer_availability,0);

  LOG_I(GTPU,"[%ld] GTP-U sending DL Data Delivery status to UE ID:RAB:teid %lu/%x/%x, oldseq %d, oldnum %d\n",
        instance, ue_id, bearer_id,ptr2->second.teid_outgoing, ptr2->second.seqNum,ptr2->second.npduNum );
  // copy to release the mutex
  gtpv1u_bearer_t tmp=ptr2->second;
  pthread_mutex_unlock(&globGtp.gtp_lock);
  gtpv1uCreateAndSendMsg(
      compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port, GTP_GPDU, tmp.teid_outgoing, NULL, 0, false, false, 0, 0, NR_RAN_CONTAINER, extensionHeader->buffer, extensionHeader->length);
}

static void gtpv1uEndTunnel(instance_t instance, gtpv1u_enb_end_marker_req_t *req) {
  ue_id_t ue_id = req->rnti;
  int  bearer_id = (int)req->rab_id;
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetVoid(compatInst(instance));
  getUeRetVoid(inst, ue_id);

  auto ptr2=ptrUe->second.bearers.find(bearer_id);

  if ( ptr2 == ptrUe->second.bearers.end() ) {
    LOG_E(GTPU,"[%ld] GTP-U sending a packet to a non existant UE:RAB: %lx/%x\n", instance, ue_id, bearer_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return;
  }

  LOG_D(GTPU,"[%ld] sending a end packet packet to UE:RAB:teid %lx/%x/%x\n",
        instance, ue_id, bearer_id,ptr2->second.teid_outgoing);
  gtpv1u_bearer_t tmp=ptr2->second;
  pthread_mutex_unlock(&globGtp.gtp_lock);
  Gtpv1uMsgHeaderT  msgHdr;
  // N should be 0 for us (it was used only in 2G and 3G)
  msgHdr.PN=0;
  msgHdr.S=0;
  msgHdr.E=0;
  msgHdr.spare=0;
  //PT=0 is for GTP' TS 32.295 (charging)
  msgHdr.PT=1;
  msgHdr.version=1;
  msgHdr.msgType=GTP_END_MARKER;
  msgHdr.msgLength=htons(0);
  msgHdr.teid=htonl(tmp.teid_outgoing);
  // Fix me: add IPv6 support, using flag ipVersion
  static struct sockaddr_in to= {0};
  to.sin_family      = AF_INET;
  to.sin_port        = htons(tmp.outgoing_port);
  to.sin_addr.s_addr = tmp.outgoing_ip_addr;
  char ip4[INET_ADDRSTRLEN];
  //char ip6[INET6_ADDRSTRLEN];
  LOG_D(GTPU,"[%ld] sending end packet to %s\n", instance, inet_ntoa(to.sin_addr) );

  if (sendto(compatInst(instance), (void *)&msgHdr, sizeof(msgHdr), 0,(struct sockaddr *)&to, sizeof(to) ) !=  sizeof(msgHdr)) {
    LOG_E(GTPU,
          "[%ld] Failed to send data to %s on port %d, buffer size %lu\n",
          compatInst(instance), inet_ntop(AF_INET, &tmp.outgoing_ip_addr, ip4, INET_ADDRSTRLEN), tmp.outgoing_port, sizeof(msgHdr));
  }
}

static  int udpServerSocket(openAddr_s addr) {
  LOG_I(GTPU, "Initializing UDP for local address %s with port %s\n", addr.originHost, addr.originService);
  int status;
  struct addrinfo hints= {0}, *servinfo, *p;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if ((status = getaddrinfo(addr.originHost, addr.originService, &hints, &servinfo)) != 0) {
    LOG_E(GTPU,"getaddrinfo error: %s\n", gai_strerror(status));
    return -1;
  }

  int sockfd=-1;

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      LOG_W(GTPU,"socket: %s\n", strerror(errno));
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      LOG_W(GTPU,"bind: %s\n", strerror(errno));
      continue;
    } else {
      // We create the gtp instance on the socket
      globGtp.instances[sockfd].addr=addr;

      if (p->ai_family == AF_INET) {
        struct sockaddr_in *ipv4=(struct sockaddr_in *)p->ai_addr;
        memcpy(globGtp.instances[sockfd].foundAddr,
               &ipv4->sin_addr.s_addr, sizeof(ipv4->sin_addr.s_addr));
        globGtp.instances[sockfd].foundAddrLen=sizeof(ipv4->sin_addr.s_addr);
        globGtp.instances[sockfd].ipVersion=4;
        break;
      } else if (p->ai_family == AF_INET6) {
        LOG_W(GTPU,"Local address is IP v6\n");
        struct sockaddr_in6 *ipv6=(struct sockaddr_in6 *)p->ai_addr;
        memcpy(globGtp.instances[sockfd].foundAddr,
               &ipv6->sin6_addr.s6_addr, sizeof(ipv6->sin6_addr.s6_addr));
        globGtp.instances[sockfd].foundAddrLen=sizeof(ipv6->sin6_addr.s6_addr);
        globGtp.instances[sockfd].ipVersion=6;
      } else
        AssertFatal(false,"Local address is not IPv4 or IPv6");
    }

    break; // if we get here, we must have connected successfully
  }

  if (p == NULL) {
    // looped off the end of the list with no successful bind
    LOG_E(GTPU,"failed to bind socket: %s %s \n", addr.originHost, addr.originService);
    return -1;
  }

  freeaddrinfo(servinfo); // all done with this structure

  int sendbuff = 1000*1000*10;
  AssertFatal(0==setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff)),"");
  LOG_D(GTPU,"[%d] Created listener for paquets to: %s:%s, send buffer size: %d\n", sockfd, addr.originHost, addr.originService,sendbuff);
  return sockfd;
}

instance_t gtpv1Init(openAddr_t context) {
  // [perf] printf("-------gtp init----------\n");
  pthread_mutex_lock(&globGtp.gtp_lock);
  int id=udpServerSocket(context);

  if (id>=0) {
    itti_subscribe_event_fd(TASK_GTPV1_U, id);
  } else
    LOG_E(GTPU,"can't create GTP-U instance\n");

  /* Start CU REST (port 8888) and LBO REST (port 8887) once. LBO defaults
   * OFF and only enables UE-to-UE CU-UP local breakout after xApp control. */
  static int lbo_rest_started = 0;
  if (!lbo_rest_started) {
    lbo_rest_started = 1;
    ensure_cpe_gtpu_table();
    ue_gtp_ctx_load_from_db();   /* populate in-memory cache from DB on startup */
    pthread_t cu_tid;
    pthread_create(&cu_tid, NULL, cu_rest_thread, NULL);
    pthread_detach(cu_tid);
    pthread_t lbo_tid;
    pthread_create(&lbo_tid, NULL, lbo_rest_thread, NULL);
    pthread_detach(lbo_tid);
    system("ip rule del iif ens18 to 192.168.1.0/24 lookup 200 priority 90 2>/dev/null || true");
    system("ip route flush table 200 2>/dev/null || true");
  }

  pthread_mutex_unlock(&globGtp.gtp_lock);
  LOG_I(GTPU, "Created gtpu instance id: %d\n", id);
  return id;
}

// 找出 IP 的 index；如果不存在就加入；若已滿回傳 -1
int find_or_add_ip(const char* ip) {
  for (int i = 0; i < MAX_IPS; ++i) {
    if (ip_list[i] && strcmp(ip_list[i], ip) == 0) {
      return i;  // 已存在
    }
  }
  // 未找到，新增
  for (int i = 0; i < MAX_IPS; ++i) {
    if (ip_list[i] == NULL) {
      ip_list[i] = strdup(ip);  // 儲存字串副本
      return i;
    }
  }
  return -1;  // 滿了
}

void init_ip_active_defaults() {
  const char* default_ips[] = {
    "192.168.1.101",
    "192.168.1.151"
  };

  for (size_t i = 0; i < sizeof(default_ips)/sizeof(default_ips[0]); ++i) {
    int idx = find_or_add_ip(default_ips[i]);
    if (idx >= 0) {
      IP_active[idx] = 1;
      // [perf] printf("Default active IP set: %s (idx=%d)\n", default_ips[i], idx);
    } else {
      fprintf(stderr, "Failed to add default IP: %s (list full?)\n", default_ips[i]);
    }
  }
}

/*void update_ue_outgoing_teid_ip(uint64_t ue_id, uint32_t outgoing_teid, const char* remote_ipv4) {
  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
    fprintf(stderr, "mysql_init() failed\n");
    return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
    fprintf(stderr, "mysql_real_connect() failed\n");
    mysql_close(conn);
    return;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "UPDATE ue_context SET outgoing_teid = %u, remote_ipv4 = '%s' WHERE ue_id = %lu",
           outgoing_teid, remote_ipv4, ue_id);

  if (mysql_query(conn, query)) {
    fprintf(stderr, "UPDATE failed: %s\n", mysql_error(conn));
  }else {
    // 更新成功，設定 IP_active 為 0
    IP_active = 0;
  }

  mysql_close(conn);
}*/

static bool is_cpe_ue_gtp_ue_id(uint64_t ue_id)
{
  if (ue_id == 0)
    return false;

  cpe_ue_table_t *tbl = cpe_ue_table_get();
  if (!tbl)
    return false;

  bool found = false;
  cpe_ue_lock(tbl);
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid && e->gtp_ue_id != 0 && e->gtp_ue_id == (uint32_t)ue_id) {
      found = true;
      break;
    }
  }
  cpe_ue_unlock(tbl);
  return found;
}

void update_ue_outgoing_teid_ip(uint64_t ue_id, uint32_t outgoing_teid, const char* remote_ipv4) {
  if (is_cpe_ue_gtp_ue_id(ue_id)) {
    LOG_D(GTPU, "[UE_CTX] skip CPE_UE ue_id=%lu outgoing_teid=0x%x remote=%s\n",
          ue_id, outgoing_teid, remote_ipv4);
    return;
  }

  if (ue_id >= CPE_UE_MAX_ENTRIES) {
    LOG_D(GTPU, "[UE_CTX] skip non-CU UE id %lu outgoing_teid=0x%x remote=%s\n",
          ue_id, outgoing_teid, remote_ipv4);
    return;
  }

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
    fprintf(stderr, "mysql_init() failed\n");
    return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
    fprintf(stderr, "mysql_real_connect() failed\n");
    mysql_close(conn);
    return;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "INSERT INTO ue_context (ue_id,outgoing_teid,remote_ipv4,ready,role) "
           "VALUES (%lu,%u,'%s',1,'NORMAL_UE') "
           "ON DUPLICATE KEY UPDATE "
           "outgoing_teid=VALUES(outgoing_teid),"
           "remote_ipv4=VALUES(remote_ipv4),ready=1,"
           "role=IF(role='',VALUES(role),role)",
           ue_id, outgoing_teid, remote_ipv4);

  if (mysql_query(conn, query))
    fprintf(stderr, "UPSERT ue_context outgoing failed: %s\n", mysql_error(conn));
  else
    LOG_I(GTPU, "[UE_CTX] ue_id=%lu outgoing_teid=0x%x remote=%s ready=1\n",
          ue_id, outgoing_teid, remote_ipv4);
  mysql_close(conn);

  /* Mirror to in-memory cache — data path reads this, not MySQL. */
  ue_gtp_ctx_t *c = &s_ue_gtp_ctx[ue_id];
  c->outgoing_teid = outgoing_teid;
  strncpy(c->remote_ipv4, remote_ipv4, INET_ADDRSTRLEN - 1);
  c->ready = true;
}

void update_ue_pdu_address(uint64_t ue_id, const char *pdu_address) {
  if (is_cpe_ue_gtp_ue_id(ue_id)) {
    LOG_D(GTPU, "[UE_CTX] skip CPE_UE ue_id=%lu pdu_address=%s\n",
          ue_id, pdu_address ? pdu_address : "");
    return;
  }

  if (ue_id >= CPE_UE_MAX_ENTRIES || !pdu_address || !pdu_address[0])
    return;

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
    fprintf(stderr, "mysql_init() failed\n");
    return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
    fprintf(stderr, "mysql_real_connect() failed\n");
    mysql_close(conn);
    return;
  }

  char escaped[INET_ADDRSTRLEN * 2 + 1] = {0};
  mysql_real_escape_string(conn, escaped, pdu_address, strlen(pdu_address));

  char query[512];
  snprintf(query, sizeof(query),
           "INSERT INTO ue_context (ue_id,pdu_address,role) "
           "VALUES (%lu,'%s','NORMAL_UE') "
           "ON DUPLICATE KEY UPDATE "
           "pdu_address=IF(pdu_address='',VALUES(pdu_address),pdu_address)",
           ue_id, escaped);

  if (mysql_query(conn, query))
    fprintf(stderr, "UPSERT ue_context pdu_address failed: %s\n", mysql_error(conn));
  else if (mysql_affected_rows(conn) > 0)
    LOG_I(GTPU, "[UE_CTX] ue_id=%lu pdu_address=%s\n", ue_id, pdu_address);

  mysql_close(conn);

  ue_gtp_ctx_t *c = &s_ue_gtp_ctx[ue_id];
  if (c->pdu_address[0] == '\0') {
    strncpy(c->pdu_address, pdu_address, INET_ADDRSTRLEN - 1);
    c->pdu_address[INET_ADDRSTRLEN - 1] = '\0';
  }
}

void GtpuUpdateTunnelOutgoingAddressAndTeid(instance_t instance, ue_id_t ue_id, ebi_t bearer_id, in_addr_t newOutgoingAddr, teid_t newOutgoingTeid) {
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetVoid(compatInst(instance));
  getUeRetVoid(inst, ue_id);

  auto ptr2=ptrUe->second.bearers.find(bearer_id);

  if ( ptr2 == ptrUe->second.bearers.end() ) {
    LOG_E(GTPU,"[%ld] Update tunnel for a existing ue id %lu, but wrong bearer_id %u\n", instance, ue_id, bearer_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return;
  }

  ptr2->second.outgoing_ip_addr = newOutgoingAddr;
  ptr2->second.teid_outgoing = newOutgoingTeid;
  LOG_I(GTPU, "[%ld] Tunnel Outgoing TEID updated to %x and address to %x\n", instance, ptr2->second.teid_outgoing, ptr2->second.outgoing_ip_addr);
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &newOutgoingAddr, ip_str, INET_ADDRSTRLEN);

  LOG_I(GTPU, "[%ld] Tunnel Outgoing TEID updated to %x and address to %s\n",
        instance, newOutgoingTeid, ip_str);
  update_ue_outgoing_teid_ip(ue_id, newOutgoingTeid, ip_str);
  pthread_mutex_unlock(&globGtp.gtp_lock);

  /* Update the CPE_UE in-memory entry so DL forwarding can bypass MySQL.
   * gtp_lock is released above; cpe_ue_lock is safe to acquire here. */
  if (newOutgoingTeid != 0) {
    cpe_ue_table_t *ctbl = cpe_ue_table_get();
    if (ctbl) {
      cpe_ue_lock(ctbl);
      for (int _i = 0; _i < CPE_UE_MAX_ENTRIES; _i++) {
        cpe_ue_entry_t *_e = &ctbl->entries[_i];
        if (_e->valid && _e->gtp_ue_id != 0 && _e->gtp_ue_id == (uint32_t)ue_id) {
          _e->gtp_instance      = (int)instance;
          _e->gtp_outgoing_teid = newOutgoingTeid;
          strncpy(_e->gtp_remote_ipv4, ip_str, INET_ADDRSTRLEN - 1);
          _e->gtp_remote_ipv4[INET_ADDRSTRLEN - 1] = '\0';
          _e->gtp_ready = true;
          LOG_I(GTPU, "[CPE_UE] GTP-U F1 params stored: ue_id=%lu inst=%ld teid=0x%x remote=%s\n",
                (unsigned long)ue_id, instance, newOutgoingTeid, ip_str);
          cpe_ue_table_persist_locked(ctbl);
          break;
        }
      }
      cpe_ue_unlock(ctbl);
    }
  }
  return;
}
void update_ue_instance_teid(uint64_t ue_id, long instance, uint32_t incoming_teid) {
  if (is_cpe_ue_gtp_ue_id(ue_id)) {
    LOG_D(GTPU, "[UE_CTX] skip CPE_UE ue_id=%lu incoming_teid=0x%x instance=%ld\n",
          ue_id, incoming_teid, instance);
    return;
  }

  if (ue_id >= CPE_UE_MAX_ENTRIES) {
    LOG_D(GTPU, "[UE_CTX] skip non-CU UE id %lu incoming_teid=0x%x instance=%ld\n",
          ue_id, incoming_teid, instance);
    return;
  }

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
    fprintf(stderr, "mysql_init() failed\n");
    return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
    fprintf(stderr, "mysql_real_connect() failed\n");
    mysql_close(conn);
    return;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "INSERT INTO ue_context (ue_id,instance,incoming_teid,role) "
           "VALUES (%lu,%ld,%u,'NORMAL_UE') "
           "ON DUPLICATE KEY UPDATE "
           "instance=VALUES(instance),incoming_teid=VALUES(incoming_teid),"
           "role=IF(role='',VALUES(role),role)",
           ue_id, instance, incoming_teid);

  if (mysql_query(conn, query))
    fprintf(stderr, "UPDATE ue_context incoming failed: %s\n", mysql_error(conn));
  else if (mysql_affected_rows(conn) > 0)
    LOG_I(GTPU, "[UE_CTX] ue_id=%lu incoming_teid=0x%x instance=%ld\n",
           ue_id, incoming_teid, instance);

  mysql_close(conn);

  /* Mirror to in-memory cache. */
  s_ue_gtp_ctx[ue_id].instance      = (int)instance;
  s_ue_gtp_ctx[ue_id].incoming_teid = incoming_teid;
}
teid_t newGtpuCreateTunnel(instance_t instance,
                           ue_id_t ue_id,
                           int incoming_bearer_id,
                           int outgoing_bearer_id,
                           teid_t outgoing_teid,
                           int outgoing_qfi,
                           transport_layer_addr_t remoteAddr,
                           int port,
                           gtpCallback callBack,
                           gtpCallbackSDAP callBackSDAP) {
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));
  auto it=inst->ue2te_mapping.find(ue_id);

  if ( it != inst->ue2te_mapping.end() &&  it->second.bearers.find(outgoing_bearer_id) != it->second.bearers.end()) {
    LOG_W(GTPU,"[%ld] Create a config for a already existing GTP tunnel (ue id %lu)\n", instance, ue_id);
    inst->ue2te_mapping.erase(it);
  }

  teid_t incoming_teid=gtpv1uNewTeid();

  while (globGtp.te2ue_mapping.find(incoming_teid) != globGtp.te2ue_mapping.end()) {
    LOG_W(GTPU, "[%ld] generated a random Teid that exists, re-generating (%x)\n", instance, incoming_teid);
    incoming_teid=gtpv1uNewTeid();
  };

  globGtp.te2ue_mapping[incoming_teid].ue_id = ue_id;
  globGtp.te2ue_mapping[incoming_teid].incoming_rb_id = incoming_bearer_id;
  globGtp.te2ue_mapping[incoming_teid].outgoing_teid = outgoing_teid;
  globGtp.te2ue_mapping[incoming_teid].callBack = callBack;
  globGtp.te2ue_mapping[incoming_teid].callBackSDAP = callBackSDAP;
  globGtp.te2ue_mapping[incoming_teid].pdusession_id = (uint8_t)outgoing_bearer_id;

  gtpv1u_bearer_t *tmp=&inst->ue2te_mapping[ue_id].bearers[outgoing_bearer_id];

  int addrs_length_in_bytes = remoteAddr.length / 8;

  switch (addrs_length_in_bytes) {
    case 4:
      memcpy(&tmp->outgoing_ip_addr,remoteAddr.buffer,4);
      break;

    case 16:
      memcpy(tmp->outgoing_ip6_addr.s6_addr,remoteAddr.buffer,
             16);
      break;

    case 20:
      memcpy(&tmp->outgoing_ip_addr,remoteAddr.buffer,4);
      memcpy(tmp->outgoing_ip6_addr.s6_addr,
             remoteAddr.buffer+4,
             16);

    default:
      AssertFatal(false, "SGW Address size impossible");
  }

  tmp->teid_incoming = incoming_teid;
  tmp->outgoing_port=port;
  tmp->teid_outgoing= outgoing_teid;
  tmp->outgoing_qfi=outgoing_qfi;
  pthread_mutex_unlock(&globGtp.gtp_lock);
  char ip4[INET_ADDRSTRLEN];
  char ip6[INET6_ADDRSTRLEN];
  // [perf] printf("Outgoing TEID: 0x%x (%u)\n", outgoing_teid, outgoing_teid);
  LOG_I(GTPU,
        "[%ld] Created tunnel for UE ID %lu, teid for incoming: %x, teid for outgoing %x to remote IPv4: %s, IPv6 %s\n",
        instance,
        ue_id,
        tmp->teid_incoming,
        tmp->teid_outgoing,
        inet_ntop(AF_INET, (void *)&tmp->outgoing_ip_addr, ip4, INET_ADDRSTRLEN),
        inet_ntop(AF_INET6, (void *)&tmp->outgoing_ip6_addr.s6_addr, ip6, INET6_ADDRSTRLEN));
  return incoming_teid;
}

void gtpv1uSendDirect(instance_t instance,
                      ue_id_t ue_id,
                      int bearer_id,
                      uint8_t *buf,
                      size_t len,
                      bool seqNumFlag,
                      bool npduNumFlag)
{
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetVoid(compatInst(instance));
  getUeRetVoid(inst, ue_id);

  auto ptr2 = ptrUe->second.bearers.find(bearer_id);
  if (ptr2 == ptrUe->second.bearers.end()) {
    LOG_E(GTPU, "[%ld] GTP-U instance: sending a packet to a non existant UE:RAB: %lx/%x\n", instance, ue_id, bearer_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return;
  }

  if (seqNumFlag) ptr2->second.seqNum++;
  if (npduNumFlag) ptr2->second.npduNum++;

  gtpv1u_bearer_t tmp = ptr2->second;
  pthread_mutex_unlock(&globGtp.gtp_lock);

  if (tmp.outgoing_qfi != -1) {
    Gtpv1uExtHeaderT ext = {0};
    ext.ExtHeaderLen = 1;
    ext.pdusession_cntr.PDU_type = UL_PDU_SESSION_INFORMATION;
    ext.pdusession_cntr.QFI = tmp.outgoing_qfi;
    ext.NextExtHeaderType = NO_MORE_EXT_HDRS;
    gtpv1uCreateAndSendMsg(compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port,
                           GTP_GPDU, tmp.teid_outgoing, buf, len,
                           seqNumFlag, npduNumFlag, tmp.seqNum, tmp.npduNum,
                           PDU_SESSION_CONTAINER, (uint8_t *)&ext, sizeof(ext));
  } else {
    gtpv1uCreateAndSendMsg(compatInst(instance), tmp.outgoing_ip_addr, tmp.outgoing_port,
                           GTP_GPDU, tmp.teid_outgoing, buf, len,
                           seqNumFlag, npduNumFlag, tmp.seqNum, tmp.npduNum,
                           NO_MORE_EXT_HDRS, NULL, 0);
  }
}

int gtpv1u_create_s1u_tunnel(instance_t instance,
                             const gtpv1u_enb_create_tunnel_req_t  *create_tunnel_req,
                             gtpv1u_enb_create_tunnel_resp_t *create_tunnel_resp,
                             gtpCallback callBack)
{
  LOG_D(GTPU, "[%ld] Start create tunnels for UE ID %u, num_tunnels %d, sgw_S1u_teid %x\n",
        instance,
        create_tunnel_req->rnti,
        create_tunnel_req->num_tunnels,
        create_tunnel_req->sgw_S1u_teid[0]);
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));
  
  tcp_udp_port_t dstport=inst->get_dstport();
  uint8_t addr[inst->foundAddrLen];
  memcpy(addr, inst->foundAddr, inst->foundAddrLen);
  pthread_mutex_unlock(&globGtp.gtp_lock);
  
  for (int i = 0; i < create_tunnel_req->num_tunnels; i++) {
    AssertFatal(create_tunnel_req->eps_bearer_id[i] > 4,
                "From legacy code not clear, seems impossible (bearer=%d)\n",
                create_tunnel_req->eps_bearer_id[i]);
    int incoming_rb_id=create_tunnel_req->eps_bearer_id[i]-4;
    teid_t teid = newGtpuCreateTunnel(compatInst(instance),
                                      create_tunnel_req->rnti,
                                      incoming_rb_id,
                                      create_tunnel_req->eps_bearer_id[i],
                                      create_tunnel_req->sgw_S1u_teid[i],
                                      -1, // no pdu session in 4G
                                      create_tunnel_req->sgw_addr[i],
                                      dstport,
                                      callBack,
                                      NULL);
    create_tunnel_resp->status=0;
    create_tunnel_resp->rnti=create_tunnel_req->rnti;
    create_tunnel_resp->num_tunnels=create_tunnel_req->num_tunnels;
    create_tunnel_resp->enb_S1u_teid[i]=teid;
    create_tunnel_resp->eps_bearer_id[i] = create_tunnel_req->eps_bearer_id[i];
    memcpy(create_tunnel_resp->enb_addr.buffer,addr,sizeof(addr));
    create_tunnel_resp->enb_addr.length= sizeof(addr);
  }

  return !GTPNOK;
}

int gtpv1u_update_s1u_tunnel(
  const instance_t                              instance,
  const gtpv1u_enb_create_tunnel_req_t *const   create_tunnel_req,
  const rnti_t                                  prior_rnti
) {
  LOG_D(GTPU, "[%ld] Start update tunnels for old RNTI %x, new RNTI %x, num_tunnels %d, sgw_S1u_teid %x, eps_bearer_id %x\n",
        instance,
        prior_rnti,
        create_tunnel_req->rnti,
        create_tunnel_req->num_tunnels,
        create_tunnel_req->sgw_S1u_teid[0],
        create_tunnel_req->eps_bearer_id[0]);
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));

  if ( inst->ue2te_mapping.find(create_tunnel_req->rnti) == inst->ue2te_mapping.end() ) {
    LOG_E(GTPU,"[%ld] Update not already existing tunnel (new rnti %x, old rnti %x)\n", 
          instance, create_tunnel_req->rnti, prior_rnti);
  }

  auto it=inst->ue2te_mapping.find(prior_rnti);

  if ( it != inst->ue2te_mapping.end() ) {
    pthread_mutex_unlock(&globGtp.gtp_lock);
    AssertFatal(false, "logic bug: update of non-existing tunnel (new ue id %u, old ue id %u)\n", create_tunnel_req->rnti, prior_rnti);
    /* we don't know if we need 4G or 5G PDCP and can therefore not create a
     * new tunnel */
    return 0;
  }

  inst->ue2te_mapping[create_tunnel_req->rnti]=it->second;
  inst->ue2te_mapping.erase(it);
  pthread_mutex_unlock(&globGtp.gtp_lock);
  return 0;
}

int gtpv1u_create_ngu_tunnel(const instance_t instance,
                             const gtpv1u_gnb_create_tunnel_req_t *const create_tunnel_req,
                             gtpv1u_gnb_create_tunnel_resp_t *const create_tunnel_resp,
                             gtpCallback callBack,
                             gtpCallbackSDAP callBackSDAP)
{
  LOG_D(GTPU, "[%ld] Start create tunnels for ue id %lu, num_tunnels %d, sgw_S1u_teid %x\n",
        instance,
        create_tunnel_req->ue_id,
        create_tunnel_req->num_tunnels,
        create_tunnel_req->outgoing_teid[0]);
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));

  tcp_udp_port_t dstport = inst->get_dstport();
  uint8_t addr[inst->foundAddrLen];
  memcpy(addr, inst->foundAddr, inst->foundAddrLen);
  pthread_mutex_unlock(&globGtp.gtp_lock);
  for (int i = 0; i < create_tunnel_req->num_tunnels; i++) {
    teid_t teid = newGtpuCreateTunnel(instance,
                                      create_tunnel_req->ue_id,
                                      create_tunnel_req->incoming_rb_id[i],
                                      create_tunnel_req->pdusession_id[i],
                                      create_tunnel_req->outgoing_teid[i],
                                      create_tunnel_req->outgoing_qfi[i],
                                      create_tunnel_req->dst_addr[i],
                                      dstport,
                                      callBack,
                                      callBackSDAP);
    update_ue_instance_teid(create_tunnel_req->ue_id, instance, teid);
    create_tunnel_resp->status=0;
    create_tunnel_resp->ue_id=create_tunnel_req->ue_id;
    create_tunnel_resp->num_tunnels=create_tunnel_req->num_tunnels;
    create_tunnel_resp->gnb_NGu_teid[i]=teid;
    memcpy(create_tunnel_resp->gnb_addr.buffer,addr,sizeof(addr));
    create_tunnel_resp->gnb_addr.length= sizeof(addr);
    create_tunnel_resp->pdusession_id[i] = create_tunnel_req->pdusession_id[i];

    /* Store only the real N3 incoming TEID. Do not let F1-U/DU placeholder
     * tunnels overwrite this value; otherwise local switching may inject into
     * the wrong PDCP/SDAP context after handover. */
    bool is_real_n3_tunnel = create_tunnel_req->outgoing_teid[i] != 0
                             && create_tunnel_req->outgoing_teid[i] != 0xffff;
    if (is_real_n3_tunnel) {
      cpe_ue_table_t *_ctbl = cpe_ue_table_get();
      if (_ctbl) {
        cpe_ue_lock(_ctbl);
        for (int _i = 0; _i < CPE_UE_MAX_ENTRIES; _i++) {
          cpe_ue_entry_t *_e = &_ctbl->entries[_i];
          if (_e->valid && _e->gtp_ue_id != 0
              && _e->gtp_ue_id == (uint32_t)create_tunnel_req->ue_id) {
            _e->gtp_n3_incoming_teid = teid;
            LOG_I(GTPU, "[CPE_UE] N3 incoming TEID 0x%x stored for ue_id=%lu\n",
                  teid, (unsigned long)create_tunnel_req->ue_id);
            cpe_ue_table_persist_locked(_ctbl);
            break;
          }
        }
        cpe_ue_unlock(_ctbl);
      }
    }
  }

  return !GTPNOK;
}

int gtpv1u_update_ue_id(const instance_t instanceP, ue_id_t old_ue_id, ue_id_t new_ue_id)
{
  pthread_mutex_lock(&globGtp.gtp_lock);

  auto inst = &globGtp.instances[compatInst(instanceP)];
  auto it = inst->ue2te_mapping.find(old_ue_id);
  if (it == inst->ue2te_mapping.end()) {
    LOG_W(GTPU, "[%ld] Update GTP tunnels for UEid: %lx, but no tunnel exits\n", instanceP, old_ue_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return GTPNOK;
  }

  for (unsigned i = 0; i < it->second.bearers.size(); ++i) {
    teid_t incoming_teid = inst->ue2te_mapping[old_ue_id].bearers[i].teid_incoming;
    if (globGtp.te2ue_mapping[incoming_teid].ue_id == old_ue_id) {
      globGtp.te2ue_mapping[incoming_teid].ue_id = new_ue_id;
    }
  }

  inst->ue2te_mapping[new_ue_id] = it->second;
  inst->ue2te_mapping.erase(it);

  pthread_mutex_unlock(&globGtp.gtp_lock);

  LOG_I(GTPU, "[%ld] Updated tunnels from UEid %lx to UEid %lx\n", instanceP, old_ue_id, new_ue_id);
  return !GTPNOK;
}

int gtpv1u_create_x2u_tunnel(
  const instance_t instanceP,
  const gtpv1u_enb_create_x2u_tunnel_req_t   *const create_tunnel_req_pP,
  gtpv1u_enb_create_x2u_tunnel_resp_t *const create_tunnel_resp_pP) {
  AssertFatal( false, "to be developped\n");
}

int newGtpuDeleteOneTunnel(instance_t instance, ue_id_t ue_id, int rb_id)
{
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));
  map<uint64_t, teidData_t>::iterator ue_it = inst->ue2te_mapping.find(ue_id);
  if (ue_it == inst->ue2te_mapping.end()) {
    LOG_E(GTPU, "%s() no such UE %ld\n", __func__, ue_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return !GTPNOK;
  }
  map<ue_id_t, gtpv1u_bearer_t>::iterator rb_it = ue_it->second.bearers.find(rb_id);
  if (rb_it == ue_it->second.bearers.end()) {
    LOG_E(GTPU, "%s() UE %ld has no bearer %d, available\n", __func__, ue_id, rb_id);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return !GTPNOK;
  }
  int teid = rb_it->second.teid_incoming;
  globGtp.te2ue_mapping.erase(teid);
  ue_it->second.bearers.erase(rb_id);
  pthread_mutex_unlock(&globGtp.gtp_lock);
  LOG_I(GTPU, "Deleted tunnel TEID %d (RB %d) for ue id %ld, remaining bearers:\n", teid, rb_id, ue_id);
  for (auto b: ue_it->second.bearers)
    LOG_I(GTPU, "bearer %ld\n", b.first);
  return !GTPNOK;
}

int newGtpuDeleteAllTunnels(instance_t instance, ue_id_t ue_id) {
  LOG_D(GTPU, "[%ld] Start delete tunnels for ue id %lu\n",
        instance, ue_id);
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));
  getUeRetInt(inst, ue_id);

  int nb=0;

  for (auto j=ptrUe->second.bearers.begin();
       j!=ptrUe->second.bearers.end();
       ++j) {
    globGtp.te2ue_mapping.erase(j->second.teid_incoming);
    nb++;
  }

  inst->ue2te_mapping.erase(ptrUe);
  pthread_mutex_unlock(&globGtp.gtp_lock);
  LOG_I(GTPU, "[%ld] Deleted all tunnels for ue id %ld (%d tunnels deleted)\n", instance, ue_id, nb);
  return !GTPNOK;
}

int gtpv1u_delete_s1u_tunnel( const instance_t instance,
                              const gtpv1u_enb_delete_tunnel_req_t *const req_pP) {
  LOG_D(GTPU, "[%ld] Start delete tunnels for RNTI %x\n", instance, req_pP->rnti);
  pthread_mutex_lock(&globGtp.gtp_lock);
  auto inst = &globGtp.instances[compatInst(instance)];
  auto ptrRNTI = inst->ue2te_mapping.find(req_pP->rnti);
  if (ptrRNTI == inst->ue2te_mapping.end()) {
    LOG_W(GTPU, "[%ld] Delete Released GTP tunnels for rnti: %x, but no tunnel exits\n", instance, req_pP->rnti);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return -1;
  }

  int nb = 0;

  for (int i = 0; i < req_pP->num_erab; i++) {
    auto ptr2 = ptrRNTI->second.bearers.find(req_pP->eps_bearer_id[i]);
    if (ptr2 == ptrRNTI->second.bearers.end()) {
      LOG_E(GTPU,
            "[%ld] GTP-U instance: delete of not existing tunnel RNTI:RAB: %x/%x\n",
            instance,
            req_pP->rnti,
            req_pP->eps_bearer_id[i]);
    } else {
      globGtp.te2ue_mapping.erase(ptr2->second.teid_incoming);
      nb++;
    }
  }

  if (ptrRNTI->second.bearers.size() == 0)
    // no tunnels on this rnti, erase the ue entry
    inst->ue2te_mapping.erase(ptrRNTI);

  pthread_mutex_unlock(&globGtp.gtp_lock);
  LOG_I(GTPU, "[%ld] Deleted released tunnels for RNTI %x (%d tunnels deleted)\n", instance, req_pP->rnti, nb);
  return !GTPNOK;
}

// Legacy delete tunnel finish by deleting all the ue id
int gtpv1u_delete_all_s1u_tunnel(const instance_t instance, const rnti_t rnti)
{
  return newGtpuDeleteAllTunnels(instance, rnti);
}

int newGtpuDeleteTunnels(instance_t instance, ue_id_t ue_id, int nbTunnels, pdusessionid_t *pdusession_id) {
  LOG_D(GTPU, "[%ld] Start delete tunnels for ue id %lu\n",
        instance, ue_id);
  pthread_mutex_lock(&globGtp.gtp_lock);
  getInstRetInt(compatInst(instance));
  getUeRetInt(inst, ue_id);
  int nb=0;

  for (int i=0; i<nbTunnels; i++) {
    auto ptr2=ptrUe->second.bearers.find(pdusession_id[i]);

    if ( ptr2 == ptrUe->second.bearers.end() ) {
      LOG_E(GTPU,"[%ld] GTP-U instance: delete of not existing tunnel UE ID:RAB: %ld/%x\n", instance, ue_id, pdusession_id[i]);
    } else {
      globGtp.te2ue_mapping.erase(ptr2->second.teid_incoming);
      nb++;
    }
  }

  if (ptrUe->second.bearers.size() == 0 )
    // no tunnels on this ue id, erase the ue entry
    inst->ue2te_mapping.erase(ptrUe);

  pthread_mutex_unlock(&globGtp.gtp_lock);
  LOG_I(GTPU, "[%ld] Deleted all tunnels for ue id %lu (%d tunnels deleted)\n", instance, ue_id, nb);
  return !GTPNOK;
}

int gtpv1u_delete_x2u_tunnel( const instance_t instanceP,
                              const gtpv1u_enb_delete_tunnel_req_t *const req_pP) {
  LOG_E(GTPU,"x2 tunnel not implemented\n");
  return 0;
}

int gtpv1u_delete_ngu_tunnel( const instance_t instance,
                              gtpv1u_gnb_delete_tunnel_req_t *req) {
  return  newGtpuDeleteTunnels(instance, req->ue_id, req->num_pdusession, req->pdusession_id);
}

static int Gtpv1uHandleEchoReq(int h,
                               uint8_t *msgBuf,
                               uint32_t msgBufLen,
                               uint16_t peerPort,
                               uint32_t peerIp) {
  Gtpv1uMsgHeaderT      *msgHdr = (Gtpv1uMsgHeaderT *) msgBuf;

  if ( msgHdr->version != 1 ||  msgHdr->PT != 1 ) {
    LOG_E(GTPU, "[%d] Received a packet that is not GTP header\n", h);
    return GTPNOK;
  }

  if ( msgHdr->S != 1 ) {
    LOG_E(GTPU, "[%d] Received a echo request packet with no sequence number \n", h);
    return GTPNOK;
  }

  uint16_t seq=ntohs(*(uint16_t *)(msgHdr+1));
  LOG_D(GTPU, "[%d] Received a echo request, TEID: %d, seq: %hu\n", h, msgHdr->teid, seq);
  uint8_t recovery[2]= {14,0};
  return gtpv1uCreateAndSendMsg(h, peerIp, peerPort, GTP_ECHO_RSP, ntohl(msgHdr->teid), recovery, sizeof recovery, true, false, seq, 0, NO_MORE_EXT_HDRS, NULL, 0);
}

static int Gtpv1uHandleError(int h,
                             uint8_t *msgBuf,
                             uint32_t msgBufLen,
                             uint16_t peerPort,
                             uint32_t peerIp) {
  LOG_E(GTPU, "Received GTP error indication (error handling is missing/not implemented)\n");
  int rc = GTPNOK;
  return rc;
}

static int Gtpv1uHandleSupportedExt(int h,
                                    uint8_t *msgBuf,
                                    uint32_t msgBufLen,
                                    uint16_t peerPort,
                                    uint32_t peerIp) {
  LOG_E(GTPU,"Supported extensions to be dev\n");
  int rc = GTPNOK;
  return rc;
}

// When end marker arrives, we notify the client with buffer size = 0
// The client will likely call "delete tunnel"
// nevertheless we don't take the initiative
static int Gtpv1uHandleEndMarker(int h,
                                 uint8_t *msgBuf,
                                 uint32_t msgBufLen,
                                 uint16_t peerPort,
                                 uint32_t peerIp) {
  Gtpv1uMsgHeaderT      *msgHdr = (Gtpv1uMsgHeaderT *) msgBuf;

  if ( msgHdr->version != 1 ||  msgHdr->PT != 1 ) {
    LOG_E(GTPU, "[%d] Received a packet that is not GTP header\n", h);
    return GTPNOK;
  }

  pthread_mutex_lock(&globGtp.gtp_lock);
  // the socket Linux file handler is the instance id
  getInstRetInt(h);

  auto tunnel = globGtp.te2ue_mapping.find(ntohl(msgHdr->teid));

  if (tunnel == globGtp.te2ue_mapping.end()) {
    LOG_E(GTPU,"[%d]  (%x) Dropping!\n", h, msgHdr->teid);
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return GTPNOK;
  }

  // This context is not good for gtp
  // frame, ... has no meaning
  // manyother attributes may come from create tunnel
  protocol_ctxt_t ctxt;
  ctxt.module_id = 0;
  ctxt.enb_flag = 1;
  ctxt.instance = inst->addr.originInstance;
  ctxt.rntiMaybeUEid = tunnel->second.ue_id;
  ctxt.frame = 0;
  ctxt.subframe = 0;
  ctxt.eNB_index = 0;
  ctxt.brOption = 0;
  const srb_flag_t     srb_flag=SRB_FLAG_NO;
  const rb_id_t        rb_id=tunnel->second.incoming_rb_id;
  const mui_t          mui=RLC_MUI_UNDEFINED;
  const confirm_t      confirm=RLC_SDU_CONFIRM_NO;
  const pdcp_transmission_mode_t mode=PDCP_TRANSMISSION_MODE_DATA;
  const uint32_t sourceL2Id=0;
  const uint32_t destinationL2Id=0;
  pthread_mutex_unlock(&globGtp.gtp_lock);

  if ( !tunnel->second.callBack(&ctxt,
                                srb_flag,
                                rb_id,
                                mui,
                                confirm,
                                0,
                                NULL,
                                mode,
                                &sourceL2Id,
                                &destinationL2Id) )
    LOG_E(GTPU,"[%d] down layer refused incoming packet\n", h);

  LOG_D(GTPU,"[%d] Received END marker packet for: teid:%x\n", h, ntohl(msgHdr->teid));
  return !GTPNOK;
}
typedef struct {
  int instance;
  uint32_t outgoing_teid;
  char remote_ipv4[64];  
  bool found;
} PduContext;



/*PduContext get_remoteipv4_instance_and_teid_by_pdu_address(const char *pdu_address) {
  PduContext result;

  result.instance = -1;
  result.outgoing_teid = 0;
  result.found = false;
  memset(result.remote_ipv4, 0, sizeof(result.remote_ipv4));  

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return result;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "SELECT instance, outgoing_teid, remote_ipv4 FROM ue_context "
           "WHERE pdu_address = '%s' AND ready=1 LIMIT 1",
           pdu_address);

  if (mysql_query(conn, query)) {
      fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_RES *res = mysql_store_result(conn);
  if (res == NULL) {
      fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  
  MYSQL_ROW row = mysql_fetch_row(res);
  if (row && row[0] && row[1] && row[2]) {
      result.instance = atoi(row[0]);  
      result.outgoing_teid = (uint32_t)strtoul(row[1], NULL, 10);  
      strncpy(result.remote_ipv4, row[2], sizeof(result.remote_ipv4) - 1);  
      result.remote_ipv4[sizeof(result.remote_ipv4) - 1] = '\0';  
      result.found = true;
  } else {
      printf("No record found for pdu_address: %s\n", pdu_address);
  }

  mysql_free_result(res);
  mysql_close(conn);

  return result;
}*/

#define CACHE_SIZE 100

typedef struct {
  char pdu_address[128];
  PduContext context;
  bool used;
} CacheEntry;

PduContext get_remoteipv4_instance_and_teid_by_pdu_address(const char *pdu_address) {
  static CacheEntry cache[CACHE_SIZE];
  const bool use_cache = false; /* mobility updates remote_ipv4; prefer fresh DB data */
  
  // 1. 先查快取
  if (use_cache) {
    for (int i = 0; i < CACHE_SIZE; i++) {
      if (cache[i].used && strcmp(cache[i].pdu_address, pdu_address) == 0) {
        // 找到快取結果，直接回傳
        return cache[i].context;
      }
    }
  }
  
  // 2. 如果快取沒找到，則查MySQL
  PduContext result;

  result.instance = -1;
  result.outgoing_teid = 0;
  result.found = false;
  memset(result.remote_ipv4, 0, sizeof(result.remote_ipv4));  

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return result;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "SELECT instance, outgoing_teid, remote_ipv4 FROM ue_context "
           "WHERE pdu_address = '%s' AND ready=1 LIMIT 1",
           pdu_address);

  if (mysql_query(conn, query)) {
      fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_RES *res = mysql_store_result(conn);
  if (res == NULL) {
      fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_ROW row = mysql_fetch_row(res);
  if (row && row[0] && row[1] && row[2]) {
      result.instance = atoi(row[0]);  
      result.outgoing_teid = (uint32_t)strtoul(row[1], NULL, 10);  
      strncpy(result.remote_ipv4, row[2], sizeof(result.remote_ipv4) - 1);  
      result.remote_ipv4[sizeof(result.remote_ipv4) - 1] = '\0';  
      result.found = true;
  } else {
      printf("No record found for pdu_address: %s\n", pdu_address);
  }

  mysql_free_result(res);
  mysql_close(conn);

  // 3. 把結果存到快取裡面（找到空位存，沒空位就覆蓋第一筆）
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (!cache[i].used) {
      strncpy(cache[i].pdu_address, pdu_address, sizeof(cache[i].pdu_address) - 1);
      cache[i].pdu_address[sizeof(cache[i].pdu_address) - 1] = '\0';
      cache[i].context = result;
      cache[i].used = true;
      break;
    }
    // 沒找到空位，覆蓋第一筆
    if (i == CACHE_SIZE - 1) {
      strncpy(cache[0].pdu_address, pdu_address, sizeof(cache[0].pdu_address) - 1);
      cache[0].pdu_address[sizeof(cache[0].pdu_address) - 1] = '\0';
      cache[0].context = result;
      cache[0].used = true;
    }
  }

  return result;
}

/* Look up CPE host context by ue_id directly (no dependency on pdu_address). */
static PduContext get_context_by_ue_id(uint32_t ue_id)
{
  PduContext result = {-1, 0, {0}, false};
  if (ue_id == 0)
    return result;

  MYSQL *conn = mysql_init(NULL);
  if (!conn)
    return result;
  if (!mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0)) {
    mysql_close(conn);
    return result;
  }

  char q[256];
  snprintf(q, sizeof(q),
           "SELECT instance,outgoing_teid,remote_ipv4 FROM ue_context"
           " WHERE ue_id=%u AND ready=1 LIMIT 1", ue_id);
  if (!mysql_query(conn, q)) {
    MYSQL_RES *res = mysql_store_result(conn);
    MYSQL_ROW row  = res ? mysql_fetch_row(res) : NULL;
    if (row && row[0] && row[1] && row[2]) {
      result.instance       = atoi(row[0]);
      result.outgoing_teid  = (uint32_t)strtoul(row[1], NULL, 10);
      strncpy(result.remote_ipv4, row[2], sizeof(result.remote_ipv4) - 1);
      result.found = (result.outgoing_teid != 0 && result.remote_ipv4[0] != '\0');
    }
    if (res) mysql_free_result(res);
  }
  mysql_close(conn);
  return result;
}

static uint32_t get_ready_ue_id_by_pdu_address(const char *pdu_address)
{
  if (!pdu_address || !pdu_address[0])
    return 0;

  for (uint32_t i = 1; i < CPE_UE_MAX_ENTRIES; i++) {
    const ue_gtp_ctx_t *c = &s_ue_gtp_ctx[i];
    if (c->ready && strncmp(c->pdu_address, pdu_address, INET_ADDRSTRLEN) == 0)
      return i;
  }

  uint32_t ue_id = 0;
  MYSQL *conn = mysql_init(NULL);
  if (!conn)
    return 0;
  if (!mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0)) {
    mysql_close(conn);
    return 0;
  }

  char q[256];
  snprintf(q, sizeof(q),
           "SELECT ue_id FROM ue_context WHERE pdu_address='%s' AND ready=1 LIMIT 1",
           pdu_address);
  if (!mysql_query(conn, q)) {
    MYSQL_RES *res = mysql_store_result(conn);
    MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
    if (row && row[0])
      ue_id = (uint32_t)strtoul(row[0], NULL, 10);
    if (res)
      mysql_free_result(res);
  }
  mysql_close(conn);
  if (ue_id > 0 && ue_id < CPE_UE_MAX_ENTRIES) {
    ue_gtp_ctx_t *c = &s_ue_gtp_ctx[ue_id];
    if (c->pdu_address[0] == '\0') {
      strncpy(c->pdu_address, pdu_address, INET_ADDRSTRLEN - 1);
      c->pdu_address[INET_ADDRSTRLEN - 1] = '\0';
    }
  }
  return ue_id;
}

static bool send_ip_sdu_to_ue_via_n3(ue_id_t ue_id,
                                     uint64_t n3_hint,
                                     uint8_t *ip_sdu,
                                     unsigned sdu_size,
                                     int qfi,
                                     bool rqi,
                                     const char *tag)
{
  if (ue_id == 0 || !ip_sdu || sdu_size == 0)
    return false;

  pthread_mutex_lock(&globGtp.gtp_lock);
  gtpCallbackSDAP cb_sdap = nullptr;
  gtpCallback cb = nullptr;
  int pdu_sid = 0;
  rb_id_t rb_id = 0;
  uint64_t n3_teid = 0;
  instance_t origin_instance = 0;

  if (n3_hint != 0) {
    auto it = globGtp.te2ue_mapping.find(n3_hint);
    if (it != globGtp.te2ue_mapping.end()
        && it->second.ue_id == ue_id
        && it->second.callBackSDAP != nullptr) {
      n3_teid = it->first;
      cb_sdap = it->second.callBackSDAP;
      cb = it->second.callBack;
      pdu_sid = it->second.pdusession_id;
      rb_id = it->second.incoming_rb_id;
    }
    if (!n3_teid) {
      pthread_mutex_unlock(&globGtp.gtp_lock);
      LOG_W(GTPU,
            "[%s] N3 hint 0x%lx does not match ue_id=%lu, drop local packet\n",
            tag ? tag : "CPE_UE", n3_hint, (unsigned long)ue_id);
      return false;
    }
  } else {
    for (auto &kv : globGtp.te2ue_mapping) {
      if (kv.second.ue_id == ue_id && kv.second.callBackSDAP != nullptr) {
        n3_teid = kv.first;
        cb_sdap = kv.second.callBackSDAP;
        cb = kv.second.callBack;
        pdu_sid = kv.second.pdusession_id;
        rb_id = kv.second.incoming_rb_id;
        break;
      }
    }
  }

  if (n3_teid != 0) {
    for (auto &inst_kv : globGtp.instances) {
      auto ue_it = inst_kv.second.ue2te_mapping.find(ue_id);
      if (ue_it == inst_kv.second.ue2te_mapping.end())
        continue;
      bool found_bearer = false;
      for (auto &bearer_kv : ue_it->second.bearers) {
        if (bearer_kv.second.teid_incoming == n3_teid) {
          origin_instance = inst_kv.second.addr.originInstance;
          found_bearer = true;
          break;
        }
      }
      if (found_bearer)
        break;
    }
  }
  pthread_mutex_unlock(&globGtp.gtp_lock);

  if (!n3_teid) {
    LOG_D(GTPU, "[%s] no local N3 TEID for ue_id=%lu, continue normal GTP path\n",
          tag ? tag : "CPE_UE", (unsigned long)ue_id);
    return false;
  }

  protocol_ctxt_t ctxt = {};
  ctxt.module_id = 0;
  ctxt.instance = origin_instance;
  ctxt.rntiMaybeUEid = ue_id;
  ctxt.enb_flag = 1;
  ctxt.frame = 0;
  ctxt.subframe = 0;
  ctxt.eNB_index = 0;
  ctxt.brOption = 0;
  const uint32_t src_l2 = 0, dst_l2 = 0;

  LOG_D(GTPU, "[%s] PDCP callback ue_id=%lu rb=%ld sz=%u n3_teid=0x%lx ctxt_inst=%ld\n",
        tag ? tag : "CPE_UE", (unsigned long)ue_id, rb_id, sdu_size, n3_teid, origin_instance);
  bool accepted = false;
  if (cb_sdap)
    accepted = cb_sdap(&ctxt, ue_id, SRB_FLAG_NO, rb_id,
                       RLC_MUI_UNDEFINED, RLC_SDU_CONFIRM_NO,
                       (sdu_size_t)sdu_size, ip_sdu,
                       PDCP_TRANSMISSION_MODE_DATA,
                       &src_l2, &dst_l2, qfi >= 0 ? qfi : 1, rqi, pdu_sid);
  else if (cb)
    accepted = cb(&ctxt, SRB_FLAG_NO, rb_id,
                  RLC_MUI_UNDEFINED, RLC_SDU_CONFIRM_NO,
                  (sdu_size_t)sdu_size, ip_sdu,
                  PDCP_TRANSMISSION_MODE_DATA, &src_l2, &dst_l2);
  if (!accepted)
    LOG_E(GTPU, "[%s] down layer refused local packet ue_id=%lu n3_teid=0x%lx\n",
          tag ? tag : "CPE_UE", (unsigned long)ue_id, n3_teid);
  return accepted;
}

static bool send_ip_sdu_via_ue_n3_outgoing(ue_id_t ue_id,
                                           uint8_t *ip_sdu,
                                           unsigned ip_sdu_size,
                                           int qfi,
                                           const char *tag)
{
  if (ue_id == 0 || !ip_sdu || ip_sdu_size == 0)
    return false;

  instance_t selected_instance = -1;
  gtpv1u_bearer_t selected_bearer = {};
  pthread_mutex_lock(&globGtp.gtp_lock);
  for (auto &inst_kv : globGtp.instances) {
    auto ue_it = inst_kv.second.ue2te_mapping.find(ue_id);
    if (ue_it == inst_kv.second.ue2te_mapping.end())
      continue;

    for (auto &bearer_kv : ue_it->second.bearers) {
      gtpv1u_bearer_t *b = &bearer_kv.second;
      if (b->teid_outgoing != 0
          && b->teid_outgoing != 0xffff
          && b->outgoing_ip_addr != 0
          && b->outgoing_qfi != -1) {
        selected_instance = inst_kv.first;
        if (b->seqNum < UINT16_MAX)
          b->seqNum++;
        selected_bearer = *b;
        break;
      }
    }
    if (selected_instance != -1)
      break;
  }
  pthread_mutex_unlock(&globGtp.gtp_lock);

  if (selected_instance == -1) {
    LOG_W(GTPU, "[%s] no N3 outgoing bearer for ue_id=%lu, drop packet\n",
          tag ? tag : "CPE_HOST", (unsigned long)ue_id);
    return false;
  }

  Gtpv1uExtHeaderT ext = {0};
  ext.ExtHeaderLen = 1;
  ext.pdusession_cntr.PDU_type = UL_PDU_SESSION_INFORMATION;
  ext.pdusession_cntr.QFI = qfi >= 0 ? qfi : selected_bearer.outgoing_qfi;
  ext.NextExtHeaderType = NO_MORE_EXT_HDRS;

  char remote_ip[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &selected_bearer.outgoing_ip_addr, remote_ip, sizeof(remote_ip));
  LOG_D(GTPU,
        "[%s] N3 send ue_id=%lu remote=%s teid=0x%x qfi=%d sz=%u instance=%ld\n",
        tag ? tag : "CPE_HOST", (unsigned long)ue_id, remote_ip,
        selected_bearer.teid_outgoing, ext.pdusession_cntr.QFI,
        ip_sdu_size, selected_instance);

  gtpv1uCreateAndSendMsg(compatInst(selected_instance),
                         selected_bearer.outgoing_ip_addr,
                         selected_bearer.outgoing_port,
                         GTP_GPDU,
                         selected_bearer.teid_outgoing,
                         ip_sdu,
                         ip_sdu_size,
                         false,
                         false,
                         selected_bearer.seqNum,
                         selected_bearer.npduNum,
                         PDU_SESSION_CONTAINER,
                         (uint8_t *)&ext,
                         sizeof(ext));
  return true;
}

static int Gtpv1uHandleGpdu(int h,
                            uint8_t *msgBuf,
                            uint32_t msgBufLen,
                            uint16_t peerPort,
                            uint32_t peerIp) {
  Gtpv1uMsgHeaderT      *msgHdr = (Gtpv1uMsgHeaderT *) msgBuf;
  
  //LOG_I(GTPU, "Printing entire GTP packet:\n");
  //dump_data(msgBuf, msgBufLen);

  if ( msgHdr->version != 1 ||  msgHdr->PT != 1 ) {
    LOG_E(GTPU, "[%d] Received a packet that is not GTP header\n", h);
    return GTPNOK;
  }

  pthread_mutex_lock(&globGtp.gtp_lock);
  // the socket Linux file handler is the instance id
  getInstRetInt(h);
  auto tunnel = globGtp.te2ue_mapping.find(ntohl(msgHdr->teid));

  if (tunnel == globGtp.te2ue_mapping.end()) {
    LOG_E(GTPU,"[%d] Received a incoming packet on unknown teid (%x) Dropping!\n", h, ntohl(msgHdr->teid));
    pthread_mutex_unlock(&globGtp.gtp_lock);
    return GTPNOK;
  }

  /* see TS 29.281 5.1 */
  //Minimum length of GTP-U header if non of the optional fields are present
  unsigned int offset = sizeof(Gtpv1uMsgHeaderT);

  int8_t qfi = -1;
  bool rqi = false;
  uint32_t NR_PDCP_PDU_SN = 0;

  /* if E, S, or PN is set then there are 4 more bytes of header */
  if( msgHdr->E ||  msgHdr->S ||msgHdr->PN)
    offset += 4;

  if (msgHdr->E) {
    int next_extension_header_type = msgBuf[offset - 1];
    int extension_header_length;

    while (next_extension_header_type != NO_MORE_EXT_HDRS) {
      extension_header_length = msgBuf[offset];
      switch (next_extension_header_type) {
        case PDU_SESSION_CONTAINER: {
	  if (offset + sizeof(PDUSessionContainerT) > msgBufLen ) {
	    LOG_E(GTPU, "gtp-u received header is malformed, ignore gtp packet\n");
	    return GTPNOK;
	  }
          PDUSessionContainerT *pdusession_cntr = (PDUSessionContainerT *)(msgBuf + offset + 1);
          qfi = pdusession_cntr->QFI;
          rqi = pdusession_cntr->Reflective_QoS_activation;
          break;
        }
        case NR_RAN_CONTAINER: {
	  if (offset + 1 > msgBufLen ) {
	    LOG_E(GTPU, "gtp-u received header is malformed, ignore gtp packet\n");
	    return GTPNOK;
	  }
          uint8_t PDU_type = (msgBuf[offset+1]>>4) & 0x0f;
          if (PDU_type == 0){ //DL USER Data Format
            int additional_offset = 6; //Additional offset capturing the first non-mandatory octet (TS 38.425, Figure 5.5.2.1-1)
            if(msgBuf[offset+1]>>2 & 0x1){ //DL Discard Blocks flag is present
              LOG_I(GTPU, "DL User Data: DL Discard Blocks handling not enabled\n"); 
              additional_offset = additional_offset + 9; //For the moment ignore
            }
            if(msgBuf[offset+1]>>1 & 0x1){ //DL Flush flag is present
              LOG_I(GTPU, "DL User Data: DL Flush handling not enabled\n");
              additional_offset = additional_offset + 3; //For the moment ignore
            }
            if((msgBuf[offset+2]>>3)& 0x1){ //"Report delivered" enabled (TS 38.425, 5.4)
              /*Store the NR PDCP PDU SN for which a delivery status report shall be generated once the
               *PDU gets forwarded to the lower layers*/
              //NR_PDCP_PDU_SN = msgBuf[offset+6] << 16 | msgBuf[offset+7] << 8 | msgBuf[offset+8];
              NR_PDCP_PDU_SN = msgBuf[offset+additional_offset] << 16 | msgBuf[offset+additional_offset+1] << 8 | msgBuf[offset+additional_offset+2]; 
              LOG_D(GTPU, " NR_PDCP_PDU_SN: %u \n",  NR_PDCP_PDU_SN);
            }
          }
          else{
            LOG_W(GTPU, "NR-RAN container type: %d not supported \n", PDU_type);
          }
          break;
        }
        default:
          LOG_W(GTPU, "unhandled extension 0x%2.2x, skipping\n", next_extension_header_type);
	  break;
      }

      offset += extension_header_length * EXT_HDR_LNTH_OCTET_UNITS;
      if (offset > msgBufLen ) {
	LOG_E(GTPU, "gtp-u received header is malformed, ignore gtp packet\n");
	return GTPNOK;
      }
      next_extension_header_type = msgBuf[offset - 1];
    }
  }

  // This context is not good for gtp
  // frame, ... has no meaning
  // manyother attributes may come from create tunnel
  protocol_ctxt_t ctxt;
  ctxt.module_id = 0;
  ctxt.enb_flag = 1;
  ctxt.instance = inst->addr.originInstance;
  ctxt.rntiMaybeUEid = tunnel->second.ue_id;
  ctxt.frame = 0;
  ctxt.subframe = 0;
  ctxt.eNB_index = 0;
  ctxt.brOption = 0;
  const srb_flag_t     srb_flag=SRB_FLAG_NO;
  const rb_id_t        rb_id=tunnel->second.incoming_rb_id;
  const mui_t          mui=RLC_MUI_UNDEFINED;
  const confirm_t      confirm=RLC_SDU_CONFIRM_NO;
  const sdu_size_t sdu_buffer_size = msgBufLen - offset;
  unsigned char *const sdu_buffer=msgBuf+offset;
  const pdcp_transmission_mode_t mode=PDCP_TRANSMISSION_MODE_DATA;
  const uint32_t sourceL2Id=0;
  const uint32_t destinationL2Id=0;
  pthread_mutex_unlock(&globGtp.gtp_lock);

  /* ---- xApp-controlled LBO: normal OAI UE -> normal OAI UE ---------------
   * The fast path is disabled by default. xApp enables it through
   * POST /lbo/control {"enable":1}. Once enabled, CU-UP detects an IPv4
   * packet whose destination is another known UE PDU address and injects the
   * raw IP SDU into that UE's local N3/PDCP callback, avoiding UPF hairpin. */
  int lbo_ip_off = -1;
  if (sdu_buffer_size > 20 && ((sdu_buffer[0] >> 4) & 0xf) == 4)
    lbo_ip_off = 0;
  else if (sdu_buffer_size > 23 && ((sdu_buffer[3] >> 4) & 0xf) == 4)
    lbo_ip_off = 3;

  if (lbo_is_enabled()
      && lbo_ip_off >= 0
      && !is_cpe_ue_gtp_ue_id(tunnel->second.ue_id)) {
    uint8_t *ip_lbo = &sdu_buffer[lbo_ip_off];
    char lbo_src_ip[INET_ADDRSTRLEN];
    char lbo_dst_ip[INET_ADDRSTRLEN];
    snprintf(lbo_src_ip, sizeof(lbo_src_ip), "%u.%u.%u.%u",
             ip_lbo[12], ip_lbo[13], ip_lbo[14], ip_lbo[15]);
    snprintf(lbo_dst_ip, sizeof(lbo_dst_ip), "%u.%u.%u.%u",
             ip_lbo[16], ip_lbo[17], ip_lbo[18], ip_lbo[19]);

    uint32_t dst_ue_id = get_ready_ue_id_by_pdu_address(lbo_dst_ip);
    if (dst_ue_id != 0
        && dst_ue_id != tunnel->second.ue_id
        && !is_cpe_ue_gtp_ue_id(dst_ue_id)) {
      bool src_matches_known_ue = true;
      if (tunnel->second.ue_id > 0 && tunnel->second.ue_id < CPE_UE_MAX_ENTRIES
          && s_ue_gtp_ctx[tunnel->second.ue_id].pdu_address[0])
        src_matches_known_ue = strncmp(s_ue_gtp_ctx[tunnel->second.ue_id].pdu_address,
                                       lbo_src_ip,
                                       INET_ADDRSTRLEN) == 0;

      if (src_matches_known_ue) {
        unsigned ip_sdu_size = sdu_buffer_size > lbo_ip_off
                               ? (unsigned)(sdu_buffer_size - lbo_ip_off) : 0;
        LOG_D(GTPU,
              "[LBO] UE local-breakout %s ue_id=%lu -> %s ue_id=%u ip_off=%d\n",
              lbo_src_ip, (unsigned long)tunnel->second.ue_id,
              lbo_dst_ip, dst_ue_id, lbo_ip_off);
        if (send_ip_sdu_to_ue_via_n3((ue_id_t)dst_ue_id,
                                     0,
                                     sdu_buffer + lbo_ip_off,
                                     ip_sdu_size,
                                     qfi, rqi,
                                     "LBO UE-to-UE")) {
          return 0;
        }
      } else {
        LOG_D(GTPU,
              "[LBO] src %s does not match ue_id=%lu PDU address, continue normal path\n",
              lbo_src_ip, (unsigned long)tunnel->second.ue_id);
      }
    }
  }
  /* ----------------------------------------------------------------------- */

  /* ---- CPE LAN local switch: OAI UE -> CPE host -> LAN client -----------
   * When a normal OAI UE sends to a CPE LAN client that is still behind the
   * CPE host, route the packet to the CPE host bearer. This replaces the old
   * cpe0 side path with the normal F1-U/DRB path. */
  int ip_off_cpe_lan = -1;
  if (sdu_buffer_size > 20 && ((sdu_buffer[0] >> 4) & 0xf) == 4)
    ip_off_cpe_lan = 0;
  else if (sdu_buffer_size > 23 && ((sdu_buffer[3] >> 4) & 0xf) == 4)
    ip_off_cpe_lan = 3;

  if (ip_off_cpe_lan >= 0) {
    uint8_t *ip_cpe_lan = &sdu_buffer[ip_off_cpe_lan];
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             ip_cpe_lan[12], ip_cpe_lan[13], ip_cpe_lan[14], ip_cpe_lan[15]);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             ip_cpe_lan[16], ip_cpe_lan[17], ip_cpe_lan[18], ip_cpe_lan[19]);
    LOG_D(GTPU, "[CPE LAN] inspect src=%s dst=%s ue_id=%lu size=%u ip_off=%d\n",
          src_ip_str, dst_ip_str, tunnel->second.ue_id, sdu_buffer_size,
          ip_off_cpe_lan);

    char cpe_outer_ip[INET_ADDRSTRLEN] = {0};
    uint32_t cpe_outer_gtp_ue_id = 0;
    uint32_t cpe_ru_ue_id = 0;
    uint64_t cpe_ru_n3_hint = 0;
    cpe_ue_table_t *ctbl_cpe_lan = cpe_ue_table_get();
    if (ctbl_cpe_lan) {
      cpe_ue_lock(ctbl_cpe_lan);
      cpe_ue_entry_t *lan_entry = cpe_ue_find_by_inner_ip_locked(ctbl_cpe_lan, dst_ip_str);
      if (lan_entry) {
        if (lan_entry->cpe_outer_ip[0]) {
          strncpy(cpe_outer_ip, lan_entry->cpe_outer_ip, sizeof(cpe_outer_ip) - 1);
          cpe_outer_gtp_ue_id = lan_entry->cpe_outer_gtp_ue_id;
        }
        if (lan_entry->active_path == CPE_UE_PATH_RU
            && lan_entry->gtp_ready
            && lan_entry->gtp_ue_id != 0) {
          cpe_ru_ue_id = lan_entry->gtp_ue_id;
          cpe_ru_n3_hint = lan_entry->gtp_n3_incoming_teid;
        }
      }
      cpe_ue_unlock(ctbl_cpe_lan);
    }

    if (cpe_ru_ue_id != 0) {
      unsigned ip_sdu_size = sdu_buffer_size > (unsigned)ip_off_cpe_lan
                              ? sdu_buffer_size - (unsigned)ip_off_cpe_lan : 0;
      LOG_D(GTPU,
            "[CPE LAN] ru-switch %s -> %s via CPE_UE ue_id=%u n3_teid=0x%lx\n",
            src_ip_str, dst_ip_str, cpe_ru_ue_id, cpe_ru_n3_hint);
      if (send_ip_sdu_to_ue_via_n3((ue_id_t)cpe_ru_ue_id,
                                   cpe_ru_n3_hint,
                                   sdu_buffer + ip_off_cpe_lan,
                                   ip_sdu_size,
                                   qfi, rqi,
                                   "CPE LAN ru-switch")) {
        return 0;
      }
    }

    if (cpe_outer_ip[0] && cpe_outer_gtp_ue_id != 0) {
      unsigned ip_sdu_size = sdu_buffer_size > (unsigned)ip_off_cpe_lan
                              ? sdu_buffer_size - (unsigned)ip_off_cpe_lan : 0;
      LOG_D(GTPU,
            "[CPE LAN] local-switch %s -> %s via CPE host %s ue_id=%u\n",
            src_ip_str, dst_ip_str, cpe_outer_ip, cpe_outer_gtp_ue_id);
      if (send_ip_sdu_to_ue_via_n3((ue_id_t)cpe_outer_gtp_ue_id,
                                   0,
                                   sdu_buffer + ip_off_cpe_lan,
                                   ip_sdu_size,
                                   qfi, rqi,
                                   "CPE LAN local-switch")) {
        return 0;
      }
    } else if (cpe_outer_ip[0]) {
      LOG_D(GTPU,
            "[CPE LAN] no CPE host ue_id for %s while probing dst=%s, continue normal GTP path\n",
            cpe_outer_ip, dst_ip_str);
    }

    /* Reverse local switch: CPE LAN client -> known UE PDU address.
     * The packet arrived from the CPE host bearer with a private LAN source
     * address. If the destination is another established UE PDU address, send
     * it directly to that UE's current DU instead of letting the core try to
     * route a private 192.168.1.x source address. */
    bool src_is_cpe_lan = false;
    cpe_ue_table_t *ctbl_cpe_reply = cpe_ue_table_get();
    if (ctbl_cpe_reply) {
      cpe_ue_lock(ctbl_cpe_reply);
      for (int _i = 0; _i < CPE_UE_MAX_ENTRIES; _i++) {
        cpe_ue_entry_t *src_entry = &ctbl_cpe_reply->entries[_i];
        if (!src_entry->valid
            || strncmp(src_entry->cpe_inner_ip, src_ip_str, INET_ADDRSTRLEN) != 0
            || src_entry->active_path != CPE_UE_PATH_CPE
            || !src_entry->cpe_outer_ip[0])
          continue;
        if (src_entry->cpe_outer_gtp_ue_id == 0
            || src_entry->cpe_outer_gtp_ue_id == (uint32_t)tunnel->second.ue_id) {
          src_is_cpe_lan = true;
          break;
        }
      }
      cpe_ue_unlock(ctbl_cpe_reply);
    }

    if (src_is_cpe_lan) {
      uint32_t dst_ue_id = get_ready_ue_id_by_pdu_address(dst_ip_str);
      if (dst_ue_id != 0) {
        unsigned ip_sdu_size = sdu_buffer_size > (unsigned)ip_off_cpe_lan
                                ? sdu_buffer_size - (unsigned)ip_off_cpe_lan : 0;
        LOG_D(GTPU,
              "[CPE LAN] reverse-switch %s -> %s via UE ue_id=%u\n",
              src_ip_str, dst_ip_str, dst_ue_id);
        if (send_ip_sdu_to_ue_via_n3((ue_id_t)dst_ue_id,
                                     0,
                                     sdu_buffer + ip_off_cpe_lan,
                                     ip_sdu_size,
                                     qfi, rqi,
                                     "CPE LAN reverse-switch")) {
          return 0;
        }
      } else {
        LOG_D(GTPU,
              "[CPE LAN] no UE bearer context for reverse dst=%s src=%s, continue normal GTP path\n",
              dst_ip_str, src_ip_str);
      }
    }
  }
  /* ----------------------------------------------------------------------- */
  
  /* ---- CPE_UE NAT reverse (downlink) ----------------------------------------
   * Layout (F1-U DL, null-cipher PDCP):
   *   sdu_buffer[0:2]   = 3-byte PDCP header
   *   sdu_buffer[3]     = IP version+IHL  (0x45 for IPv4)
   *   sdu_buffer[19:22] = Destination IP
   *   sdu_buffer[3+IHL] = transport header (TCP/UDP dst port at +2)
   *
   * If this is a DL packet addressed to a CPE UE's outer IP + NAT port,
   * rewrite dst IP → pdu_session_ip so the CPE_UE gets the packet.
   * Precondition: entry->state == NR_CONNECTED (pdu_session_ip is set). */
  int ip_off_dl = -1;
  if (sdu_buffer_size > 20 && ((sdu_buffer[0] >> 4) & 0xf) == 4)
    ip_off_dl = 0; /* N3 DL: raw IP PDU */
  else if (sdu_buffer_size > 23 && ((sdu_buffer[3] >> 4) & 0xf) == 4)
    ip_off_dl = 3; /* F1-U/local path: PDCP header before IP */

  if (ip_off_dl >= 0) {
    uint8_t *ip_dl = &sdu_buffer[ip_off_dl];
    char dl_dst_ip[INET_ADDRSTRLEN];
    snprintf(dl_dst_ip, sizeof(dl_dst_ip), "%u.%u.%u.%u",
             ip_dl[16], ip_dl[17], ip_dl[18], ip_dl[19]);

    int ihl_dl  = (ip_dl[0] & 0x0F) * 4;
    int toff_dl = ip_off_dl + ihl_dl;
    uint8_t proto_dl = ip_dl[9]; /* IP protocol field */
    uint16_t dst_port_dl = 0;
    uint16_t icmp_id_dl = 0;
    if ((proto_dl == 6 || proto_dl == 17)
        && (int)sdu_buffer_size > toff_dl + 4)
      dst_port_dl = (uint16_t)((sdu_buffer[toff_dl + 2] << 8)
                               | sdu_buffer[toff_dl + 3]);
    if (proto_dl == 1 && (int)sdu_buffer_size > toff_dl + 8)
      icmp_id_dl = (uint16_t)((sdu_buffer[toff_dl + 4] << 8)
                              | sdu_buffer[toff_dl + 5]);

    cpe_ue_table_t *ctbl_dl = cpe_ue_table_get();
    if (ctbl_dl && (dst_port_dl || icmp_id_dl)) {
      cpe_ue_lock(ctbl_dl);
      cpe_ue_entry_t *cpe_dl = NULL;
      if (dst_port_dl)
        cpe_dl = cpe_ue_find_by_outer_ip_locked(ctbl_dl, dl_dst_ip, dst_port_dl);
      else {
        for (int _i = 0; _i < CPE_UE_MAX_ENTRIES; _i++) {
          cpe_ue_entry_t *_e = &ctbl_dl->entries[_i];
          if (_e->valid
              && _e->active_path == CPE_UE_PATH_RU
              && _e->has_icmp_nat
              && _e->last_icmp_nat_id == icmp_id_dl
              && strncmp(_e->cpe_outer_ip, dl_dst_ip, INET_ADDRSTRLEN) == 0) {
            cpe_dl = _e;
            break;
          }
        }
      }
      if (cpe_dl && cpe_dl->state == CPE_UE_STATE_NR_CONNECTED
          && cpe_dl->active_path == CPE_UE_PATH_RU
          && cpe_dl->pdu_session_ip[0]) {
        struct in_addr pdu_addr;
        if (inet_aton(cpe_dl->pdu_session_ip, &pdu_addr)) {
          uint32_t new_dst = ntohl(pdu_addr.s_addr);
          ip_dl[16] = (new_dst >> 24) & 0xFF;
          ip_dl[17] = (new_dst >> 16) & 0xFF;
          ip_dl[18] = (new_dst >>  8) & 0xFF;
          ip_dl[19] =  new_dst        & 0xFF;

          /* Recalculate IP checksum */
          ip_dl[10] = 0;
          ip_dl[11] = 0;
          uint16_t ip_ck = ip_checksum(ip_dl, ihl_dl);
          ip_dl[10] = (ip_ck >> 8) & 0xFF;
          ip_dl[11] =  ip_ck       & 0xFF;

          if (proto_dl == 1 && (int)sdu_buffer_size > toff_dl + 8) {
            sdu_buffer[toff_dl + 4] = (cpe_dl->last_icmp_id >> 8) & 0xff;
            sdu_buffer[toff_dl + 5] = cpe_dl->last_icmp_id & 0xff;
            sdu_buffer[toff_dl + 2] = 0;
            sdu_buffer[toff_dl + 3] = 0;
            uint16_t ip_total_len = (uint16_t)((ip_dl[2] << 8) | ip_dl[3]);
            uint16_t icmp_len = ip_total_len > ihl_dl ? ip_total_len - ihl_dl : 0;
            uint16_t icmp_ck = ip_checksum(&sdu_buffer[toff_dl], icmp_len);
            sdu_buffer[toff_dl + 2] = (icmp_ck >> 8) & 0xff;
            sdu_buffer[toff_dl + 3] = icmp_ck & 0xff;
          } else if ((proto_dl == 6 || proto_dl == 17)
                     && (int)sdu_buffer_size > toff_dl + 8) {
            sdu_buffer[toff_dl + 6] = 0;
            sdu_buffer[toff_dl + 7] = 0;
          }
          LOG_D(GTPU,
                "[CPE_UE DL] NAT reverse: %s:%u → %s path=%s ip_off=%d\n",
                dl_dst_ip, dst_port_dl ? dst_port_dl : icmp_id_dl,
                cpe_dl->pdu_session_ip, cpe_ue_path_name(cpe_dl->active_path),
                ip_off_dl);

          /* Route DL via CPE_UE's own N3 PDCP callback so the packet goes
           * through proper PDCP encoding -> F1-U -> DU -> UE. */
          if (cpe_dl->gtp_ue_id != 0) {
            ue_id_t  _cpe_ue_id = (ue_id_t)cpe_dl->gtp_ue_id;
            uint64_t _n3_hint   = cpe_dl->gtp_n3_incoming_teid;
            int      _ip_off    = ip_off_dl;
            unsigned _sdu_sz    = (sdu_buffer_size > (unsigned)_ip_off)
                                  ? sdu_buffer_size - (unsigned)_ip_off : 0;
            cpe_ue_unlock(ctbl_dl);

            if (_sdu_sz > 0) {
              send_ip_sdu_to_ue_via_n3(_cpe_ue_id,
                                        _n3_hint,
                                        sdu_buffer + _ip_off,
                                        _sdu_sz,
                                        qfi, rqi,
                                        "CPE_UE DL");
            }
            return 0;
          } else {
            /* gtp_ue_id not set yet — send_pdu_session_accept hasn't fired. */
            LOG_W(GTPU,
                  "[CPE_UE DL] gtp_ue_id not set for pdu=%s, drop DL\n",
                  cpe_dl->pdu_session_ip);
            /* Old direct F1-U path (disabled — bypassed PDCP, UE discarded pkts):
             * gtpv1uCreateAndSendMsg(cpe_dl->gtp_instance, target_addr.s_addr,
             *   du_port, GTP_GPDU, cpe_dl->gtp_outgoing_teid, sdu_buffer,
             *   sdu_buffer_size, false, false, 0, 0, NO_MORE_EXT_HDRS, NULL, 0);
             * Old MySQL path (disabled — MySQL had no row for inner IP):
             * PduContext cpeue_ctx = get_remoteipv4_instance_and_teid_by_pdu_address(cpe_dl->pdu_session_ip);
             */
          }
        }
      } else {
        LOG_D(GTPU,
              "[CPE_UE DL] no NAT match dst=%s port/id=%u proto=%u ip_off=%d\n",
              dl_dst_ip,
              dst_port_dl ? dst_port_dl : icmp_id_dl,
              proto_dl,
              ip_off_dl);
      }
      cpe_ue_unlock(ctbl_dl);
    }
  }
  /* ---- end CPE_UE NAT reverse ----------------------------------------------- */

  /* SDU byte dump removed — too verbose for production */

  if (sdu_buffer_size > 0) {
    /* ---- CPE_UE NAT rewrite (uplink) ------------------------------------
     * Layout: sdu_buffer[0:2] = PDCP header, sdu_buffer[3..] = IP packet.
     * If this packet comes from a CPE_UE (identified by src IP matching
     * ctx->pdu_session_ip), rewrite src IP → cpe_outer_ip and src port
     * → cpe_nat_port, then recalculate IP + transport checksums.
     * This makes the packet look like it originates from the CPE's WAN
     * interface to the UPF / Internet. */
    int ip_off_ul = -1;
    if (sdu_buffer_size > 20 && ((sdu_buffer[0] >> 4) & 0xf) == 4)
      ip_off_ul = 0;
    else if (sdu_buffer_size > 23 && ((sdu_buffer[3] >> 4) & 0xf) == 4)
      ip_off_ul = 3;

    if (ip_off_ul >= 0) {
      uint8_t *ip_ul = &sdu_buffer[ip_off_ul];
      char ul_src_ip[INET_ADDRSTRLEN];
      char ul_dst_ip[INET_ADDRSTRLEN];
      snprintf(ul_src_ip, sizeof(ul_src_ip), "%u.%u.%u.%u",
               ip_ul[12], ip_ul[13], ip_ul[14], ip_ul[15]);
      snprintf(ul_dst_ip, sizeof(ul_dst_ip), "%u.%u.%u.%u",
               ip_ul[16], ip_ul[17], ip_ul[18], ip_ul[19]);

      cpe_ue_table_t *ctbl = cpe_ue_table_get();
      if (ctbl) {
        bool forward_via_cpe_host = false;
        bool forward_to_known_ue = false;
        uint32_t dst_ue_id = 0;
        uint32_t cpe_host_ue_id = 0;
        char cpe_host_outer_ip[INET_ADDRSTRLEN] = {0};
        cpe_ue_lock(ctbl);
        cpe_ue_entry_t *cpe_entry = cpe_ue_find_by_pdu_ip_locked(ctbl, ul_src_ip);

        if (cpe_entry && cpe_entry->state == CPE_UE_STATE_NR_CONNECTED
            && cpe_entry->active_path == CPE_UE_PATH_RU
            && cpe_entry->cpe_outer_ip[0]) {
          dst_ue_id = get_ready_ue_id_by_pdu_address(ul_dst_ip);
          if (dst_ue_id != 0) {
            forward_to_known_ue = true;
          } else {
            struct in_addr new_src;
            if (inet_aton(cpe_entry->cpe_outer_ip, &new_src)) {
              uint32_t new_ip = ntohl(new_src.s_addr);
              ip_ul[12] = (new_ip >> 24) & 0xFF;
              ip_ul[13] = (new_ip >> 16) & 0xFF;
              ip_ul[14] = (new_ip >> 8)  & 0xFF;
              ip_ul[15] =  new_ip        & 0xFF;

              uint8_t proto = ip_ul[9];
              uint16_t nat_port = cpe_entry->cpe_nat_port;
              int ihl = (ip_ul[0] & 0x0F) * 4; /* IP header length */
              int transport_off = ip_off_ul + ihl;
              if (nat_port && (proto == 6 || proto == 17)
                  && (int)sdu_buffer_size > transport_off + 4) {
                /* src port is first 2 bytes of TCP/UDP header */
                sdu_buffer[transport_off]     = (nat_port >> 8) & 0xFF;
                sdu_buffer[transport_off + 1] =  nat_port       & 0xFF;
              } else if (nat_port && proto == 1
                         && (int)sdu_buffer_size > transport_off + 8) {
                uint16_t old_icmp_id = (uint16_t)((sdu_buffer[transport_off + 4] << 8)
                                                  | sdu_buffer[transport_off + 5]);
                cpe_entry->last_icmp_id = old_icmp_id;
                cpe_entry->last_icmp_nat_id = nat_port;
                cpe_entry->has_icmp_nat = true;
                sdu_buffer[transport_off + 4] = (nat_port >> 8) & 0xff;
                sdu_buffer[transport_off + 5] = nat_port & 0xff;
              }

              /* Recalculate IP checksum */
              ip_ul[10] = 0;
              ip_ul[11] = 0;
              uint16_t new_ip_cksum = ip_checksum(ip_ul, ihl);
              ip_ul[10] = (new_ip_cksum >> 8) & 0xFF;
              ip_ul[11] =  new_ip_cksum       & 0xFF;

              if (proto == 1 && (int)sdu_buffer_size > transport_off + 8) {
                sdu_buffer[transport_off + 2] = 0;
                sdu_buffer[transport_off + 3] = 0;
                uint16_t ip_total_len = (uint16_t)((ip_ul[2] << 8) | ip_ul[3]);
                uint16_t icmp_len = ip_total_len > ihl ? ip_total_len - ihl : 0;
                uint16_t icmp_ck = ip_checksum(&sdu_buffer[transport_off], icmp_len);
                sdu_buffer[transport_off + 2] = (icmp_ck >> 8) & 0xff;
                sdu_buffer[transport_off + 3] = icmp_ck & 0xff;
              } else if ((proto == 6 || proto == 17)
                         && (int)sdu_buffer_size > transport_off + 8) {
                /* Zero transport checksum — UPF will recompute or accept zero */
                sdu_buffer[transport_off + 6] = 0;
                sdu_buffer[transport_off + 7] = 0;
              }

              LOG_D(GTPU,
                    "[CPE_UE UL] NAT rewrite: %s → %s id/port %u path=%s ip_off=%d\n",
                    ul_src_ip, cpe_entry->cpe_outer_ip, nat_port,
                    cpe_ue_path_name(cpe_entry->active_path), ip_off_ul);

              /* The RU-attached CPE_UE uses a fake IMSI/PDU session only to
               * anchor radio access. Its uplink must still leave through the
               * original CPE host bearer; otherwise the DN sees an unroutable
               * fake UE path. */
              if (cpe_entry->cpe_outer_gtp_ue_id != 0) {
                forward_via_cpe_host = true;
                cpe_host_ue_id = cpe_entry->cpe_outer_gtp_ue_id;
                strncpy(cpe_host_outer_ip, cpe_entry->cpe_outer_ip, sizeof(cpe_host_outer_ip) - 1);
              }
            }
          }
        }
        cpe_ue_unlock(ctbl);

        if (forward_to_known_ue) {
          uint8_t *ip_sdu = sdu_buffer + ip_off_ul;
          unsigned ip_sdu_size = sdu_buffer_size > (unsigned)ip_off_ul
                                  ? sdu_buffer_size - (unsigned)ip_off_ul : 0;
          LOG_D(GTPU,
                "[CPE_UE UL] local reply %s -> %s via UE ue_id=%u\n",
                ul_src_ip, ul_dst_ip, dst_ue_id);
          if (send_ip_sdu_to_ue_via_n3((ue_id_t)dst_ue_id,
                                       0,
                                       ip_sdu,
                                       ip_sdu_size,
                                       qfi, rqi,
                                       "CPE_UE UL local-reply")) {
            return 0;
          }
        }

        if (forward_via_cpe_host) {
          uint8_t *ip_sdu = sdu_buffer + ip_off_ul;
          unsigned ip_sdu_size = sdu_buffer_size > (unsigned)ip_off_ul
                                  ? sdu_buffer_size - (unsigned)ip_off_ul : 0;
          LOG_D(GTPU,
                "[CPE_UE UL] forward %s as %s via CPE host ue_id=%u\n",
                ul_src_ip, cpe_host_outer_ip, cpe_host_ue_id);
          if (send_ip_sdu_via_ue_n3_outgoing((ue_id_t)cpe_host_ue_id,
                                             ip_sdu,
                                             ip_sdu_size,
                                             qfi,
                                             "CPE_UE UL via CPE host")) {
            return 0;
          }
        }
      }
    }
    /* ---- end CPE_UE NAT rewrite ---------------------------------------- */

    if (qfi != -1 && tunnel->second.callBackSDAP) {
      if ( !tunnel->second.callBackSDAP(&ctxt,
                                        tunnel->second.ue_id,
                                        srb_flag,
                                        rb_id,
                                        mui,
                                        confirm,
                                        sdu_buffer_size,
                                        sdu_buffer,
                                        mode,
                                        &sourceL2Id,
                                        &destinationL2Id,
                                        qfi,
                                        rqi,
                                        tunnel->second.pdusession_id) )
        LOG_E(GTPU,"[%d] down layer refused incoming packet\n", h);
    } else {
      if ( !tunnel->second.callBack(&ctxt,
                                    srb_flag,
                                    rb_id,
                                    mui,
                                    confirm,
                                    sdu_buffer_size,
                                    sdu_buffer,
                                    mode,
                                    &sourceL2Id,
                                    &destinationL2Id) )
        LOG_E(GTPU,"[%d] down layer refused incoming packet\n", h);
    }
  }

  if(NR_PDCP_PDU_SN > 0 && NR_PDCP_PDU_SN %5 ==0){
    LOG_D (GTPU, "Create and send DL DATA Delivery status for the previously received PDU, NR_PDCP_PDU_SN: %u \n", NR_PDCP_PDU_SN);
    int rlc_tx_buffer_space = nr_rlc_get_available_tx_space(ctxt.rntiMaybeUEid, rb_id + 3);
    LOG_D(GTPU, "Available buffer size in RLC for Tx: %d \n", rlc_tx_buffer_space);
    /*Total size of DDD_status PDU = 1 octet to report extension header length
     * size of mandatory part + 3 octets for highest transmitted/delivered PDCP SN
     * 1 octet for padding + 1 octet for next extension header type,
     * according to TS 38.425: Fig. 5.5.2.2-1 and section 5.5.3.24*/
    extensionHeader_t *extensionHeader;
    extensionHeader = (extensionHeader_t *) calloc(1, sizeof(extensionHeader_t)) ;
    extensionHeader->buffer[0] = (1+sizeof(DlDataDeliveryStatus_flagsT)+3+1+1)/4;
    DlDataDeliveryStatus_flagsT DlDataDeliveryStatus;
    DlDataDeliveryStatus.deliveredPdcpSn = 0;
    DlDataDeliveryStatus.transmittedPdcpSn= 1; 
    DlDataDeliveryStatus.pduType = 1;
    DlDataDeliveryStatus.drbBufferSize = htonl(rlc_tx_buffer_space); //htonl(10000000); //hardcoded for now but normally we should extract it from RLC
    memcpy(extensionHeader->buffer+1, &DlDataDeliveryStatus, sizeof(DlDataDeliveryStatus_flagsT));
    uint8_t offset = sizeof(DlDataDeliveryStatus_flagsT)+1;

    extensionHeader->buffer[offset] =   (NR_PDCP_PDU_SN >> 16) & 0xff;
    extensionHeader->buffer[offset+1] = (NR_PDCP_PDU_SN >> 8) & 0xff;
    extensionHeader->buffer[offset+2] = NR_PDCP_PDU_SN & 0xff;
    LOG_D(GTPU, "Octets reporting NR_PDCP_PDU_SN, extensionHeader-> %u:%u:%u \n",
          extensionHeader->buffer[offset],
          extensionHeader->buffer[offset+1],
          extensionHeader->buffer[offset+2]);
    extensionHeader->buffer[offset+3] = 0x00; //Padding octet
    extensionHeader->buffer[offset+4] = 0x00; //No more extension headers
    /*Total size of DDD_status PDU = size of mandatory part +
     * 3 octets for highest transmitted/delivered PDCP SN +
     * 1 octet for padding + 1 octet for next extension header type,
     * according to TS 38.425: Fig. 5.5.2.2-1 and section 5.5.3.24*/
    extensionHeader->length  = 1+sizeof(DlDataDeliveryStatus_flagsT)+3+1+1;
    gtpv1uCreateAndSendMsg(
        h, peerIp, peerPort, GTP_GPDU, globGtp.te2ue_mapping[ntohl(msgHdr->teid)].outgoing_teid, NULL, 0, false, false, 0, 0, NR_RAN_CONTAINER, extensionHeader->buffer, extensionHeader->length);
  }

  LOG_D(GTPU,"[%d] Received a %d bytes packet for: teid:%x\n", h,
        msgBufLen-offset,
        ntohl(msgHdr->teid));
  return !GTPNOK;
}

typedef struct {
  char cpe_ip[64];
  bool found;
} UeCpeMapping;

/*UeCpeMapping get_cpe_ip_by_ue_ip(const char *ue_ip) {
  UeCpeMapping result;
  result.found = false;
  memset(result.cpe_ip, 0, sizeof(result.cpe_ip));

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return result;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "SELECT cpe_ip FROM cpe_ue_info WHERE ue_ip = '%s'", ue_ip);

  if (mysql_query(conn, query)) {
      fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_RES *res = mysql_store_result(conn);
  if (res == NULL) {
      fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_ROW row = mysql_fetch_row(res);
  if (row && row[0]) {
      strncpy(result.cpe_ip, row[0], sizeof(result.cpe_ip) - 1);
      result.cpe_ip[sizeof(result.cpe_ip) - 1] = '\0';
      result.found = true;
  } else {
      printf("No record found for ue_ip: %s\n", ue_ip);
  }

  mysql_free_result(res);
  mysql_close(conn);

  return result;
}*/

#define UE_CPE_CACHE_SIZE 100

typedef struct {
  char ue_ip[64];
  UeCpeMapping mapping;
  bool used;
} UeCpeCacheEntry;

UeCpeMapping get_cpe_ip_by_ue_ip(const char *ue_ip) {
  static UeCpeCacheEntry cache[UE_CPE_CACHE_SIZE];

  // 1. 先查快取
  for (int i = 0; i < UE_CPE_CACHE_SIZE; i++) {
    if (cache[i].used && strcmp(cache[i].ue_ip, ue_ip) == 0) {
      return cache[i].mapping;
    }
  }

  // 2. 如果沒找到，查資料庫
  UeCpeMapping result;
  result.found = false;
  memset(result.cpe_ip, 0, sizeof(result.cpe_ip));

  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return result;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "SELECT cpe_ip FROM cpe_ue_info WHERE ue_ip = '%s'", ue_ip);

  if (mysql_query(conn, query)) {
      fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_RES *res = mysql_store_result(conn);
  if (res == NULL) {
      fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return result;
  }

  MYSQL_ROW row = mysql_fetch_row(res);
  if (row && row[0]) {
      strncpy(result.cpe_ip, row[0], sizeof(result.cpe_ip) - 1);
      result.cpe_ip[sizeof(result.cpe_ip) - 1] = '\0';
      result.found = true;
  } else {
      printf("No record found for ue_ip: %s\n", ue_ip);
  }

  mysql_free_result(res);
  mysql_close(conn);

  // 3. 把結果加入快取
  for (int i = 0; i < UE_CPE_CACHE_SIZE; i++) {
    if (!cache[i].used) {
      strncpy(cache[i].ue_ip, ue_ip, sizeof(cache[i].ue_ip) - 1);
      cache[i].ue_ip[sizeof(cache[i].ue_ip) - 1] = '\0';
      cache[i].mapping = result;
      cache[i].used = true;
      break;
    }
    if (i == UE_CPE_CACHE_SIZE - 1) {
      // 如果快取滿了就覆蓋第一筆
      strncpy(cache[0].ue_ip, ue_ip, sizeof(cache[0].ue_ip) - 1);
      cache[0].ue_ip[sizeof(cache[0].ue_ip) - 1] = '\0';
      cache[0].mapping = result;
      cache[0].used = true;
    }
  }

  return result;
}

/*void insert_cpe_ue_info(const char* ue_ip, const char* cpe_ip) {
  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed\n");
      mysql_close(conn);
      return;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "INSERT INTO cpe_ue_info (ue_ip, cpe_ip) VALUES ('%s', '%s') "
           "ON DUPLICATE KEY UPDATE cpe_ip = VALUES(cpe_ip)",
           ue_ip, cpe_ip);

  if (mysql_query(conn, query)) {
      fprintf(stderr, "INSERT/UPDATE failed: %s\n", mysql_error(conn));
  } else {
      printf("Inserted/Updated: ue_ip = %s, cpe_ip = %s\n", ue_ip, cpe_ip);
      IP_active = 1;
  }

  mysql_close(conn);
}*/

void insert_cpe_ue_info(const char* ue_ip, const char* cpe_ip) {
  MYSQL *conn = mysql_init(NULL);
  if (conn == NULL) {
    fprintf(stderr, "mysql_init() failed\n");
    return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
    fprintf(stderr, "mysql_real_connect() failed\n");
    mysql_close(conn);
    return;
  }

  char query[512];
  snprintf(query, sizeof(query),
           "INSERT INTO cpe_ue_info (ue_ip, cpe_ip) VALUES ('%s', '%s') "
           "ON DUPLICATE KEY UPDATE cpe_ip = VALUES(cpe_ip)",
           ue_ip, cpe_ip);

  if (mysql_query(conn, query)) {
    fprintf(stderr, "INSERT/UPDATE failed: %s\n", mysql_error(conn));
  } else {
    printf("Inserted/Updated: ue_ip = %s, cpe_ip = %s\n", ue_ip, cpe_ip);

    // 設定 ue_ip 為 active
    int idx = find_or_add_ip(ue_ip);
    if (idx >= 0) {
      IP_active[idx] = 1;
      // [perf] printf("Set IP_active[%s] = 1 (idx=%d)\n", ue_ip, idx);
    } else {
      fprintf(stderr, "IP list full, cannot track ue_ip: %s\n", ue_ip);
    }
  }

  mysql_close(conn);
}

void print_pdu_entries_from_mysql(void) {
  MYSQL *conn;
  MYSQL_RES *res;

  conn = mysql_init(NULL);
  if (conn == NULL) {
      fprintf(stderr, "mysql_init() failed\n");
      return;
  }

  if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
      fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return;
  }

  if (mysql_query(conn, "SELECT assoc_id, stream, buffer_length, buffer FROM pdu_entries")) {
      fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return;
  }

  res = mysql_store_result(conn);
  if (res == NULL) {
      fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
      mysql_close(conn);
      return;
  }

  MYSQL_ROW row_data;
  unsigned long *lengths;

  while ((row_data = mysql_fetch_row(res))) {
      lengths = mysql_fetch_lengths(res);

      (void)row_data[0]; (void)row_data[1]; (void)row_data[2];
      const unsigned char *buffer = (const unsigned char *)row_data[3];
      unsigned long buffer_len = lengths[3];

      // [perf] printf(">>> assoc_id = %d, stream = %d, buffer_length = %d\n", assoc_id, stream, buf_len);
      printf("buffer (hex):\n");

      for (unsigned long i = 0; i < buffer_len; ++i) {
          printf("%02X ", buffer[i]);
          if ((i + 1) % 16 == 0) printf("\n");
      }
      if (buffer_len % 16 != 0) printf("\n");

      // [perf] printf("---------------------------------------------------\n");
  }

  mysql_free_result(res);
  mysql_close(conn);
}

#define MAX_PDU_LENGTH 4096  // 視實際 buffer 最大長度而定

typedef struct {
  int assoc_id;
  int stream;
  uint32_t buffer_length;
  uint8_t buffer[MAX_PDU_LENGTH];
} ty2_pdu_entry_t;

int fetch_one_pdu_entry_from_mysql(ty2_pdu_entry_t *entry) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        return -1;
    }

    if (mysql_real_connect(conn, "192.168.0.140", "root", "rtlab666", "lbo", 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    if (mysql_query(conn, "SELECT assoc_id, stream, buffer_length, buffer FROM pdu_entries ORDER BY id ASC LIMIT 1 OFFSET 1")) {
        fprintf(stderr, "SELECT failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    res = mysql_store_result(conn);
    if (res == NULL) {
        fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    row = mysql_fetch_row(res);
    if (row == NULL) {
        fprintf(stderr, "No data found.\n");
        mysql_free_result(res);
        mysql_close(conn);
        return -1;
    }

    unsigned long *lengths = mysql_fetch_lengths(res);
    if (!lengths) {
        fprintf(stderr, "mysql_fetch_lengths() failed\n");
        mysql_free_result(res);
        mysql_close(conn);
        return -1;
    }

    entry->assoc_id = atoi(row[0]);
    entry->stream = atoi(row[1]);
    entry->buffer_length = (uint32_t)atoi(row[2]);

    unsigned long actual_buf_len = lengths[3];
    if (actual_buf_len > MAX_PDU_LENGTH) {
        fprintf(stderr, "Buffer too large (%lu > %d)\n", actual_buf_len, MAX_PDU_LENGTH);
        mysql_free_result(res);
        mysql_close(conn);
        return -1;
    }

    memcpy(entry->buffer, row[3], actual_buf_len);

    mysql_free_result(res);
    mysql_close(conn);

    return 0;
}

#define MAX_PACKET_SIZE 1500

/*int build_dhcp_offer(uint8_t* response, uint8_t* discover, Lease* lease) {
  memset(response, 0, MAX_PACKET_SIZE);
  
  response[0] = 0x02;  // BOOTREPLY
  response[1] = 0x01;  // Ethernet
  response[2] = 0x06;  // hlen
  response[3] = 0x00;  // hops
  memcpy(&response[4], &discover[4], 4);  // xid
  response[8] = 0x00; response[9] = 0x00; // secs
  response[10] = 0x00; response[11] = 0x00; // flags

  // yiaddr: assigned IP
  memcpy(&response[16], lease->ip, 4);

  // siaddr: DHCP server IP (static)
  response[20] = 192;
  response[21] = 168;
  response[22] = 1;
  response[23] = 1;

  // chaddr: client MAC
  memcpy(&response[28], &discover[28], 6);

  // Magic cookie
  response[236] = 99;
  response[237] = 130;
  response[238] = 83;
  response[239] = 99;

  int idx = 240;
  // DHCP Message Type (Offer)
  response[idx++] = 53; response[idx++] = 1; response[idx++] = 2;

  // Server Identifier
  response[idx++] = 54; response[idx++] = 4;
  response[idx++] = 192; response[idx++] = 168; response[idx++] = 1; response[idx++] = 1;

  // Lease time
  response[idx++] = 51; response[idx++] = 4;
  response[idx++] = 0x00; response[idx++] = 0x01; response[idx++] = 0x51; response[idx++] = 0x80; // 86400s

  // Subnet mask
  response[idx++] = 1; response[idx++] = 4;
  response[idx++] = 255; response[idx++] = 255; response[idx++] = 255; response[idx++] = 0;

  // Router (Gateway)
  response[idx++] = 3; response[idx++] = 4;
  response[idx++] = 192; response[idx++] = 168; response[idx++] = 1; response[idx++] = 1;

  // DNS (optional)
  response[idx++] = 6; response[idx++] = 4;
  response[idx++] = 8; response[idx++] = 8; response[idx++] = 8; response[idx++] = 8;

  // End option
  response[idx++] = 255;

  return idx;  // 回傳實際封包長度
}*/
int build_dhcp_offer(uint8_t* packet, uint8_t* discover, Lease* lease) {
  memset(packet, 0, MAX_PACKET_SIZE);

  // === DHCP Payload ===
  uint8_t *dhcp = packet + sizeof(struct ip) + sizeof(struct udphdr);
  memset(dhcp, 0, 548);

  dhcp[0] = 0x02;  // BOOTREPLY
  dhcp[1] = 0x01;  // Ethernet
  dhcp[2] = 0x06;  // hlen
  dhcp[3] = 0x00;  // hops
  memcpy(&dhcp[4], &discover[4], 4);  // xid
  memcpy(&dhcp[16], lease->ip, 4);    // yiaddr
  dhcp[20] = 192; dhcp[21] = 168; dhcp[22] = 1; dhcp[23] = 1; // siaddr (DHCP server IP)
  memcpy(&dhcp[28], &discover[28], 6); // chaddr (client MAC)

  dhcp[236] = 99; dhcp[237] = 130; dhcp[238] = 83; dhcp[239] = 99; // magic cookie

  int idx = 240;
  dhcp[idx++] = 53; dhcp[idx++] = 1; dhcp[idx++] = 2; // DHCP Offer
  dhcp[idx++] = 54; dhcp[idx++] = 4; dhcp[idx++] = 192; dhcp[idx++] = 168; dhcp[idx++] = 1; dhcp[idx++] = 1;
  dhcp[idx++] = 51; dhcp[idx++] = 4; dhcp[idx++] = 0x00; dhcp[idx++] = 0x01; dhcp[idx++] = 0x51; dhcp[idx++] = 0x80;
  dhcp[idx++] = 1; dhcp[idx++] = 4; dhcp[idx++] = 255; dhcp[idx++] = 255; dhcp[idx++] = 255; dhcp[idx++] = 0;
  dhcp[idx++] = 3; dhcp[idx++] = 4; dhcp[idx++] = 192; dhcp[idx++] = 168; dhcp[idx++] = 1; dhcp[idx++] = 1;
  dhcp[idx++] = 6; dhcp[idx++] = 4; dhcp[idx++] = 8; dhcp[idx++] = 8; dhcp[idx++] = 8; dhcp[idx++] = 8;
  dhcp[idx++] = 255;

  int dhcp_len = idx;

  // === UDP Header ===
  struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
  udph->source = htons(67);
  udph->dest = htons(68);
  udph->len = htons(sizeof(struct udphdr) + dhcp_len);
  udph->check = 0; // Optional for IPv4, skip for now

  // === IP Header ===
  struct ip *iph = (struct ip *)packet;
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + dhcp_len);
  iph->ip_id = htons(0x1234);
  iph->ip_off = 0;
  iph->ip_ttl = 64;
  iph->ip_p = IPPROTO_UDP;
  iph->ip_sum = 0;

  // Source IP: DHCP Server (192.168.1.1)
  iph->ip_src.s_addr = inet_addr("192.168.1.1");

  // Destination IP: relay from discover (giaddr) or fallback to broadcast
  struct in_addr dst_ip;
  memcpy(&dst_ip.s_addr, &discover[24], 4); // giaddr
  if (dst_ip.s_addr == 0)
      dst_ip.s_addr = inet_addr("255.255.255.255");
  iph->ip_dst = dst_ip;

  iph->ip_sum = checksum((uint16_t *)iph, sizeof(struct ip)/2);

  return sizeof(struct ip) + sizeof(struct udphdr) + dhcp_len;
}

int build_dhcp_ack(uint8_t* packet, uint8_t* request, Lease* lease) {
  memset(packet, 0, MAX_PACKET_SIZE);

  // === DHCP Payload ===
  uint8_t *dhcp = packet + sizeof(struct ip) + sizeof(struct udphdr);
  memset(dhcp, 0, 548);

  dhcp[0] = 0x02;  // BOOTREPLY
  dhcp[1] = 0x01;  // Ethernet
  dhcp[2] = 0x06;  // hlen
  dhcp[3] = 0x00;  // hops
  memcpy(&dhcp[4], &request[4], 4);  // xid
  memcpy(&dhcp[16], lease->ip, 4);   // yiaddr (your IP)
  dhcp[20] = 192; dhcp[21] = 168; dhcp[22] = 1; dhcp[23] = 1; // siaddr
  memcpy(&dhcp[28], &request[28], 6); // chaddr (client MAC)

  dhcp[236] = 99; dhcp[237] = 130; dhcp[238] = 83; dhcp[239] = 99; // magic cookie

  int idx = 240;
  dhcp[idx++] = 53; dhcp[idx++] = 1; dhcp[idx++] = 5; // DHCP ACK
  dhcp[idx++] = 54; dhcp[idx++] = 4; dhcp[idx++] = 192; dhcp[idx++] = 168; dhcp[idx++] = 1; dhcp[idx++] = 1;
  dhcp[idx++] = 51; dhcp[idx++] = 4; dhcp[idx++] = 0x00; dhcp[idx++] = 0x01; dhcp[idx++] = 0x51; dhcp[idx++] = 0x80;
  dhcp[idx++] = 1;  dhcp[idx++] = 4; dhcp[idx++] = 255; dhcp[idx++] = 255; dhcp[idx++] = 255; dhcp[idx++] = 0;
  dhcp[idx++] = 3;  dhcp[idx++] = 4; dhcp[idx++] = 192; dhcp[idx++] = 168; dhcp[idx++] = 1; dhcp[idx++] = 1;
  dhcp[idx++] = 6;  dhcp[idx++] = 4; dhcp[idx++] = 8; dhcp[idx++] = 8; dhcp[idx++] = 8; dhcp[idx++] = 8;
  dhcp[idx++] = 255;

  int dhcp_len = idx;

  // === UDP Header ===
  struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
  udph->source = htons(67);
  udph->dest = htons(68);
  udph->len = htons(sizeof(struct udphdr) + dhcp_len);
  udph->check = 0;

  // === IP Header ===
  struct ip *iph = (struct ip *)packet;
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + dhcp_len);
  iph->ip_id = htons(0x5678);
  iph->ip_off = 0;
  iph->ip_ttl = 64;
  iph->ip_p = IPPROTO_UDP;
  iph->ip_sum = 0;

  iph->ip_src.s_addr = inet_addr("192.168.1.1");

  struct in_addr dst_ip;
  memcpy(&dst_ip.s_addr, &request[24], 4); // giaddr
  if (dst_ip.s_addr == 0)
      dst_ip.s_addr = inet_addr("255.255.255.255");
  iph->ip_dst = dst_ip;

  iph->ip_sum = checksum((uint16_t *)iph, sizeof(struct ip)/2);

  return sizeof(struct ip) + sizeof(struct udphdr) + dhcp_len;
}

// [perf] static double total_lbo_req_time_ms = 0.0;
// [perf] static int lbo_req_count = 0;

// [perf] static double total_lbo_reply_time_ms = 0.0;
// [perf] static int lbo_reply_count = 0;

// [perf] static double total_lbo_ho1_time_ms = 0.0;
// [perf] static int lbo_ho1_count = 0;

// [perf] static double total_lbo_ho2_time_ms = 0.0;
// [perf] static int lbo_ho2_count = 0;

// [perf] static double total_origin_time_ms = 0.0;
// [perf] static int origin_process_count = 0;

static double total_updatetable_time_ms = 0.0;

void gtpv1uReceiver(int h) {
  uint8_t           udpData[65536];
  int               udpDataLen;
  socklen_t          from_len;
  /* timing removed for performance */
  struct sockaddr_in addr;
  from_len = (socklen_t)sizeof(struct sockaddr_in);
  
  if ((udpDataLen = recvfrom(h, udpData, sizeof(udpData), 0,
                             (struct sockaddr *)&addr, &from_len)) < 0) {
    LOG_E(GTPU, "[%d] Recvfrom failed (%s)\n", h, strerror(errno));
    return;
  } else if (udpDataLen == 0) {
    LOG_W(GTPU, "[%d] Recvfrom returned 0\n", h);
    return;
  } else {
    if ( udpDataLen < (int)sizeof(Gtpv1uMsgHeaderT) ) {
      LOG_W(GTPU, "[%d] received malformed gtp packet \n", h);
      return;
    }
    Gtpv1uMsgHeaderT* msg=(Gtpv1uMsgHeaderT*) udpData;
    if ( (int)(ntohs(msg->msgLength) + sizeof(Gtpv1uMsgHeaderT)) != udpDataLen ) {
      LOG_W(GTPU, "[%d] received malformed gtp packet length\n", h);
      return;
    }
    LOG_D(GTPU, "[%d] Received GTP data, msg type: %x\n", h, msg->msgType);
    switch(msg->msgType) {
      case GTP_ECHO_RSP:
        break;

      case GTP_ECHO_REQ:
        Gtpv1uHandleEchoReq( h, udpData, udpDataLen, htons(addr.sin_port), addr.sin_addr.s_addr);
        break;

      case GTP_ERROR_INDICATION:
        Gtpv1uHandleError( h, udpData, udpDataLen, htons(addr.sin_port), addr.sin_addr.s_addr);
        break;

      case GTP_SUPPORTED_EXTENSION_HEADER_INDICATION:
        Gtpv1uHandleSupportedExt( h, udpData, udpDataLen, htons(addr.sin_port), addr.sin_addr.s_addr);
        break;

      case GTP_END_MARKER:
        Gtpv1uHandleEndMarker( h, udpData, udpDataLen, htons(addr.sin_port), addr.sin_addr.s_addr);
        break;

      case GTP_GPDU:
        Gtpv1uHandleGpdu(h, udpData, udpDataLen, htons(addr.sin_port), addr.sin_addr.s_addr);
        break;
      default:
        LOG_E(GTPU, "[%d] Received a GTP packet of unknown type: %d\n", h, msg->msgType);
        break;
    }
  }
}

#include <openair2/ENB_APP/enb_paramdef.h>

void *gtpv1uTask(void *args)  {
  while(1) {
    /* Trying to fetch a message from the message queue.
       If the queue is empty, this function will block till a
       message is sent to the task.
    */
    MessageDef *message_p = NULL;
    itti_receive_msg(TASK_GTPV1_U, &message_p);

    if (message_p != NULL ) {
      openAddr_t addr= {{0}};
      const instance_t myInstance = ITTI_MSG_DESTINATION_INSTANCE(message_p);
      const int msgType = ITTI_MSG_ID(message_p);
      LOG_D(GTPU, "GTP-U received %s for instance %ld\n", messages_info[msgType].name, myInstance);
      //LOG_I(GTPU, "GTP-U received %s for instance %ld\n", messages_info[msgType].name, myInstance);
      switch (msgType) {
          // DATA TO BE SENT TO UDP

        /* GTPV1U_TUNNEL_DATA_REQ removed in current OAI — data sent via gtpv1uSendDirect API */

        case GTPV1U_DU_BUFFER_REPORT_REQ:{
          gtpv1uSendDlDeliveryStatus(compatInst(myInstance), &GTPV1U_DU_BUFFER_REPORT_REQ(message_p));
        }
        break;

        case TERMINATE_MESSAGE:
          break;

        case TIMER_HAS_EXPIRED:
          LOG_E(GTPU, "Received unexpected timer expired (no need of timers in this version) %s\n", ITTI_MSG_NAME(message_p));
          break;

        case GTPV1U_ENB_END_MARKER_REQ:
          gtpv1uEndTunnel(compatInst(myInstance), &GTPV1U_ENB_END_MARKER_REQ(message_p));
          break;

        case GTPV1U_ENB_DATA_FORWARDING_REQ:
        case GTPV1U_ENB_DATA_FORWARDING_IND:
        case GTPV1U_ENB_END_MARKER_IND:
          LOG_E(GTPU, "to be developped %s\n", ITTI_MSG_NAME(message_p));
          abort();
          break;

        case GTPV1U_REQ:
          // to be dev: should be removed, to use API
          strcpy(addr.originHost, GTPV1U_REQ(message_p).localAddrStr);
          strcpy(addr.originService, GTPV1U_REQ(message_p).localPortStr);
          strcpy(addr.destinationService,addr.originService);
          AssertFatal((legacyInstanceMapping=gtpv1Init(addr))!=0,"Instance 0 reserved for legacy\n");
          break;

        default:
          LOG_E(GTPU, "Received unexpected message %s\n", ITTI_MSG_NAME(message_p));
          abort();
          break;
      }

      AssertFatal(EXIT_SUCCESS==itti_free(TASK_GTPV1_U, message_p), "Failed to free memory!\n");
    }

    struct epoll_event events[20];
    int nb_events = itti_get_events(TASK_GTPV1_U, events, 20);

    for (int i = 0; i < nb_events; i++)
      if ((events[i].events&EPOLLIN))
        gtpv1uReceiver(events[i].data.fd);
  }

  return NULL;
}

#ifdef __cplusplus
}
#endif
