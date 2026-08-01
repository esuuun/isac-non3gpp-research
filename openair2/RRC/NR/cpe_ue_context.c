#include "cpe_ue_context.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

/* ── Global singleton ──────────────────────────────────────────────────── */

static cpe_ue_table_t g_cpe_ue_table;
static int            g_initialized = 0;

/* Outer CPE UE info — saved the first time register_outer_cpe() runs so
 * that CPE_UE entries added LATER (via HO API) can inherit it immediately. */
static uint16_t g_outer_cpe_rnti        = 0;
static uint32_t g_outer_cpe_gtp_ue_id   = 0;
static bool           g_mysql_ready = false;
static __thread bool  g_mysql_syncing = false;

#define CPE_UE_MYSQL_DEFAULT_HOST "192.168.0.140"
#define CPE_UE_MYSQL_DEFAULT_USER "root"
#define CPE_UE_MYSQL_DEFAULT_PASS "rtlab666"
#define CPE_UE_MYSQL_DEFAULT_DB   "lbo"
#define CPE_UE_MYSQL_TABLE        "cpe_ue_context"
#define CPE_UE_CONTEXT_TABLE      "ue_context"

static const char *mysql_env_or_default(const char *name, const char *fallback)
{
  const char *v = getenv(name);
  return v && v[0] ? v : fallback;
}

static bool mysql_env_is_true(const char *name)
{
  const char *v = getenv(name);
  return v && (strcmp(v, "1") == 0
               || strcasecmp(v, "true") == 0
               || strcasecmp(v, "yes") == 0
               || strcasecmp(v, "on") == 0);
}

static MYSQL *cpe_ue_mysql_connect(bool with_db)
{
  const char *host = mysql_env_or_default("CPE_MYSQL_HOST", CPE_UE_MYSQL_DEFAULT_HOST);
  const char *user = mysql_env_or_default("CPE_MYSQL_USER", CPE_UE_MYSQL_DEFAULT_USER);
  const char *pass = mysql_env_or_default("CPE_MYSQL_PASSWORD", CPE_UE_MYSQL_DEFAULT_PASS);
  const char *db = mysql_env_or_default("CPE_MYSQL_DB", CPE_UE_MYSQL_DEFAULT_DB);

  MYSQL *conn = mysql_init(NULL);
  if (!conn)
    return NULL;

  unsigned int timeout = 1;
  mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
  mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout);
  mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

  if (!mysql_real_connect(conn, host, user, pass, with_db ? db : NULL, 0, NULL, 0)) {
    fprintf(stderr, "[CPE_UE MySQL] connect failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    return NULL;
  }
  return conn;
}

static bool cpe_ue_mysql_init_schema(void)
{
  const char *db = mysql_env_or_default("CPE_MYSQL_DB", CPE_UE_MYSQL_DEFAULT_DB);
  MYSQL *conn = cpe_ue_mysql_connect(false);
  if (!conn)
    return false;

  char q[256];
  snprintf(q, sizeof(q), "CREATE DATABASE IF NOT EXISTS `%s`", db);
  if (mysql_query(conn, q)) {
    fprintf(stderr, "[CPE_UE MySQL] create db failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    return false;
  }
  if (mysql_select_db(conn, db)) {
    fprintf(stderr, "[CPE_UE MySQL] select db failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    return false;
  }

  /* Clean legacy experiment tables if they are present.  Do not drop active
   * tables by default: CU-CP and CU-UP can initialize this helper at different
   * times, and dropping here can erase UE rows that were already learned from
   * GTP-U tunnel setup.  Set CPE_MYSQL_RESET=1 before starting the CU if a
   * fresh experiment database is desired.
   *
   * The active schema is intentionally only:
   *   ue_context      - generic NR UE bearer/location table
   *   cpe_ue_context - CPE_UE ownership/path table
   */
  mysql_query(conn, "DROP TABLE IF EXISTS cpe_ue_info");
  mysql_query(conn, "DROP TABLE IF EXISTS pdu_entries");
  if (mysql_env_is_true("CPE_MYSQL_RESET")) {
    mysql_query(conn, "DROP TABLE IF EXISTS " CPE_UE_CONTEXT_TABLE);
    mysql_query(conn, "DROP TABLE IF EXISTS " CPE_UE_MYSQL_TABLE);
    fprintf(stderr, "[CPE_UE MySQL] CPE_MYSQL_RESET=1, active tables recreated\n");
  }

  const char *create_ue_context =
    "CREATE TABLE IF NOT EXISTS " CPE_UE_CONTEXT_TABLE " ("
    "ue_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,"
    "rnti INT UNSIGNED NOT NULL DEFAULT 0,"
    "pdu_address VARCHAR(45) NOT NULL DEFAULT '',"
    "role VARCHAR(16) NOT NULL DEFAULT 'NORMAL_UE',"
    "instance INT NOT NULL DEFAULT 0,"
    "incoming_teid INT UNSIGNED NOT NULL DEFAULT 0,"
    "outgoing_teid INT UNSIGNED NOT NULL DEFAULT 0,"
    "remote_ipv4 VARCHAR(45) NOT NULL DEFAULT '',"
    "ready TINYINT(1) NOT NULL DEFAULT 0,"
    "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
    "KEY idx_pdu_address (pdu_address),"
    "KEY idx_role (role),"
    "KEY idx_remote_ipv4 (remote_ipv4)"
    ")";
  if (mysql_query(conn, create_ue_context)) {
    fprintf(stderr, "[CPE_UE MySQL] create ue_context failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    return false;
  }

  const char *create_table =
    "CREATE TABLE IF NOT EXISTS " CPE_UE_MYSQL_TABLE " ("
    "imsi BIGINT UNSIGNED NOT NULL PRIMARY KEY,"
    "rnti INT UNSIGNED NOT NULL DEFAULT 0,"
    "cpe_mac VARCHAR(17) NOT NULL DEFAULT '',"
    "cpe_inner_ip VARCHAR(45) NOT NULL DEFAULT '',"
    "cpe_outer_ip VARCHAR(45) NOT NULL DEFAULT '',"
    "cpe_nat_port INT UNSIGNED NOT NULL DEFAULT 0,"
    "cpe_rnti INT UNSIGNED NOT NULL DEFAULT 0,"
    "pdu_session_ip VARCHAR(45) NOT NULL DEFAULT '',"
    "active_path INT NOT NULL DEFAULT 0,"
    "gtp_ue_id INT UNSIGNED NOT NULL DEFAULT 0,"
    "cpe_outer_gtp_ue_id INT UNSIGNED NOT NULL DEFAULT 0,"
    "gtp_n3_incoming_teid INT UNSIGNED NOT NULL DEFAULT 0,"
    "gtp_instance INT NOT NULL DEFAULT 0,"
    "gtp_outgoing_teid INT UNSIGNED NOT NULL DEFAULT 0,"
    "gtp_remote_ipv4 VARCHAR(45) NOT NULL DEFAULT '',"
    "gtp_ready TINYINT(1) NOT NULL DEFAULT 0,"
    "last_icmp_id INT UNSIGNED NOT NULL DEFAULT 0,"
    "last_icmp_nat_id INT UNSIGNED NOT NULL DEFAULT 0,"
    "has_icmp_nat TINYINT(1) NOT NULL DEFAULT 0,"
    "ul_packets BIGINT UNSIGNED NOT NULL DEFAULT 0,"
    "dl_packets BIGINT UNSIGNED NOT NULL DEFAULT 0,"
    "state INT NOT NULL DEFAULT 0,"
    "valid TINYINT(1) NOT NULL DEFAULT 1,"
    "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
    "KEY idx_rnti (rnti),"
    "KEY idx_pdu_session_ip (pdu_session_ip),"
    "KEY idx_cpe_outer (cpe_outer_ip,cpe_nat_port),"
    "KEY idx_gtp_ue_id (gtp_ue_id)"
    ")";
  if (mysql_query(conn, create_table)) {
    fprintf(stderr, "[CPE_UE MySQL] create table failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    return false;
  }

  mysql_close(conn);
  return true;
}

static void cpe_ue_mysql_load(cpe_ue_table_t *tbl)
{
  if (!g_mysql_ready || g_mysql_syncing)
    return;
  g_mysql_syncing = true;

  MYSQL *conn = cpe_ue_mysql_connect(true);
  if (!conn) {
    g_mysql_syncing = false;
    return;
  }

  const char *q =
    "SELECT imsi,rnti,cpe_inner_ip,cpe_outer_ip,cpe_nat_port,cpe_rnti,"
    "pdu_session_ip,active_path,gtp_ue_id,cpe_outer_gtp_ue_id,gtp_n3_incoming_teid,"
    "gtp_instance,gtp_outgoing_teid,gtp_remote_ipv4,gtp_ready,"
    "last_icmp_id,last_icmp_nat_id,has_icmp_nat,ul_packets,dl_packets,state,valid "
    "FROM " CPE_UE_MYSQL_TABLE " WHERE valid=1 ORDER BY updated_at DESC LIMIT 64";
  if (mysql_query(conn, q)) {
    fprintf(stderr, "[CPE_UE MySQL] load failed: %s\n", mysql_error(conn));
    mysql_close(conn);
    g_mysql_syncing = false;
    return;
  }

  MYSQL_RES *res = mysql_store_result(conn);
  if (!res) {
    mysql_close(conn);
    g_mysql_syncing = false;
    return;
  }

  memset(tbl->entries, 0, sizeof(tbl->entries));
  MYSQL_ROW row;
  int i = 0;
  while (i < CPE_UE_MAX_ENTRIES && (row = mysql_fetch_row(res))) {
    cpe_ue_entry_t *e = &tbl->entries[i++];
    e->imsi = row[0] ? strtoull(row[0], NULL, 10) : 0;
    e->rnti = row[1] ? (uint16_t)strtoul(row[1], NULL, 10) : 0;
    if (row[2]) strncpy(e->cpe_inner_ip, row[2], INET_ADDRSTRLEN - 1);
    if (row[3]) strncpy(e->cpe_outer_ip, row[3], INET_ADDRSTRLEN - 1);
    e->cpe_nat_port = row[4] ? (uint16_t)strtoul(row[4], NULL, 10) : 0;
    e->cpe_rnti = row[5] ? (uint16_t)strtoul(row[5], NULL, 10) : 0;
    if (row[6]) strncpy(e->pdu_session_ip, row[6], INET_ADDRSTRLEN - 1);
    e->active_path = row[7] ? (cpe_ue_path_e)atoi(row[7]) : CPE_UE_PATH_CPE;
    e->gtp_ue_id = row[8] ? (uint32_t)strtoul(row[8], NULL, 10) : 0;
    e->cpe_outer_gtp_ue_id = row[9] ? (uint32_t)strtoul(row[9], NULL, 10) : 0;
    e->gtp_n3_incoming_teid = row[10] ? (uint32_t)strtoul(row[10], NULL, 10) : 0;
    e->gtp_instance = row[11] ? atoi(row[11]) : 0;
    e->gtp_outgoing_teid = row[12] ? (uint32_t)strtoul(row[12], NULL, 10) : 0;
    if (row[13]) strncpy(e->gtp_remote_ipv4, row[13], INET_ADDRSTRLEN - 1);
    e->gtp_ready = row[14] ? atoi(row[14]) != 0 : false;
    e->last_icmp_id = row[15] ? (uint16_t)strtoul(row[15], NULL, 10) : 0;
    e->last_icmp_nat_id = row[16] ? (uint16_t)strtoul(row[16], NULL, 10) : 0;
    e->has_icmp_nat = row[17] ? atoi(row[17]) != 0 : false;
    e->ul_packets = row[18] ? strtoull(row[18], NULL, 10) : 0;
    e->dl_packets = row[19] ? strtoull(row[19], NULL, 10) : 0;
    e->state = row[20] ? (cpe_ue_state_e)atoi(row[20]) : CPE_UE_STATE_WIFI_ONLY;
    e->valid = row[21] ? atoi(row[21]) != 0 : false;
  }

  mysql_free_result(res);
  mysql_close(conn);
  g_mysql_syncing = false;
}

static void cpe_ue_mysql_save_entry(MYSQL *conn, const cpe_ue_entry_t *e)
{
  if (!conn || !e || !e->valid || e->imsi == 0)
    return;

  char inner[INET_ADDRSTRLEN * 2 + 1] = {0};
  char outer[INET_ADDRSTRLEN * 2 + 1] = {0};
  char pdu[INET_ADDRSTRLEN * 2 + 1] = {0};
  char remote[INET_ADDRSTRLEN * 2 + 1] = {0};
  mysql_real_escape_string(conn, inner, e->cpe_inner_ip, strlen(e->cpe_inner_ip));
  mysql_real_escape_string(conn, outer, e->cpe_outer_ip, strlen(e->cpe_outer_ip));
  mysql_real_escape_string(conn, pdu, e->pdu_session_ip, strlen(e->pdu_session_ip));
  mysql_real_escape_string(conn, remote, e->gtp_remote_ipv4, strlen(e->gtp_remote_ipv4));

  char q[2048];
  snprintf(q, sizeof(q),
           "INSERT INTO " CPE_UE_MYSQL_TABLE " "
           "(imsi,rnti,cpe_inner_ip,cpe_outer_ip,cpe_nat_port,cpe_rnti,"
           "pdu_session_ip,active_path,gtp_ue_id,cpe_outer_gtp_ue_id,gtp_n3_incoming_teid,"
           "gtp_instance,gtp_outgoing_teid,gtp_remote_ipv4,gtp_ready,"
           "last_icmp_id,last_icmp_nat_id,has_icmp_nat,ul_packets,dl_packets,state,valid) "
           "VALUES (%llu,%u,'%s','%s',%u,%u,'%s',%d,%u,%u,%u,%d,%u,'%s',%d,%u,%u,%d,%llu,%llu,%d,%d) "
           "ON DUPLICATE KEY UPDATE "
           "rnti=VALUES(rnti),cpe_inner_ip=VALUES(cpe_inner_ip),"
           "cpe_outer_ip=VALUES(cpe_outer_ip),cpe_nat_port=VALUES(cpe_nat_port),"
           "cpe_rnti=VALUES(cpe_rnti),pdu_session_ip=VALUES(pdu_session_ip),"
           "active_path=VALUES(active_path),gtp_ue_id=VALUES(gtp_ue_id),"
           "cpe_outer_gtp_ue_id=VALUES(cpe_outer_gtp_ue_id),"
           "gtp_n3_incoming_teid=VALUES(gtp_n3_incoming_teid),"
           "gtp_instance=VALUES(gtp_instance),gtp_outgoing_teid=VALUES(gtp_outgoing_teid),"
           "gtp_remote_ipv4=VALUES(gtp_remote_ipv4),gtp_ready=VALUES(gtp_ready),"
           "last_icmp_id=VALUES(last_icmp_id),last_icmp_nat_id=VALUES(last_icmp_nat_id),"
           "has_icmp_nat=VALUES(has_icmp_nat),ul_packets=VALUES(ul_packets),"
           "dl_packets=VALUES(dl_packets),state=VALUES(state),valid=VALUES(valid)",
           (unsigned long long)e->imsi, e->rnti, inner, outer, e->cpe_nat_port,
           e->cpe_rnti, pdu, (int)e->active_path, e->gtp_ue_id,
           e->cpe_outer_gtp_ue_id, e->gtp_n3_incoming_teid, e->gtp_instance, e->gtp_outgoing_teid,
           remote, e->gtp_ready ? 1 : 0, e->last_icmp_id, e->last_icmp_nat_id,
           e->has_icmp_nat ? 1 : 0, (unsigned long long)e->ul_packets,
           (unsigned long long)e->dl_packets, (int)e->state, e->valid ? 1 : 0);
  if (mysql_query(conn, q))
    fprintf(stderr, "[CPE_UE MySQL] save IMSI %llu failed: %s\n",
            (unsigned long long)e->imsi, mysql_error(conn));
}

static void cpe_ue_mysql_save(cpe_ue_table_t *tbl)
{
  if (!g_mysql_ready || g_mysql_syncing)
    return;
  g_mysql_syncing = true;

  MYSQL *conn = cpe_ue_mysql_connect(true);
  if (!conn) {
    g_mysql_syncing = false;
    return;
  }

  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++)
    cpe_ue_mysql_save_entry(conn, &tbl->entries[i]);

  mysql_close(conn);
  g_mysql_syncing = false;
}

static void cpe_ue_mysql_delete_where(const char *where)
{
  if (!g_mysql_ready || !where)
    return;
  MYSQL *conn = cpe_ue_mysql_connect(true);
  if (!conn)
    return;
  char q[256];
  snprintf(q, sizeof(q), "DELETE FROM " CPE_UE_MYSQL_TABLE " WHERE %s", where);
  if (mysql_query(conn, q))
    fprintf(stderr, "[CPE_UE MySQL] delete failed: %s\n", mysql_error(conn));
  mysql_close(conn);
}

bool cpe_ue_lookup_host_pdu_address(uint32_t host_ue_id, char *out, size_t out_len)
{
  if (!g_mysql_ready || !out || out_len == 0)
    return false;

  MYSQL *conn = cpe_ue_mysql_connect(true);
  if (!conn)
    return false;

  char q[256];
  if (host_ue_id != 0)
    snprintf(q, sizeof(q),
             "SELECT pdu_address FROM ue_context"
             " WHERE ue_id=%u AND pdu_address<>'' LIMIT 1",
             host_ue_id);
  else
    snprintf(q, sizeof(q),
             "SELECT pdu_address FROM ue_context"
             " WHERE role='CPE_HOST' AND pdu_address<>'' LIMIT 1");

  bool found = false;
  if (!mysql_query(conn, q)) {
    MYSQL_RES *res = mysql_store_result(conn);
    MYSQL_ROW row  = res ? mysql_fetch_row(res) : NULL;
    if (row && row[0] && row[0][0]) {
      strncpy(out, row[0], out_len - 1);
      out[out_len - 1] = '\0';
      found = true;
    }
    if (res) mysql_free_result(res);
  }
  mysql_close(conn);
  return found;
}

static void cpe_ue_mysql_upsert_ue_context(uint32_t ue_id,
                                           uint16_t rnti,
                                           const char *pdu_address,
                                           const char *role)
{
  if (!g_mysql_ready || ue_id == 0)
    return;

  MYSQL *conn = cpe_ue_mysql_connect(true);
  if (!conn)
    return;

  char pdu[INET_ADDRSTRLEN * 2 + 1] = {0};
  char role_esc[32] = {0};
  if (pdu_address)
    mysql_real_escape_string(conn, pdu, pdu_address, strlen(pdu_address));
  if (role)
    mysql_real_escape_string(conn, role_esc, role, strlen(role));
  else
    snprintf(role_esc, sizeof(role_esc), "NORMAL_UE");

  char q[1024];
  snprintf(q, sizeof(q),
           "INSERT INTO " CPE_UE_CONTEXT_TABLE " "
           "(ue_id,rnti,pdu_address,role) VALUES (%u,%u,'%s','%s') "
           "ON DUPLICATE KEY UPDATE "
           "rnti=IF(VALUES(rnti)<>0,VALUES(rnti),rnti),"
           "pdu_address=IF(VALUES(pdu_address)<>'',VALUES(pdu_address),pdu_address),"
           "role=IF(role='CPE_HOST',role,IF(VALUES(role)<>'',VALUES(role),role))",
           ue_id, rnti, pdu, role_esc);
  if (mysql_query(conn, q))
    fprintf(stderr, "[CPE_UE MySQL] upsert ue_context failed: %s\n", mysql_error(conn));
  mysql_close(conn);
}

void cpe_ue_table_upsert_ue_context(uint32_t ue_id,
                                     uint16_t rnti,
                                     const char *pdu_address,
                                     const char *role)
{
  cpe_ue_mysql_upsert_ue_context(ue_id, rnti, pdu_address, role);
}

cpe_ue_table_t *cpe_ue_table_get(void)
{
  return &g_cpe_ue_table;
}

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

void cpe_ue_table_init(cpe_ue_table_t *tbl)
{
  if (g_initialized)
    return;
  memset(tbl, 0, sizeof(*tbl));
  pthread_mutex_init(&tbl->lock, NULL);
  g_mysql_ready = cpe_ue_mysql_init_schema();
  if (g_mysql_ready) {
    pthread_mutex_lock(&tbl->lock);
    cpe_ue_mysql_load(tbl);
    pthread_mutex_unlock(&tbl->lock);
    fprintf(stderr, "[CPE_UE MySQL] using %s.%s as CPE_UE context store\n",
            mysql_env_or_default("CPE_MYSQL_DB", CPE_UE_MYSQL_DEFAULT_DB),
            CPE_UE_MYSQL_TABLE);
  } else {
    fprintf(stderr, "[CPE_UE MySQL] unavailable, falling back to process memory\n");
  }
  g_initialized = 1;
}

void cpe_ue_table_destroy(cpe_ue_table_t *tbl)
{
  pthread_mutex_destroy(&tbl->lock);
  memset(tbl, 0, sizeof(*tbl));
  g_initialized = 0;
}

/* ── Lock helpers ──────────────────────────────────────────────────────── */

void cpe_ue_lock(cpe_ue_table_t *tbl)
{
  pthread_mutex_lock(&tbl->lock);
}

void cpe_ue_unlock(cpe_ue_table_t *tbl)
{
  pthread_mutex_unlock(&tbl->lock);
}

void cpe_ue_table_persist_locked(cpe_ue_table_t *tbl)
{
  cpe_ue_mysql_save(tbl);
}

const char *cpe_ue_state_name(cpe_ue_state_e state)
{
  switch (state) {
    case CPE_UE_STATE_WIFI_ONLY: return "WIFI_ONLY";
    case CPE_UE_STATE_HO_IN_PROGRESS: return "HO_IN_PROGRESS";
    case CPE_UE_STATE_NR_CONNECTED: return "NR_CONNECTED";
    default: return "UNKNOWN";
  }
}

const char *cpe_ue_path_name(cpe_ue_path_e path)
{
  switch (path) {
    case CPE_UE_PATH_CPE: return "CPE";
    case CPE_UE_PATH_RU: return "RU";
    default: return "UNKNOWN";
  }
}

/* ── Virtual USIM Provisioning ──────────────────────────────────────────── */
/* Generate NAI-based SUPI from MAC and provision to Free5GC UDM via REST API */
static void provision_virtual_usim(const char *mac_address)
{
  if (!mac_address || mac_address[0] == '\0') return;

  /* 1. Generate NAI-based SUPI from MAC */
  /* Remove colons from MAC: "AA:BB:CC:DD:EE:FF" -> "AABBCCDDEEFF" */
  char mac_hex[13] = {0};
  int j = 0;
  for (int i = 0; mac_address[i] && j < 12; i++) {
    if (mac_address[i] != ':')
      mac_hex[j++] = mac_address[i];
  }

  char supi[64] = {0};
  snprintf(supi, sizeof(supi), "nai-mac-%s@airport.net", mac_hex);

  fprintf(stderr, "[VUSIM] Provisioning Virtual USIM: MAC=%s SUPI=%s\n",
        mac_address, supi);

  /* 2. Build subscriber JSON */
  char json_body[1024] = {0};
  snprintf(json_body, sizeof(json_body),
    "{"
    "\"plmnID\":\"20893\","
    "\"AuthenticationSubscription\":{"
      "\"authenticationMethod\":\"5G_AKA\","
      "\"permanentKey\":{\"permanentKeyValue\":\"8baf473f2f8fd09487cccbd7097c6862\",\"encryptionKey\":0,\"encryptionAlgorithm\":0},"
      "\"sequenceNumber\":\"000000000000\","
      "\"authenticationManagementField\":\"8000\","
      "\"opc\":{\"opcValue\":\"8e27b6af0e692e750f32667a3b14605d\",\"encryptionKey\":0,\"encryptionAlgorithm\":0}"
    "},"
    "\"AccessAndMobilitySubscriptionData\":{"
      "\"gpsis\":[\"msisdn-0000000000\"],"
      "\"nssai\":{\"defaultSingleNssais\":[{\"sst\":1,\"sd\":\"010203\"}]}"
    "},"
    "\"SessionManagementSubscriptionData\":[{"
      "\"singleNssai\":{\"sst\":1,\"sd\":\"010203\"},"
      "\"dnnConfigurations\":{"
        "\"internet\":{\"sscModes\":{\"defaultSscMode\":\"SSC_MODE_1\"},\"pduSessionTypes\":{\"defaultSessionType\":\"IPV4\"},\"5gQosProfile\":{\"5qi\":9}},"
        "\"isac.airport.net\":{\"sscModes\":{\"defaultSscMode\":\"SSC_MODE_1\"},\"pduSessionTypes\":{\"defaultSessionType\":\"IPV4\"},\"5gQosProfile\":{\"5qi\":5}}"
      "}"
    "}]"
    "}");

  /* 3. POST to Free5GC WebUI API */
  char url[128] = {0};
  snprintf(url, sizeof(url),
           "http://127.0.0.1:5000/subscriber/%s/20893", supi);

  /* Use system curl for simplicity in PoC */
  char cmd[2048] = {0};
  snprintf(cmd, sizeof(cmd),
           "curl -s -X POST '%s' "
           "-H 'Content-Type: application/json' "
           "-d '%s' > /tmp/vusim_provision.log 2>&1 &",
           url, json_body);

  int ret = system(cmd);
  if (ret != 0)
    fprintf(stderr, "[VUSIM] curl command failed for SUPI=%s\n", supi);
  else
    fprintf(stderr, "[VUSIM] Provisioning request sent for SUPI=%s\n", supi);
}

/* ── CRUD ──────────────────────────────────────────────────────────────── */

cpe_ue_entry_t *cpe_ue_add(cpe_ue_table_t *tbl,
                            uint64_t imsi,
                            const uint8_t cpe_mac[CPE_UE_MAC_LEN],
                            const char *cpe_outer_ip,
                            uint16_t    cpe_nat_port,
                            const char *cpe_inner_ip)
{
  cpe_ue_lock(tbl);

  /* If an entry already exists for this IMSI, update it in place */
  cpe_ue_entry_t *slot = NULL;
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    if (tbl->entries[i].valid && tbl->entries[i].imsi == imsi) {
      slot = &tbl->entries[i];
      break;
    }
  }

  /* Otherwise find an empty slot */
  if (!slot) {
    for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
      if (!tbl->entries[i].valid) {
        slot = &tbl->entries[i];
        break;
      }
    }
  }

  if (!slot) {
    cpe_ue_unlock(tbl);
    fprintf(stderr, "[CPE_UE] Table full — cannot add IMSI %llu\n",
            (unsigned long long)imsi);
    return NULL;
  }

  memset(slot, 0, sizeof(*slot));
  slot->imsi        = imsi;
  slot->cpe_nat_port = cpe_nat_port;
  slot->state       = CPE_UE_STATE_HO_IN_PROGRESS;
  slot->active_path = CPE_UE_PATH_CPE;
  slot->valid       = true;

  if (cpe_mac)
    memcpy(slot->cpe_mac, cpe_mac, CPE_UE_MAC_LEN);
    /* Convert binary MAC to human-readable string for ISAC use */
    snprintf(slot->mac_address, sizeof(slot->mac_address),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             cpe_mac[0], cpe_mac[1], cpe_mac[2],
             cpe_mac[3], cpe_mac[4], cpe_mac[5]);
    /* Automatically provision Virtual USIM to Free5GC UDM */
    provision_virtual_usim(slot->mac_address);
  if (cpe_outer_ip)
    strncpy(slot->cpe_outer_ip, cpe_outer_ip, INET_ADDRSTRLEN - 1);
  if (cpe_inner_ip)
    strncpy(slot->cpe_inner_ip, cpe_inner_ip, INET_ADDRSTRLEN - 1);

  /* Always resolve cpe_outer_gtp_ue_id from ue_context.pdu_address so that
   * stale globals (g_outer_cpe_gtp_ue_id) cannot cause writes to the wrong
   * ue_id.  The pdu_address column is the authoritative source for the CPE
   * host's identity, populated by rrc_gNB_process_NGAP_PDUSESSION_SETUP_REQ. */
  if (slot->cpe_outer_ip[0] && g_mysql_ready) {
    MYSQL *conn = cpe_ue_mysql_connect(true);
    if (conn) {
      char esc[INET_ADDRSTRLEN * 2 + 1] = {0};
      mysql_real_escape_string(conn, esc, slot->cpe_outer_ip, strlen(slot->cpe_outer_ip));
      char q[256];
      snprintf(q, sizeof(q),
               "SELECT ue_id,rnti FROM ue_context"
               " WHERE pdu_address='%s' AND pdu_address<>'' LIMIT 1", esc);
      if (!mysql_query(conn, q)) {
        MYSQL_RES *res = mysql_store_result(conn);
        MYSQL_ROW row  = res ? mysql_fetch_row(res) : NULL;
        if (row && row[0]) {
          uint32_t h_ue_id = (uint32_t)strtoul(row[0], NULL, 10);
          uint16_t h_rnti  = row[1] ? (uint16_t)strtoul(row[1], NULL, 10) : 0;
          if (h_ue_id != 0) {
            slot->cpe_outer_gtp_ue_id = h_ue_id;
            slot->cpe_rnti            = h_rnti;
            fprintf(stderr, "[CPE_UE] auto-bound outer CPE host: cpe_outer_gtp_ue_id=%u cpe_rnti=0x%04x\n",
                    h_ue_id, h_rnti);
          }
        }
        if (res) mysql_free_result(res);
      }
      mysql_close(conn);
    }
  }

  cpe_ue_table_persist_locked(tbl);
  cpe_ue_unlock(tbl);

  if (slot->cpe_outer_gtp_ue_id != 0 && slot->cpe_outer_ip[0])
    cpe_ue_mysql_upsert_ue_context(slot->cpe_outer_gtp_ue_id,
                                   slot->cpe_rnti,
                                   slot->cpe_outer_ip,
                                   "CPE_HOST");
  return slot;
}

static void remove_entry(cpe_ue_entry_t *e)
{
  memset(e, 0, sizeof(*e));
  /* valid = false already from memset */
}

void cpe_ue_remove_by_rnti(cpe_ue_table_t *tbl, uint16_t rnti)
{
  char where[64];
  snprintf(where, sizeof(where), "rnti=%u", rnti);
  cpe_ue_mysql_delete_where(where);
  cpe_ue_lock(tbl);
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++)
    if (tbl->entries[i].valid && tbl->entries[i].rnti == rnti)
      remove_entry(&tbl->entries[i]);
  cpe_ue_unlock(tbl);
}

void cpe_ue_remove_by_imsi(cpe_ue_table_t *tbl, uint64_t imsi)
{
  char where[96];
  snprintf(where, sizeof(where), "imsi=%llu", (unsigned long long)imsi);
  cpe_ue_mysql_delete_where(where);
  cpe_ue_lock(tbl);
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++)
    if (tbl->entries[i].valid && tbl->entries[i].imsi == imsi)
      remove_entry(&tbl->entries[i]);
  cpe_ue_unlock(tbl);
}

/* ── Locked lookups ────────────────────────────────────────────────────── */

cpe_ue_entry_t *cpe_ue_find_by_rnti_locked(cpe_ue_table_t *tbl, uint16_t rnti)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++)
    if (tbl->entries[i].valid && tbl->entries[i].rnti == rnti)
      return &tbl->entries[i];
  return NULL;
}

cpe_ue_entry_t *cpe_ue_find_by_imsi_locked(cpe_ue_table_t *tbl, uint64_t imsi)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++)
    if (tbl->entries[i].valid && tbl->entries[i].imsi == imsi)
      return &tbl->entries[i];
  return NULL;
}

cpe_ue_entry_t *cpe_ue_find_by_inner_ip_locked(cpe_ue_table_t *tbl,
                                                const char *inner_ip)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid && inner_ip
        && strncmp(e->cpe_inner_ip, inner_ip, INET_ADDRSTRLEN) == 0)
      return e;
  }
  return NULL;
}

cpe_ue_entry_t *cpe_ue_find_by_pdu_ip_locked(cpe_ue_table_t *tbl,
                                              const char *pdu_ip)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid && pdu_ip
        && strncmp(e->pdu_session_ip, pdu_ip, INET_ADDRSTRLEN) == 0)
      return e;
  }
  return NULL;
}

void cpe_ue_table_register_outer_cpe(uint16_t cpe_rnti, uint32_t outer_gtp_ue_id)
{
  /* Keep the latest outer CPE identity for debug/history, but bind entries
   * only by the UE PDU address.  Multiple CPE hosts may be alive at once. */
  g_outer_cpe_rnti      = cpe_rnti;
  g_outer_cpe_gtp_ue_id = outer_gtp_ue_id;

  char host_pdu[INET_ADDRSTRLEN] = {0};
  bool have_host_pdu = cpe_ue_lookup_host_pdu_address(outer_gtp_ue_id,
                                                       host_pdu,
                                                       sizeof(host_pdu));
  if (!have_host_pdu) {
    fprintf(stderr,
            "[CPE table] outer CPE ue_id=%u rnti=0x%04x has no PDU address yet; defer CPE_UE binding\n",
            outer_gtp_ue_id, cpe_rnti);
    return;
  }

  cpe_ue_table_t *tbl = cpe_ue_table_get();
  cpe_ue_lock(tbl);
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid
        && strncmp(e->cpe_outer_ip, host_pdu, INET_ADDRSTRLEN) == 0) {
      e->cpe_rnti            = cpe_rnti;
      e->cpe_outer_gtp_ue_id = outer_gtp_ue_id;
      cpe_ue_mysql_upsert_ue_context(outer_gtp_ue_id, cpe_rnti, e->cpe_outer_ip, "CPE_HOST");
      fprintf(stderr, "[CPE table] outer CPE RNTI 0x%04x gtp_ue_id=%u registered for IMSI %llu\n",
              cpe_rnti, outer_gtp_ue_id, (unsigned long long)e->imsi);
    }
  }
  cpe_ue_table_persist_locked(tbl);
  cpe_ue_unlock(tbl);
}

cpe_ue_entry_t *cpe_ue_find_by_outer_ip_locked(cpe_ue_table_t *tbl,
                                                const char *outer_ip,
                                                uint16_t nat_port)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid
        && strncmp(e->cpe_outer_ip, outer_ip, INET_ADDRSTRLEN) == 0
        && e->cpe_nat_port == nat_port)
      return e;
  }
  return NULL;
}

cpe_ue_entry_t *cpe_ue_find_by_outer_ip_any_locked(cpe_ue_table_t *tbl,
                                                    const char *outer_ip)
{
  for (int i = 0; i < CPE_UE_MAX_ENTRIES; i++) {
    cpe_ue_entry_t *e = &tbl->entries[i];
    if (e->valid && outer_ip
        && strncmp(e->cpe_outer_ip, outer_ip, INET_ADDRSTRLEN) == 0)
      return e;
  }
  return NULL;
}

bool cpe_ue_sync_to_cuup(const cpe_ue_entry_t *entry)
{
  if (!entry || !entry->valid)
    return false;

  const char *host = getenv("CPE_CUUP_REST_HOST");
  if (!host || host[0] == '\0')
    host = "127.0.0.1";

  const char *port_env = getenv("CPE_CUUP_REST_PORT");
  int port = (port_env && port_env[0]) ? atoi(port_env) : 8888;
  if (port <= 0 || port > 65535)
    port = 8888;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return false;

  struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    close(fd);
    return false;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return false;
  }

  char json[1024];
  int json_len = snprintf(json, sizeof(json),
                          "{\"imsi\":\"%llu\",\"rnti\":\"0x%04x\","
                          "\"cpe_outer_ip\":\"%s\",\"cpe_nat_port\":%u,"
                          "\"cpe_rnti\":\"0x%04x\","
                          "\"cpe_inner_ip\":\"%s\",\"pdu_session_ip\":\"%s\","
                          "\"active_path\":\"%s\",\"gtp_ue_id\":%u,"
                          "\"cpe_outer_gtp_ue_id\":%u}",
                          (unsigned long long)entry->imsi,
                          entry->rnti,
                          entry->cpe_outer_ip,
                          entry->cpe_nat_port,
                          entry->cpe_rnti,
                          entry->cpe_inner_ip,
                          entry->pdu_session_ip,
                          cpe_ue_path_name(entry->active_path),
                          entry->gtp_ue_id,
                          entry->cpe_outer_gtp_ue_id);
  if (json_len <= 0 || json_len >= (int)sizeof(json)) {
    close(fd);
    return false;
  }

  char req[1400];
  int req_len = snprintf(req, sizeof(req),
                         "POST /cpe_ue/update HTTP/1.1\r\n"
                         "Host: %s:%d\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: close\r\n\r\n"
                         "%s",
                         host, port, json_len, json);
  if (req_len <= 0 || req_len >= (int)sizeof(req)) {
    close(fd);
    return false;
  }

  ssize_t sent = send(fd, req, (size_t)req_len, 0);
  char resp[128];
  ssize_t nr = recv(fd, resp, sizeof(resp) - 1, 0);
  close(fd);
  return sent == req_len && nr > 0 && strstr(resp, "200 OK") != NULL;
}
