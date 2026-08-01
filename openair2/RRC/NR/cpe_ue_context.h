/*
 * CPE UE Mapping Table
 *
 * Tracks CPE_UE entries that transition from WiFi-only to NR_CONNECTED
 * via the /api/cpe_handover REST trigger.
 *
 * A CPE_UE is a device behind the CPE (a 5G NR UE acting as WiFi AP).
 * Once the HO is triggered, the CPE_UE gets its own NR identity (RNTI)
 * without going through a full RACH — the CU injects the context directly.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_UE_MAX_ENTRIES  64
#define CPE_UE_MAC_LEN       6
#define CPE_UE_IMSI_STRLEN  16   /* "460001234567890\0" */

typedef enum {
  CPE_UE_STATE_WIFI_ONLY = 0,
  CPE_UE_STATE_HO_IN_PROGRESS,
  CPE_UE_STATE_NR_CONNECTED,
} cpe_ue_state_e;

typedef enum {
  CPE_UE_PATH_CPE = 0, /* traffic is still served through the outer CPE UE */
  CPE_UE_PATH_RU,      /* traffic is served by the CPE_UE's own NR bearer */
} cpe_ue_path_e;

typedef struct {
  /* NR identity assigned by CU to CPE_UE */
  uint16_t rnti;               /* C-RNTI allocated for CPE_UE; 0 = not yet assigned */
  uint64_t imsi;               /* IMSI/SUPI as integer (e.g. 460001234567890) */

  /* CPE physical identity */
  uint8_t  cpe_mac[CPE_UE_MAC_LEN];
  char     cpe_inner_ip[INET_ADDRSTRLEN]; /* LAN side, 192.168.x.x */
  char     cpe_outer_ip[INET_ADDRSTRLEN]; /* WAN side (NR GTP-U endpoint) */
  uint16_t cpe_nat_port;

  /* Cross-reference to the CPE device's own NR context */
  uint16_t cpe_rnti;           /* CPE's own C-RNTI on the RU */

  /* PDU session assigned to CPE_UE after NR attach */
  char     pdu_session_ip[INET_ADDRSTRLEN]; /* e.g. 10.60.0.x */

  /* Forwarding decision owned by CU/CU-UP */
  cpe_ue_path_e active_path;

  /* rrc_ue_id == gNB_cu_cp_ue_id == ue_id used in CU-UP GTP-U tables.
   * Set when the PDU session is established (rrc_gNB_cpe_nas.c) and
   * synced to CU-UP so GtpuUpdateTunnelOutgoingAddressAndTeid can match. */
  uint32_t gtp_ue_id;

  /* CU-UP ue_id of the OUTER CPE UE (the 5G UE acting as WiFi AP).
   * Kept for history/debug correlation only. Post-HO forwarding must use the
   * CPE_UE's own GTP-U + SDAP/PDCP bearer path, not the outer CPE bearer. */
  uint32_t cpe_outer_gtp_ue_id;

  /* N3 incoming TEID allocated by newGtpuCreateTunnel for the CPE_UE's
   * PDU session.  Used at DL time to find the PDCP callback via
   * te2ue_mapping so the DL packet goes through proper PDCP → F1-U. */
  uint32_t gtp_n3_incoming_teid;

  /* GTP-U F1-U forwarding info (populated in CU-UP when DU's TEID arrives).
   * Used for DL forwarding when active_path == RU. */
  int      gtp_instance;
  uint32_t gtp_outgoing_teid;
  char     gtp_remote_ipv4[INET_ADDRSTRLEN];
  bool     gtp_ready;

  /* ICMP NAT state for ping continuity through the CPE outer tunnel */
  uint16_t last_icmp_id;
  uint16_t last_icmp_nat_id;
  bool     has_icmp_nat;

  /* Lightweight datapath counters */
  uint64_t ul_packets;
  uint64_t dl_packets;

   /* MAC address of the N3D device (WiFi client behind CPE) */
  char     mac_address[18];    /* format: "AA:BB:CC:DD:EE:FF\0" */

  /* ISAC service authorization flag */
  int      isac_authorized;    /* 0 = not authorized, 1 = authorized for ISAC */

  cpe_ue_state_e state;
  bool     valid;              /* slot in use */
} cpe_ue_entry_t;

typedef struct {
  cpe_ue_entry_t entries[CPE_UE_MAX_ENTRIES];
  pthread_mutex_t lock;
} cpe_ue_table_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */
void cpe_ue_table_init(cpe_ue_table_t *tbl);
void cpe_ue_table_destroy(cpe_ue_table_t *tbl);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

/*
 * Add a new entry.  Returns pointer to the allocated slot (table is still
 * locked by the caller if needed externally), or NULL if the table is full.
 * Caller must hold no lock; the function acquires it internally.
 */
cpe_ue_entry_t *cpe_ue_add(cpe_ue_table_t *tbl,
                            uint64_t imsi,
                            const uint8_t cpe_mac[CPE_UE_MAC_LEN],
                            const char *cpe_outer_ip,
                            uint16_t    cpe_nat_port,
                            const char *cpe_inner_ip);

void cpe_ue_remove_by_rnti(cpe_ue_table_t *tbl, uint16_t rnti);
void cpe_ue_remove_by_imsi(cpe_ue_table_t *tbl, uint64_t imsi);

/* ── Lookups (return pointer valid only under lock) ──────────────────────── */

/* Acquire the table lock — caller must call cpe_ue_unlock() when done. */
void cpe_ue_lock(cpe_ue_table_t *tbl);
void cpe_ue_unlock(cpe_ue_table_t *tbl);

/* Persist the current in-memory table to MySQL. Caller must hold the lock. */
void cpe_ue_table_persist_locked(cpe_ue_table_t *tbl);

/* Must be called with lock held. */
cpe_ue_entry_t *cpe_ue_find_by_rnti_locked(cpe_ue_table_t *tbl, uint16_t rnti);
cpe_ue_entry_t *cpe_ue_find_by_imsi_locked(cpe_ue_table_t *tbl, uint64_t imsi);
cpe_ue_entry_t *cpe_ue_find_by_inner_ip_locked(cpe_ue_table_t *tbl,
                                                const char *inner_ip);
cpe_ue_entry_t *cpe_ue_find_by_pdu_ip_locked(cpe_ue_table_t *tbl,
                                              const char *pdu_ip);
cpe_ue_entry_t *cpe_ue_find_by_outer_ip_locked(cpe_ue_table_t *tbl,
                                                const char *outer_ip,
                                                uint16_t nat_port);
cpe_ue_entry_t *cpe_ue_find_by_outer_ip_any_locked(cpe_ue_table_t *tbl,
                                                    const char *outer_ip);

const char *cpe_ue_state_name(cpe_ue_state_e state);
const char *cpe_ue_path_name(cpe_ue_path_e path);

/* Best-effort sync from CU-CP's in-memory table to CU-UP/GTP-U's table.
 * Destination defaults to 127.0.0.1:8888 and can be overridden with:
 *   CPE_CUUP_REST_HOST=<ip-or-host>
 *   CPE_CUUP_REST_PORT=<port>
 */
bool cpe_ue_sync_to_cuup(const cpe_ue_entry_t *entry);

/* ── Global singleton used by RRC and GTP-U ─────────────────────────────── */
cpe_ue_table_t *cpe_ue_table_get(void);

/*
 * Called when the outer CPE device's PDU session becomes ESTABLISHED.
 * Writes cpe_rnti into every valid table entry that still has cpe_rnti == 0,
 * so that cpe_drb_setup() can find the outer UE directly without scanning
 * the RRC UE tree.
 */
/* outer_gtp_ue_id = the outer CPE UE's rrc_ue_id (= CU-UP ue_id). */
void cpe_ue_table_register_outer_cpe(uint16_t cpe_rnti, uint32_t outer_gtp_ue_id);

/* Persist/update one generic NR UE bearer identity row. Used for CPE host
 * rows where pdu_address is learned from CPE_UE ownership registration. */
void cpe_ue_table_upsert_ue_context(uint32_t ue_id,
                                     uint16_t rnti,
                                     const char *pdu_address,
                                     const char *role);

/* Look up the CPE host's PDU address from ue_context.
 * If host_ue_id != 0, queries WHERE ue_id=host_ue_id; otherwise queries
 * WHERE role='CPE_HOST'. Writes result into out (INET_ADDRSTRLEN).
 * Returns true if a non-empty address was found. */
bool cpe_ue_lookup_host_pdu_address(uint32_t host_ue_id, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
