/*
 * Depth B: CU-local 5GC proxy NAS state machine for CPE_UE.
 * See rrc_gNB_cpe_nas.h for the full description and state diagram.
 */

#include "rrc_gNB_cpe_nas.h"
#include "nr_rrc_proto.h"
#include "cpe_ue_context.h"
#include "rrc_gNB_UE_context.h"
#include "common/utils/LOG/log.h"
#include "common/utils/utils.h"
#include "assertions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <arpa/inet.h>

/* ── CPE_UE PDU session IP pool: 10.61.0.2 – 10.61.0.254 ───────────────── */
#define CPE_PDU_IP_BASE   0x0A3D0002u  /* 10.61.0.2 in host byte order */
#define CPE_PDU_IP_LAST   0x0A3D00FEu  /* 10.61.0.254 */

static _Atomic uint32_t g_next_ip = CPE_PDU_IP_BASE;

static uint32_t alloc_pdu_ip(void)
{
  uint32_t ip = atomic_fetch_add(&g_next_ip, 1);
  if (ip > CPE_PDU_IP_LAST) {
    /* wrap — crude but acceptable for ≤252 CPE_UEs in a demo */
    atomic_store(&g_next_ip, CPE_PDU_IP_BASE);
    ip = CPE_PDU_IP_BASE;
  }
  return ip; /* host byte order */
}

/* ── NAS constants ──────────────────────────────────────────────────────── */
#define NAS_5GMM_EPD            0x7eu
#define NAS_PLAIN_HDR           0x00u
#define NAS_INT_NEW_CTX_HDR     0x03u
#define NAS_5GMM_REG_ACCEPT     0x42u
#define NAS_5GMM_REG_COMPLETE   0x43u
#define NAS_5GMM_UL_NAS_XPORT   0x67u
#define NAS_5GSM_EPD            0x2eu
#define NAS_5GSM_PDU_EST_REQ    0xc1u
#define NAS_5GMM_DL_NAS_XPORT   0x68u
#define NAS_5GSM_PDU_EST_ACC    0xc2u

/* Offsets within the full NAS PDU (security protected outer + plain inner) */
#define NAS_SP_HDR_LEN          7   /* EPD(1)+sec_hdr(1)+MAC(4)+SN(1) */
#define NAS_MM_HDR_LEN          3   /* EPD(1)+sec_hdr(1)+msg_type(1)  */
#define NAS_INNER_MSG_TYPE_OFF  (NAS_SP_HDR_LEN + 2)   /* offset 9 (sec-protected) */
#define NAS_PLAIN_MSG_TYPE_OFF  2                        /* offset 2 (plain) */
/* UL NAS Transport payload starts at offset 10 (SP) or 3 (plain): */
#define NAS_5GSM_MSG_TYPE_SP    16  /* SP: [7]EPD [8]sec [9]msg [10]ct [11-12]len [13]5GSM-EPD [14]PSI [15]PTI [16]5GSM-msg */
#define NAS_5GSM_MSG_TYPE_PLAIN 9   /* plain: [0]EPD [1]sec [2]msg [3]ct [4-5]len [6]5GSM-EPD [7]PSI [8]PTI [9]5GSM-msg */

/* ── send helpers ────────────────────────────────────────────────────────── */

/* Write a 7-byte dummy security protected header (MAC=0, SN=0).
 * Use security header type 0x03 so the OAI UE decodes the inner 5GMM
 * message at offset 9. If this is 0x00, the UE treats byte 2 as the plain
 * message type and never processes Registration Accept / DL NAS Transport. */
static int write_sp_hdr(uint8_t *buf)
{
  buf[0] = NAS_5GMM_EPD;
  buf[1] = NAS_INT_NEW_CTX_HDR;
  memset(buf + 2, 0, 4); /* MAC = 0 (NIA0) */
  buf[6] = 0x00;          /* SN = 0 */
  return NAS_SP_HDR_LEN;
}

/* Write a plain 5GMM header. */
static int write_mm_hdr(uint8_t *buf, uint8_t msg_type)
{
  buf[0] = NAS_5GMM_EPD;
  buf[1] = NAS_PLAIN_HDR;
  buf[2] = msg_type;
  return NAS_MM_HDR_LEN;
}

/* ── Registration Accept ─────────────────────────────────────────────────── */

static void send_registration_accept(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE)
{
  uint8_t pdu[64];
  int off = 0;

  /* Security protected header */
  off += write_sp_hdr(pdu + off);
  /* Plain 5GMM header */
  off += write_mm_hdr(pdu + off, NAS_5GMM_REG_ACCEPT);

  /* 5GS registration result (M, LV): length=1, value=0x01 3GPP access */
  pdu[off++] = 0x01;
  pdu[off++] = 0x01; /* 3GPP access, SMS not allowed */

  /* 5G-GUTI (O, TLV-E): IEI=0x77, 11 bytes of content.
   * Required for UE to decode Registration Accept and send Registration Complete.
   * Format: spare(1111)|type(0010=GUTI)=0xF2 | PLMN(3) | AMF-RegionID(1) |
   *         AMF-SetID(10b)+AMF-Ptr(6b)(2) | 5G-TMSI(4) */
  pdu[off++] = 0x77;         /* IEI */
  pdu[off++] = 0x00;         /* length MSB */
  pdu[off++] = 0x0B;         /* length LSB = 11 */
  pdu[off++] = 0xF2;         /* spare=1111 | identity_type=0010 (5G-GUTI) */
  /* PLMN: MCC=208 MNC=93 → bytes 0x02 0xF8 0x39 */
  pdu[off++] = 0x02;
  pdu[off++] = 0xF8;
  pdu[off++] = 0x39;
  pdu[off++] = 0x01;         /* AMF Region ID = 1 */
  pdu[off++] = 0x00;         /* AMF Set ID high (Set=1→upper 8bits of 10b field) */
  pdu[off++] = 0x40;         /* AMF Set ID low (2b) + AMF Pointer (6b=0) = 0x40 */
  /* 5G-TMSI = lower 32 bits of IMSI for uniqueness */
  uint32_t tmsi = (uint32_t)(UE->imsi & 0xFFFFFFFFu);
  pdu[off++] = (tmsi >> 24) & 0xFF;
  pdu[off++] = (tmsi >> 16) & 0xFF;
  pdu[off++] = (tmsi >>  8) & 0xFF;
  pdu[off++] =  tmsi        & 0xFF;

  /* Allowed NSSAI IEI=0x15, S-NSSAI list length=5, item_len=4,
   * SST=1, SD=0x010203. This must match the UE SIM/NAS config or the UE
   * will not request a PDU session after Registration Accept. */
  pdu[off++] = 0x15;
  pdu[off++] = 0x05;
  pdu[off++] = 0x04;
  pdu[off++] = 0x01; /* SST = 1 (eMBB) */
  pdu[off++] = 0x01;
  pdu[off++] = 0x02;
  pdu[off++] = 0x03; /* SD = 0x010203 */

  /* Hand the NAS PDU to rrc_forward_ue_nas_message */
  UE->nas_pdu.buf = malloc(off);
  if (!UE->nas_pdu.buf) {
    LOG_E(NR_RRC, "[CPE NAS] malloc failed for Registration Accept\n");
    return;
  }
  memcpy(UE->nas_pdu.buf, pdu, off);
  UE->nas_pdu.len = off;
  rrc_forward_ue_nas_message(rrc, UE);

  LOG_I(NR_RRC, "[CPE NAS] UE %u: sent Registration Accept (IMSI %llu)\n",
        UE->rrc_ue_id, (unsigned long long)UE->imsi);
}

/* ── DRB setup for CPE_UE ────────────────────────────────────────────────── */

static void cpe_drb_setup(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE, uint8_t pdu_session_id)
{
  /* Find the outer CPE UE and borrow its UPF (n3_incoming) GTP-U endpoint.
   * First try cpe_rnti from the table — it is written by
   * cpe_ue_table_register_outer_cpe() when the outer CPE UE's PDU session
   * becomes ESTABLISHED (called from rrc_gNB_send_NGAP_PDUSESSION_SETUP_RESP).
   * If still unset, fall back to scanning the RRC UE tree. */
  gNB_RRC_UE_t *cpe_outer = NULL;
  gtpu_tunnel_t n3_in = {0};

  /* --- Try explicit cpe_rnti from table --- */
  {
    cpe_ue_table_t *tbl = cpe_ue_table_get();
    cpe_ue_lock(tbl);
    cpe_ue_entry_t *e = cpe_ue_find_by_imsi_locked(tbl, UE->imsi);
    uint16_t cpe_rnti = (e && e->valid) ? e->cpe_rnti : 0;
    cpe_ue_unlock(tbl);

    if (cpe_rnti != 0) {
      rrc_gNB_ue_context_t *ctx = rrc_gNB_get_ue_context_by_rnti_any_du(rrc, cpe_rnti);
      if (ctx)
        cpe_outer = &ctx->ue_context;
    }
  }

  /* --- Fallback: scan RRC tree for first outer UE with established PDU session --- */
  if (!cpe_outer) {
    rrc_gNB_ue_context_t *ue_ctx_p;
    RB_FOREACH(ue_ctx_p, rrc_nr_ue_tree_s, &rrc->rrc_ue_head) {
      gNB_RRC_UE_t *cand = &ue_ctx_p->ue_context;
      if (cand->is_cpe_ue) continue;
      for (int i = 0; i < cand->nb_of_pdusessions; i++) {
        if (cand->pduSession[i].status == PDU_SESSION_STATUS_ESTABLISHED) {
          cpe_outer = cand;
          n3_in     = cand->pduSession[i].param.n3_incoming;
          break;
        }
      }
      if (cpe_outer) break;
    }
    if (cpe_outer)
      LOG_I(NR_RRC, "[CPE NAS] UE %u: auto-selected outer CPE UE RNTI %u\n",
            UE->rrc_ue_id, cpe_outer->rnti);
  }

  if (!cpe_outer) {
    LOG_W(NR_RRC,
          "[CPE NAS] UE %u: no outer CPE UE with established PDU session — DRB setup skipped\n",
          UE->rrc_ue_id);
    return;
  }

  /* If n3_in was not filled by the scan (explicit cpe_rnti path), find it now. */
  if (n3_in.teid == 0) {
    bool found = false;
    for (int i = 0; i < cpe_outer->nb_of_pdusessions; i++) {
      if (cpe_outer->pduSession[i].status == PDU_SESSION_STATUS_ESTABLISHED) {
        n3_in = cpe_outer->pduSession[i].param.n3_incoming;
        found = true;
        break;
      }
    }
    if (!found) {
      LOG_W(NR_RRC,
            "[CPE NAS] UE %u: outer CPE UE RNTI %u has no established PDU session — DRB setup skipped\n",
            UE->rrc_ue_id, cpe_outer->rnti);
      return;
    }
  }

  /* Inherit NSSAI from the outer CPE's PDU session so E2SM-KPM condition
   * matching (which checks ue->pduSession[p].param.nssai) works correctly. */
  nssai_t outer_nssai = {.sst = 1, .sd = 0xffffff};
  for (int _i = 0; _i < cpe_outer->nb_of_pdusessions; _i++) {
    if (cpe_outer->pduSession[_i].status == PDU_SESSION_STATUS_ESTABLISHED) {
      outer_nssai = cpe_outer->pduSession[_i].param.nssai;
      break;
    }
  }

  /* Synthesize a pdusession_t for CPE_UE sharing the outer CPE UE's UPF endpoint.
   * 5QI-9 non-GBR is the standard default bearer. */
  pdusession_t synth = {0};
  synth.pdusession_id    = pdu_session_id;
  synth.pdu_session_type = PDUSessionType_ipv4;
  synth.nssai            = outer_nssai;
  synth.nb_qos           = 1;
  synth.n3_incoming      = n3_in;
  synth.qos[0].qfi                = 1;
  synth.qos[0].fiveQI             = 9;
  synth.qos[0].fiveQI_type        = NON_DYNAMIC;
  synth.qos[0].qos_priority       = 9;
  synth.qos[0].allocation_retention_priority.priority_level    = NGAP_PRIORITY_LEVEL_8;
  synth.qos[0].allocation_retention_priority.pre_emp_capability   =
      NGAP_PRE_EMPTION_CAPABILITY_SHALL_NOT_TRIGGER_PREEMPTION;
  synth.qos[0].allocation_retention_priority.pre_emp_vulnerability =
      NGAP_PRE_EMPTION_VULNERABILITY_NOT_PREEMPTABLE;

  /* Use the "initial PDU setup" code path so the RRCReconfigurationComplete
   * handler can clean up initial_pdus correctly. */
  if (UE->initial_pdus) {
    free(UE->initial_pdus);
    UE->initial_pdus  = NULL;
    UE->n_initial_pdu = 0;
  }
  UE->initial_pdus    = calloc_or_fail(1, sizeof(*UE->initial_pdus));
  UE->initial_pdus[0] = synth;
  UE->n_initial_pdu   = 1;

  if (!trigger_bearer_setup(rrc, UE, 1, UE->initial_pdus, 0)) {
    LOG_W(NR_RRC, "[CPE NAS] UE %u: trigger_bearer_setup failed (CU-UP not ready?)\n",
          UE->rrc_ue_id);
    free(UE->initial_pdus);
    UE->initial_pdus  = NULL;
    UE->n_initial_pdu = 0;
    return;
  }

  LOG_I(NR_RRC,
        "[CPE NAS] UE %u IMSI %llu: DRB setup triggered PSI=%u via outer RNTI=%u\n",
        UE->rrc_ue_id, (unsigned long long)UE->imsi, pdu_session_id, cpe_outer->rnti);
}

/* ── PDU Session Establishment Accept ───────────────────────────────────── */

static void send_pdu_session_accept(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE,
                                    uint8_t pdu_session_id, uint8_t pti)
{
  /* Prefer the original LAN-side UE IP for IP continuity. If the CPE_UE
   * entry has no cpe_inner_ip, fall back to the local demo pool. */
  uint32_t ip_host = 0;
  uint32_t ip_net = 0;
  struct in_addr ia = {0};
  char ip_str[INET_ADDRSTRLEN];
  bool used_inner_ip = false;

  cpe_ue_table_t *tbl = cpe_ue_table_get();
  cpe_ue_entry_t sync_entry = {0};
  bool need_cuup_sync = false;
  cpe_ue_lock(tbl);
  cpe_ue_entry_t *e = cpe_ue_find_by_rnti_locked(tbl, UE->rnti);
  if (e && e->cpe_inner_ip[0] != '\0' && inet_pton(AF_INET, e->cpe_inner_ip, &ia) == 1) {
    ip_net = ia.s_addr;
    ip_host = ntohl(ip_net);
    snprintf(ip_str, sizeof(ip_str), "%s", e->cpe_inner_ip);
    used_inner_ip = true;
  } else {
    ip_host = alloc_pdu_ip();
    ip_net = htonl(ip_host);
    ia.s_addr = ip_net;
    inet_ntop(AF_INET, &ia, ip_str, sizeof(ip_str));
  }

  /* Store the PDU-session IP in the CPE_UE table for GTP-U mapping. */
  if (e) {
    snprintf(e->pdu_session_ip, sizeof(e->pdu_session_ip), "%s", ip_str);
    e->state = CPE_UE_STATE_NR_CONNECTED;
    e->active_path = CPE_UE_PATH_RU;
    e->gtp_ue_id = UE->rrc_ue_id;  /* CU-UP uses this to match GTP-U bearer */
    sync_entry = *e;
    need_cuup_sync = true;
    cpe_ue_table_persist_locked(tbl);
  }
  cpe_ue_unlock(tbl);

  if (need_cuup_sync) {
    if (cpe_ue_sync_to_cuup(&sync_entry))
      LOG_I(NR_RRC, "[CPE NAS] UE %u: synced CPE_UE table to CU-UP\n", UE->rrc_ue_id);
    else
      LOG_W(NR_RRC, "[CPE NAS] UE %u: failed to sync CPE_UE table to CU-UP\n", UE->rrc_ue_id);
  }

  /* Build DL NAS Transport carrying PDU Session Establishment Accept.
   *
   * Layout (verify pdu[16] == 0xc2 per OAI UE parser):
   * [0-6]  : security protected header (7 bytes)
   * [7-9]  : plain 5GMM header EPD+sec+DL_NAS_XPORT (3 bytes)
   * [10]   : payload container type = 0x01 (N1 SM info) (1 byte)
   * [11-12]: payload container length big-endian (2 bytes)
   * [13]   : 5GSM EPD = 0x2e (1 byte)
   * [14]   : PDU session ID (1 byte)
   * [15]   : PTI (1 byte)
   * [16]   : 5GSM message type = 0xc2 ← checked by OAI UE
   * [17]   : PDU type(hi nibble SSC mode) | PDU type(lo nibble)
   * [18-19]: QoS rules length (2 bytes)
   * [20-25]: QoS rule (6 bytes: id=1, len=3, oc/dqr/nb_pf, prec, qfi)
   * [26]   : Session-AMBR length (1 byte)
   * [27-32]: Session-AMBR content (6 bytes)
   * [33]   : PDU address IEI = 0x29
   * [34]   : PDU address length = 5
   * [35]   : PDU address type = 0x01 (IPv4)
   * [36-39]: IPv4 address
   * total  : 40 bytes
   */

  uint8_t pdu[64];
  int off = 0;

  /* Security protected header */
  off += write_sp_hdr(pdu + off);
  /* Plain 5GMM DL NAS Transport header */
  off += write_mm_hdr(pdu + off, NAS_5GMM_DL_NAS_XPORT);

  /* Payload container type: N1 SM info = 0x01 */
  pdu[off++] = 0x01;

  /* Container length placeholder (fill later) */
  int clen_off = off;
  pdu[off++] = 0x00;
  pdu[off++] = 0x00;

  /* --- 5GSM container content starts here --- */
  int container_start = off;

  /* 5GSM header */
  pdu[off++] = NAS_5GSM_EPD;        /* EPD = 5GSM */
  pdu[off++] = pdu_session_id;
  pdu[off++] = pti;
  pdu[off++] = NAS_5GSM_PDU_EST_ACC;

  /* PDU type (lower nibble) + SSC mode (upper nibble): IPv4=1, SSC=1 */
  pdu[off++] = 0x11;

  /* Authorized QoS rules (M): length=6 + one default rule */
  pdu[off++] = 0x00; pdu[off++] = 0x06; /* QoS rules IE length = 6 */
  pdu[off++] = 0x01;                     /* QoS rule ID = 1 */
  pdu[off++] = 0x00; pdu[off++] = 0x03; /* rule content length = 3 */
  /* oc=create_new(001) | dqr=1(1) | nb_pf=0(0000) = 0b00110000 = 0x30 */
  pdu[off++] = 0x30;
  pdu[off++] = 0xff;                     /* precedence (default = highest) */
  pdu[off++] = 0x01;                     /* QFI = 1 */

  /* Session-AMBR (M): 100 Mbps DL/UL, unit 0x05 = 1 Mbps */
  pdu[off++] = 0x06;              /* AMBR content length = 6 */
  pdu[off++] = 0x05;              /* DL unit */
  pdu[off++] = 0x00; pdu[off++] = 0x64; /* DL = 100 Mbps */
  pdu[off++] = 0x05;              /* UL unit */
  pdu[off++] = 0x00; pdu[off++] = 0x64; /* UL = 100 Mbps */

  /* PDU Address (O): IPv4 */
  pdu[off++] = 0x29;              /* IEI */
  pdu[off++] = 0x05;              /* length = 5 */
  pdu[off++] = 0x01;              /* PDU address type = IPv4 */
  memcpy(pdu + off, &ip_net, 4);
  off += 4;

  /* Fill container length */
  uint16_t clen = (uint16_t)(off - container_start);
  pdu[clen_off]     = (clen >> 8) & 0xff;
  pdu[clen_off + 1] = clen & 0xff;

  /* Sanity: OAI UE checks pdu[16] == FGS_PDU_SESSION_ESTABLISHMENT_ACC */
  AssertFatal(pdu[16] == NAS_5GSM_PDU_EST_ACC,
              "[CPE NAS] DL NAS layout error: pdu[16]=%02x != 0xc2\n", pdu[16]);

  /* Allocate one extra byte set to 0x00: the OAI UE NAS decoder
   * (decode_pdu_session_establishment_accept_msg) passes the full PDU
   * length instead of the 5GSM-content length, causing a 1-byte overread.
   * The extra 0x00 hits the default switch case which safely exits the loop. */
  UE->nas_pdu.buf = malloc(off + 1);
  if (!UE->nas_pdu.buf) {
    LOG_E(NR_RRC, "[CPE NAS] malloc failed for PDU Session Accept\n");
    return;
  }
  memcpy(UE->nas_pdu.buf, pdu, off);
  UE->nas_pdu.buf[off] = 0x00;
  UE->nas_pdu.len = off;
  rrc_forward_ue_nas_message(rrc, UE);

  LOG_I(NR_RRC,
        "[CPE NAS] UE %u IMSI %llu: sent PDU Session Establishment Accept"
        " ip=%s%s psi=%u pti=%u\n",
        UE->rrc_ue_id, (unsigned long long)UE->imsi,
        ip_str, used_inner_ip ? " (cpe_inner_ip)" : "", pdu_session_id, pti);

  /* NAS is complete — trigger DRB setup to give CPE_UE a data radio bearer. */
  cpe_drb_setup(rrc, UE, pdu_session_id);
}

/* ── UL NAS Transport parser ─────────────────────────────────────────────── */

static void handle_ul_nas_transport(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE,
                                    const uint8_t *buf, size_t len)
{
  /* Detect plain vs security-protected NAS (buf[1] == 0x00 → plain).
   * After SecurityModeFailure the UE has no NAS security context and sends
   * plain NAS messages.
   *
   * Security-protected UL NAS Transport layout (len >= 17):
   *   [0-6]  SP header  [7]EPD [8]sec [9]=0x65  [10]ct [11-12]len
   *   [13]5GSM-EPD  [14]PSI  [15]PTI  [16]5GSM-msg
   *
   * Plain UL NAS Transport layout (len >= 10):
   *   [0]EPD [1]=0x00 [2]=0x65  [3]ct [4-5]len
   *   [6]5GSM-EPD  [7]PSI  [8]PTI  [9]5GSM-msg
   */
  bool plain = (len >= 2 && buf[1] == NAS_PLAIN_HDR);
  size_t min_len    = plain ? 10 : 17;
  uint8_t sm_msg_type_off = plain ? (uint8_t)NAS_5GSM_MSG_TYPE_PLAIN
                                   : (uint8_t)NAS_5GSM_MSG_TYPE_SP;
  uint8_t psi_off   = plain ? 7 : 14;
  uint8_t pti_off   = plain ? 8 : 15;

  if (len < min_len) {
    LOG_W(NR_RRC,
          "[CPE NAS] UE %u: UL NAS Transport too short (%zu, plain=%d)\n",
          UE->rrc_ue_id, len, (int)plain);
    return;
  }

  uint8_t sm_msg_type     = buf[sm_msg_type_off];
  uint8_t pdu_session_id  = buf[psi_off];
  uint8_t pti             = buf[pti_off];

  switch (sm_msg_type) {
    case NAS_5GSM_PDU_EST_REQ:
      LOG_I(NR_RRC,
            "[CPE NAS] UE %u: PDU Session Establishment Request psi=%u pti=%u\n",
            UE->rrc_ue_id, pdu_session_id, pti);
      send_pdu_session_accept(rrc, UE, pdu_session_id, pti);
      break;

    default:
      LOG_I(NR_RRC,
            "[CPE NAS] UE %u: unhandled 5GSM type 0x%02x — dropped\n",
            UE->rrc_ue_id, sm_msg_type);
      break;
  }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void rrc_gNB_cpe_nas_init(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE)
{
  /* Force null security so the SecurityModeCommand uses NEA0/NIA0. */
  UE->ciphering_algorithm  = 0; /* NEA0 */
  UE->integrity_algorithm  = 0; /* NIA0 */
  /* kgnb will be zeroed when UE context was calloc'd; nothing to do. */

  LOG_I(NR_RRC,
        "[CPE NAS] UE %u IMSI %llu: intercept Registration Request, "
        "sending SecurityModeCommand (NEA0/NIA0)\n",
        UE->rrc_ue_id, (unsigned long long)UE->imsi);

  rrc_gNB_generate_SecurityModeCommand(rrc, UE);
}

void rrc_gNB_cpe_nas_security_complete(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE)
{
  LOG_I(NR_RRC,
        "[CPE NAS] UE %u IMSI %llu: SecurityModeComplete — sending Registration Accept\n",
        UE->rrc_ue_id, (unsigned long long)UE->imsi);

  send_registration_accept(rrc, UE);

  /* Wait for the UE's real PDU Session Establishment Request before sending
   * PDU Session Accept. Sending Accept too early can be ignored by the UE NAS
   * state machine, so the UE never creates oaitun_ue*. */
  LOG_I(NR_RRC,
        "[CPE NAS] UE %u: waiting for PDU Session Establishment Request\n",
        UE->rrc_ue_id);
}

void rrc_gNB_cpe_nas_handle_ul_nas(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE,
                                    const uint8_t *nas_buf, size_t nas_len)
{
  if (nas_len < 3) {
    LOG_W(NR_RRC, "[CPE NAS] UE %u: UL NAS too short (%zu)\n",
          UE->rrc_ue_id, nas_len);
    return;
  }

  /* After SecurityModeFailure the UE has no NAS security context → plain NAS.
   * Plain: EPD[0] sec_hdr[1]=0x00 msg_type[2]
   * Security-protected: EPD[0] sec_hdr[1]!=0x00 MAC[2-5] SN[6] inner[7+] */
  bool plain = (nas_buf[1] == NAS_PLAIN_HDR);
  uint8_t inner_msg_type;

  if (plain) {
    inner_msg_type = nas_buf[NAS_PLAIN_MSG_TYPE_OFF]; /* offset 2 */
  } else {
    if (nas_len < (size_t)(NAS_SP_HDR_LEN + NAS_MM_HDR_LEN)) {
      LOG_W(NR_RRC, "[CPE NAS] UE %u: SP NAS too short (%zu)\n",
            UE->rrc_ue_id, nas_len);
      return;
    }
    inner_msg_type = nas_buf[NAS_INNER_MSG_TYPE_OFF]; /* offset 9 */
  }

  switch (inner_msg_type) {
    case NAS_5GMM_REG_COMPLETE:
      /* UE acknowledges Registration Accept — no response required. */
      LOG_I(NR_RRC, "[CPE NAS] UE %u: Registration Complete received\n",
            UE->rrc_ue_id);
      break;

    case NAS_5GMM_UL_NAS_XPORT:
      handle_ul_nas_transport(rrc, UE, nas_buf, nas_len);
      break;

    default:
      LOG_I(NR_RRC,
            "[CPE NAS] UE %u: unhandled 5GMM msg 0x%02x — dropped\n",
            UE->rrc_ue_id, inner_msg_type);
      break;
  }
}
