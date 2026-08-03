#pragma once

/*
 * Depth B: CU acts as a local 5GC proxy for CPE_UE.
 *
 * When the CU detects a Registration Request NAS PDU whose IMSI is in
 * the CPE_UE table (populated by POST /api/cpe_handover), it intercepts
 * the NAS at the RRC layer and runs a minimal 5GS NAS state machine
 * entirely within the CU — 5GC / AMF never sees CPE_UE at all.
 *
 * State machine (all signalled via DL/UL Information Transfer on SRB1):
 *
 *  UE              CU (Depth B proxy)
 *  --- Registration Request     --->
 *                               <--- RRC Security Mode Command (NEA0/NIA0)
 *  --- Security Mode Complete   --->  (handled by existing RRC handler)
 *                               <--- Registration Accept  (SST:1, no GUTI)
 *  --- Registration Complete    --->  (ignored)
 *  --- UL NAS: PDU Session Establishment Request --->
 *                               <--- DL NAS: PDU Session Establishment Accept
 *                                    (IP from 10.61.0.0/24 pool)
 *
 * After PDU Session Establishment Accept the CPE_UE entry is set to
 * NR_CONNECTED and the pdu_session_ip is stored for GTP-U NAT rewrites
 * in gtp_itf.cpp.
 */

#include <stddef.h>
#include <stdint.h>
#include "openair2/RRC/NR/nr_rrc_defs.h"

/*
 * Called from rrc_gNB_send_NGAP_NAS_FIRST_REQ when IMSI matches CPE_UE.
 * Caller must have already set UE->imsi and UE->is_cpe_ue = 1.
 * Sets null security algorithms and fires SecurityModeCommand.
 */
void rrc_gNB_cpe_nas_init(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE);

/*
 * Called from the SecurityModeComplete handler when UE->is_cpe_ue is set.
 * Sends Registration Accept (NEA0/NIA0 — plain outer header, SST:1 NSSAI).
 */
void rrc_gNB_cpe_nas_security_complete(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE);

/*
 * Called instead of rrc_gNB_send_NGAP_UPLINK_NAS for CPE_UE.
 * Dispatches on NAS message type byte (inner plain header):
 *   0x45 Registration Complete  — silently ignored
 *   0x65 UL NAS Transport       — extract 5GSM message type, act on it:
 *     0xc1 PDU Session Establishment Request → send Accept + update table
 *   Anything else               — logged and dropped
 */
void rrc_gNB_cpe_nas_handle_ul_nas(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE,
                                    const uint8_t *nas_buf, size_t nas_len);
