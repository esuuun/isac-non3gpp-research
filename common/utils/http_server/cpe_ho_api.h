#pragma once

/*
 * Start the CPE Handover REST API server (port 8890).
 * Call once from gtp_itf init or CU main.
 * Initialises the cpe_ue_table singleton internally.
 */
void cpe_ho_api_start(void);
