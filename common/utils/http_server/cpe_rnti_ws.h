#pragma once

/*
 * Start the CPE RNTI long-poll notification server (port 8891).
 * CPE_UE polls GET /wait_rnti?imsi=<IMSI> and blocks until CU allocates
 * the RNTI for it (or returns 408 on timeout).
 */
void cpe_rnti_ws_start(void);
