/*
 * SLICE SM E2 agent — real implementation backed by NR MAC scheduler.
 *
 * read_slice_sm  : reports current slice config + active UE associations
 *                  from the global nr_slice_table and the MAC UE list.
 * write_ctrl_slice_sm : ADD / DEL / UE_ASSOC actually update nr_slice_table
 *                       which the NR MAC scheduler hot-path reads every slot.
 */

#include "ran_func_slice.h"
#include "nr_slice_sched.h"

#include "openair2/E2AP/flexric/src/util/time_now_us.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * read_slice_sm — called periodically by the E2 agent to build indication
 * ------------------------------------------------------------------------- */

bool read_slice_sm(void *data)
{
  assert(data != NULL);

  slice_ind_data_t *ind = (slice_ind_data_t *)data;
  memset(ind, 0, sizeof(*ind));

  ind->msg.tstamp = time_now_us();

  nr_slice_table_t *tbl = &g_nr_slice_table;
  pthread_mutex_lock(&tbl->lock);

  /* ---- DL slice configuration ------------------------------------------ */
  ul_dl_slice_conf_t *dl = &ind->msg.slice_conf.dl;

  /* Count valid slices */
  uint32_t n_slices = 0;
  for (int i = 0; i < NR_SLICE_MAX; i++)
    if (tbl->slices[i].valid) n_slices++;

  if (n_slices > 0) {
    dl->len_slices = n_slices;
    dl->slices     = calloc(n_slices, sizeof(fr_slice_t));
    assert(dl->slices);

    const char *sched_name = "PF";
    dl->len_sched_name = strlen(sched_name);
    dl->sched_name     = malloc(dl->len_sched_name);
    assert(dl->sched_name);
    memcpy(dl->sched_name, sched_name, dl->len_sched_name);

    uint32_t idx = 0;
    for (int i = 0; i < NR_SLICE_MAX; i++) {
      nr_slice_entry_t *se = &tbl->slices[i];
      if (!se->valid) continue;

      fr_slice_t *s = &dl->slices[idx++];
      s->id = se->id;

      /* label */
      size_t llen = strlen(se->label);
      if (llen > 0) {
        s->len_label = llen;
        s->label     = malloc(llen);
        assert(s->label);
        memcpy(s->label, se->label, llen);
      }

      /* sched */
      const char *sched = "PF";
      s->len_sched = strlen(sched);
      s->sched     = malloc(s->len_sched);
      assert(s->sched);
      memcpy(s->sched, sched, s->len_sched);

      /* params */
      if (se->alg == NR_SLICE_ALG_NVS) {
        s->params.type                                  = SLICE_ALG_SM_V0_NVS;
        s->params.u.nvs.conf                            = SLICE_SM_NVS_V0_CAPACITY;
        s->params.u.nvs.u.capacity.u.pct_reserved      = se->pct_reserved;
      } else if (se->alg == NR_SLICE_ALG_STATIC) {
        s->params.type             = SLICE_ALG_SM_V0_STATIC;
        s->params.u.sta.pos_low   = se->pos_low;
        s->params.u.sta.pos_high  = se->pos_high;
      } else if (se->alg == NR_SLICE_ALG_MINMAX) {
        /* Carried over the wire as NVS-RATE: u1=min_pct, u2=max_pct */
        s->params.type                          = SLICE_ALG_SM_V0_NVS;
        s->params.u.nvs.conf                    = SLICE_SM_NVS_V0_RATE;
        s->params.u.nvs.u.rate.u1.mbps_required  = se->min_pct;
        s->params.u.nvs.u.rate.u2.mbps_reference = se->max_pct;
      } else {
        s->params.type = SLICE_ALG_SM_V0_NONE;
      }
    }
  }

  /* UL: empty (NR DL-only slicing for now) */
  ind->msg.slice_conf.ul.len_slices = 0;

  /* ---- UE-slice association -------------------------------------------- */
  /* Report all explicit UE-slice associations from the slice table. */
  uint32_t n_ue = 0;
  for (int i = 0; i < NR_UE_SLICE_MAX; i++)
    if (tbl->ue_map[i].valid) n_ue++;

  if (n_ue > 0) {
    ue_slice_conf_t *uc = &ind->msg.ue_slice_conf;
    uc->len_ue_slice = n_ue;
    uc->ues          = calloc(n_ue, sizeof(ue_slice_assoc_t));
    assert(uc->ues);

    uint32_t ui = 0;
    for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
      nr_ue_slice_entry_t *e = &tbl->ue_map[i];
      if (!e->valid) continue;
      uc->ues[ui].rnti  = e->rnti;
      uc->ues[ui].dl_id = e->slice_id;
      ui++;
    }
  }

  pthread_mutex_unlock(&tbl->lock);
  return true;
}

/* -------------------------------------------------------------------------
 * read_slice_setup_sm — E2 Setup (not needed)
 * ------------------------------------------------------------------------- */

void read_slice_setup_sm(void *data)
{
  assert(data != NULL);
  (void)data;
  /* E2 Setup for SLICE SM: no function definition required */
}

/* -------------------------------------------------------------------------
 * write_ctrl_slice_sm — E2 Control request: actually modifies the scheduler
 * ------------------------------------------------------------------------- */

sm_ag_if_ans_t write_ctrl_slice_sm(void const *data)
{
  assert(data != NULL);
  const int64_t t1_us = time_now_us();

  slice_ctrl_req_data_t const *req = (slice_ctrl_req_data_t const *)data;
  slice_ctrl_msg_t      const *msg = &req->msg;

  nr_slice_table_t *tbl = &g_nr_slice_table;
  pthread_mutex_lock(&tbl->lock);

  if (msg->type == SLICE_CTRL_SM_V0_ADD) {
    ul_dl_slice_conf_t const *dl = &msg->u.add_mod_slice.dl;
    for (uint32_t i = 0; i < dl->len_slices; i++) {
      fr_slice_t const *s = &dl->slices[i];

      /* Extract label (length-counted, not null-terminated) */
      char label[32] = {0};
      if (s->label && s->len_label > 0) {
        size_t cp = s->len_label < sizeof(label) - 1 ? s->len_label : sizeof(label) - 1;
        memcpy(label, s->label, cp);
      }

      nr_slice_alg_e alg = NR_SLICE_ALG_NONE;
      float    pct       = 0.0f;
      uint16_t pos_low   = 0;
      uint16_t pos_high  = 0;
      float    min_pct   = 0.0f;
      float    max_pct   = 0.0f;

      if (s->params.type == SLICE_ALG_SM_V0_NVS &&
          s->params.u.nvs.conf == SLICE_SM_NVS_V0_CAPACITY) {
        alg = NR_SLICE_ALG_NVS;
        pct = s->params.u.nvs.u.capacity.u.pct_reserved;
        printf("[E2 SLICE] ADD NVS id=%u pct=%.1f%% label=%s\n",
               s->id, pct * 100.0f, label);
      } else if (s->params.type == SLICE_ALG_SM_V0_NVS &&
                 s->params.u.nvs.conf == SLICE_SM_NVS_V0_RATE) {
        /* NVS-RATE reused to carry MINMAX: u1=min_pct, u2=max_pct */
        alg     = NR_SLICE_ALG_MINMAX;
        min_pct = s->params.u.nvs.u.rate.u1.mbps_required;
        max_pct = s->params.u.nvs.u.rate.u2.mbps_reference;
        printf("[E2 SLICE] ADD MINMAX id=%u min=%.1f%% max=%.1f%% label=%s\n",
               s->id, min_pct * 100.0f, max_pct * 100.0f, label);
      } else if (s->params.type == SLICE_ALG_SM_V0_STATIC) {
        alg      = NR_SLICE_ALG_STATIC;
        pos_low  = (uint16_t)s->params.u.sta.pos_low;
        pos_high = (uint16_t)s->params.u.sta.pos_high;
        printf("[E2 SLICE] ADD STATIC id=%u pos=[%u,%u] label=%s\n",
               s->id, pos_low, pos_high, label);
      } else {
        printf("[E2 SLICE] ADD id=%u (unsupported alg %d, ignored)\n",
               s->id, s->params.type);
      }

      nr_slice_note_ctrl_t1("add", 0, false, s->id, t1_us);
      nr_slice_addmod(s->id, label, alg, pct, pos_low, pos_high, min_pct, max_pct);
      nr_slice_note_ctrl_t2("add", 0, false, s->id, t1_us, time_now_us());
    }

  } else if (msg->type == SLICE_CTRL_SM_V0_DEL) {
    del_slice_conf_t const *del = &msg->u.del_slice;
    for (uint32_t i = 0; i < del->len_dl; i++) {
      printf("[E2 SLICE] DEL id=%u\n", del->dl[i]);
      nr_slice_note_ctrl_t1("del", 0, false, del->dl[i], t1_us);
      nr_slice_ue_deassoc_slice(del->dl[i]);
      nr_slice_del(del->dl[i]);
      nr_slice_note_ctrl_t2("del", 0, false, del->dl[i], t1_us, time_now_us());
    }

  } else if (msg->type == SLICE_CTRL_SM_V0_UE_SLICE_ASSOC) {
    ue_slice_conf_t const *assoc = &msg->u.ue_slice;
    for (uint32_t i = 0; i < assoc->len_ue_slice; i++) {
      uint16_t rnti     = assoc->ues[i].rnti;
      uint32_t slice_id = assoc->ues[i].dl_id;
      printf("[E2 SLICE] ASSOC rnti=0x%04x → slice %u\n", rnti, slice_id);
      nr_slice_note_ctrl_t1("assoc", rnti, true, slice_id, t1_us);
      nr_slice_ue_assoc(rnti, slice_id);
      nr_slice_note_ctrl_t2("assoc", rnti, true, slice_id, t1_us, time_now_us());
    }

  } else {
    assert(0 != 0 && "Unknown SLICE ctrl msg type");
  }

  pthread_mutex_unlock(&tbl->lock);

  sm_ag_if_ans_t ans = {.type = CTRL_OUTCOME_SM_AG_IF_ANS_V0};
  ans.ctrl_out.type = SLICE_AGENT_IF_CTRL_ANS_V0;
  ans.ctrl_out.slice.ans = SLICE_CTRL_OUT_OK;
  /* flexric's slice_sm_ric.c asserts len_diag > 0 on every control response;
     omitting it triggers the assert and crashes the near-RT RIC / xApp process. */
  const char *diag = "OK";
  ans.ctrl_out.slice.len_diag = strlen(diag);
  ans.ctrl_out.slice.diagnostic = malloc(ans.ctrl_out.slice.len_diag);
  assert(ans.ctrl_out.slice.diagnostic);
  memcpy(ans.ctrl_out.slice.diagnostic, diag, ans.ctrl_out.slice.len_diag);
  return ans;
}
