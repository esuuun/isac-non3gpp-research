/*
 * NR MAC slice scheduling state implementation.
 */

#include "nr_slice_sched.h"
#include "openair2/E2AP/flexric/src/util/time_now_us.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

nr_slice_table_t g_nr_slice_table;
static uint64_t g_nr_slice_ctrl_seq;

static bool slice_latency_log_enabled(void)
{
  const char *env = getenv("OAI_SLICE_LATENCY_LOG");
  return env == NULL || strcmp(env, "0") != 0;
}

static const char *rnti_field(uint16_t rnti, bool has_rnti, char *buf, size_t len)
{
  if (!has_rnti)
    return "none";
  snprintf(buf, len, "0x%04x", rnti);
  return buf;
}

void nr_slice_table_init(void)
{
  memset(&g_nr_slice_table, 0, sizeof(g_nr_slice_table));
  pthread_mutex_init(&g_nr_slice_table.lock, NULL);
}

/* --- Helpers shared by both accessors ------------------------------------ */

static nr_slice_entry_t *find_slice(uint32_t slice_id)
{
  for (int i = 0; i < NR_SLICE_MAX; i++)
    if (g_nr_slice_table.slices[i].valid &&
        g_nr_slice_table.slices[i].id == slice_id)
      return &g_nr_slice_table.slices[i];
  return NULL;
}

static bool rnti_to_slice(uint16_t rnti, nr_slice_entry_t **out)
{
  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (e->valid && e->rnti == rnti) {
      *out = find_slice(e->slice_id);
      return (*out != NULL);
    }
  }
  return false;
}

/* --- Scheduler hot-path accessors ---------------------------------------- */

uint16_t nr_slice_get_max_rbs(uint16_t rnti, uint16_t bwp_size)
{
  if (pthread_mutex_trylock(&g_nr_slice_table.lock) != 0)
    return 0; /* lock busy — skip enforcement this slot */

  nr_slice_entry_t *s = NULL;
  uint16_t max_rbs = 0;

  if (rnti_to_slice(rnti, &s) && s != NULL) {
    if (s->alg == NR_SLICE_ALG_NVS) {
      max_rbs = (uint16_t)(bwp_size * s->pct_reserved);
      if (max_rbs < 1) max_rbs = 1;
    } else if (s->alg == NR_SLICE_ALG_STATIC) {
      max_rbs = (s->pos_high >= s->pos_low)
                ? (uint16_t)(s->pos_high - s->pos_low + 1)
                : 0;
    } else if (s->alg == NR_SLICE_ALG_MINMAX) {
      max_rbs = (uint16_t)(bwp_size * s->max_pct);
      if (max_rbs < 1) max_rbs = 1;
    }
  }

  pthread_mutex_unlock(&g_nr_slice_table.lock);
  return max_rbs;
}

uint16_t nr_slice_get_min_rbs(uint16_t rnti, uint16_t bwp_size)
{
  if (pthread_mutex_trylock(&g_nr_slice_table.lock) != 0)
    return 0; /* lock busy — skip enforcement this slot */

  nr_slice_entry_t *s = NULL;
  uint16_t min_rbs = 0;

  if (rnti_to_slice(rnti, &s) && s != NULL && s->alg == NR_SLICE_ALG_MINMAX)
    min_rbs = (uint16_t)(bwp_size * s->min_pct);

  pthread_mutex_unlock(&g_nr_slice_table.lock);
  return min_rbs;
}

bool nr_slice_get_rb_range(uint16_t rnti, uint16_t *rb_low, uint16_t *rb_high)
{
  if (pthread_mutex_trylock(&g_nr_slice_table.lock) != 0)
    return false;

  nr_slice_entry_t *s = NULL;
  bool found = false;

  if (rnti_to_slice(rnti, &s) && s != NULL &&
      s->alg == NR_SLICE_ALG_STATIC) {
    *rb_low  = s->pos_low;
    *rb_high = s->pos_high;
    found = true;
  }

  pthread_mutex_unlock(&g_nr_slice_table.lock);
  return found;
}

void nr_slice_note_ctrl_t1(const char *op, uint16_t rnti, bool has_rnti, uint32_t slice_id, int64_t t1_us)
{
  if (!slice_latency_log_enabled())
    return;

  char rnti_buf[16];
  printf("SLICE_LAT,event=t1,op=%s,rnti=%s,slice_id=%u,t_us=%" PRId64 "\n",
         op,
         rnti_field(rnti, has_rnti, rnti_buf, sizeof(rnti_buf)),
         slice_id,
         t1_us);
}

void nr_slice_note_ctrl_t2(const char *op, uint16_t rnti, bool has_rnti, uint32_t slice_id, int64_t t1_us, int64_t t2_us)
{
  uint64_t seq = ++g_nr_slice_ctrl_seq;

  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (!e->valid)
      continue;
    if ((has_rnti && e->rnti == rnti) || (!has_rnti && e->slice_id == slice_id))
      e->pending_ctrl_seq = seq;
  }

  if (!slice_latency_log_enabled())
    return;

  char rnti_buf[16];
  printf("SLICE_LAT,event=t2,op=%s,seq=%" PRIu64 ",rnti=%s,slice_id=%u,t_us=%" PRId64 ",ctrl_apply_us=%" PRId64 "\n",
         op,
         seq,
         rnti_field(rnti, has_rnti, rnti_buf, sizeof(rnti_buf)),
         slice_id,
         t2_us,
         t2_us - t1_us);
}

void nr_slice_note_sched_activation(uint16_t rnti,
                                    int frame,
                                    int slot,
                                    uint16_t rb_start,
                                    uint16_t rb_size,
                                    uint16_t rb_limit)
{
  uint64_t seq = 0;

  if (pthread_mutex_trylock(&g_nr_slice_table.lock) != 0)
    return;

  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (!e->valid || e->rnti != rnti)
      continue;
    if (e->pending_ctrl_seq > e->activated_ctrl_seq) {
      e->activated_ctrl_seq = e->pending_ctrl_seq;
      seq = e->activated_ctrl_seq;
    }
    break;
  }

  pthread_mutex_unlock(&g_nr_slice_table.lock);

  if (seq == 0 || !slice_latency_log_enabled())
    return;

  printf("SLICE_LAT,event=t3,seq=%" PRIu64 ",rnti=0x%04x,frame=%d,slot=%d,t_us=%" PRId64 ",rb_start=%u,rb_size=%u,rb_limit=%u\n",
         seq,
         rnti,
         frame,
         slot,
         time_now_us(),
         rb_start,
         rb_size,
         rb_limit);
}

/* --- Control-plane helpers (called from ran_func_slice.c) ---------------- */

/* Add or update a slice entry.  Caller must hold lock. */
void nr_slice_addmod(uint32_t id, const char *label,
                     nr_slice_alg_e alg,
                     float pct, uint16_t pos_low, uint16_t pos_high,
                     float min_pct, float max_pct)
{
  /* Look for existing entry with same id */
  for (int i = 0; i < NR_SLICE_MAX; i++) {
    nr_slice_entry_t *s = &g_nr_slice_table.slices[i];
    if (s->valid && s->id == id) {
      s->alg = alg;
      s->pct_reserved = pct;
      s->pos_low  = pos_low;
      s->pos_high = pos_high;
      s->min_pct  = min_pct;
      s->max_pct  = max_pct;
      if (label)
        strncpy(s->label, label, sizeof(s->label) - 1);
      return;
    }
  }
  /* Find free slot */
  for (int i = 0; i < NR_SLICE_MAX; i++) {
    nr_slice_entry_t *s = &g_nr_slice_table.slices[i];
    if (!s->valid) {
      s->valid = true;
      s->id    = id;
      s->alg   = alg;
      s->pct_reserved = pct;
      s->pos_low  = pos_low;
      s->pos_high = pos_high;
      s->min_pct  = min_pct;
      s->max_pct  = max_pct;
      s->label[0] = '\0';
      if (label)
        strncpy(s->label, label, sizeof(s->label) - 1);
      return;
    }
  }
}

/* Delete a slice entry.  Caller must hold lock. */
void nr_slice_del(uint32_t id)
{
  for (int i = 0; i < NR_SLICE_MAX; i++) {
    nr_slice_entry_t *s = &g_nr_slice_table.slices[i];
    if (s->valid && s->id == id) {
      memset(s, 0, sizeof(*s));
      return;
    }
  }
}

/* Associate / move a UE to a slice.  Caller must hold lock. */
void nr_slice_ue_assoc(uint16_t rnti, uint32_t slice_id)
{
  /* Update existing entry if present */
  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (e->valid && e->rnti == rnti) {
      e->slice_id = slice_id;
      return;
    }
  }
  /* Add new entry */
  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (!e->valid) {
      e->valid    = true;
      e->rnti     = rnti;
      e->slice_id = slice_id;
      return;
    }
  }
}

/* Remove all UE associations for a given slice.  Caller must hold lock. */
void nr_slice_ue_deassoc_slice(uint32_t slice_id)
{
  for (int i = 0; i < NR_UE_SLICE_MAX; i++) {
    nr_ue_slice_entry_t *e = &g_nr_slice_table.ue_map[i];
    if (e->valid && e->slice_id == slice_id)
      memset(e, 0, sizeof(*e));
  }
}
