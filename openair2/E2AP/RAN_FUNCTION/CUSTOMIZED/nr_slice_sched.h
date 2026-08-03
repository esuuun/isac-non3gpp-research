/*
 * NR MAC slice scheduling state — shared between ran_func_slice.c (E2 agent)
 * and gNB_scheduler_dlsch.c (MAC scheduler hot path).
 */

#ifndef NR_SLICE_SCHED_H
#define NR_SLICE_SCHED_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define NR_SLICE_MAX     16
#define NR_UE_SLICE_MAX  64

typedef enum {
  NR_SLICE_ALG_NONE = 0,
  NR_SLICE_ALG_NVS,
  NR_SLICE_ALG_STATIC,
  NR_SLICE_ALG_MINMAX,   /* min guarantee (clamp) + max cap, fractions of BWP */
} nr_slice_alg_e;

typedef struct {
  bool     valid;
  uint32_t id;
  char     label[32];
  nr_slice_alg_e alg;
  /* NVS_CAPACITY: fraction of BWP [0.0, 1.0] */
  float    pct_reserved;
  /* STATIC: RB range within BWP (inclusive) */
  uint16_t pos_low;
  uint16_t pos_high;
  /* MINMAX: min/max fraction of BWP [0.0, 1.0] */
  float    min_pct;
  float    max_pct;
} nr_slice_entry_t;

typedef struct {
  bool     valid;
  uint16_t rnti;
  uint32_t slice_id;
  uint64_t pending_ctrl_seq;
  uint64_t activated_ctrl_seq;
} nr_ue_slice_entry_t;

typedef struct {
  nr_slice_entry_t    slices[NR_SLICE_MAX];
  nr_ue_slice_entry_t ue_map[NR_UE_SLICE_MAX];
  pthread_mutex_t     lock;
} nr_slice_table_t;

extern nr_slice_table_t g_nr_slice_table;

/* Called once at gNB startup. */
void nr_slice_table_init(void);

/*
 * Scheduler hot-path accessors — use trylock; if lock unavailable for this
 * slot, return 0 / false (no constraint applied for that slot).
 *
 * nr_slice_get_max_rbs: returns the max RBs this UE may receive in one slot
 *   based on its slice policy (0 = no slice constraint).
 *
 * nr_slice_get_rb_range: for STATIC slices, sets *rb_low and *rb_high
 *   (RB indices within BWP, inclusive).  Returns true when constrained.
 */
uint16_t nr_slice_get_max_rbs(uint16_t rnti, uint16_t bwp_size);
/* nr_slice_get_min_rbs: for MINMAX slices, the guaranteed-floor RBs this UE
 *   should get when scheduled (0 = no floor). Caller must still clamp to the
 *   RBs actually available this slot. */
uint16_t nr_slice_get_min_rbs(uint16_t rnti, uint16_t bwp_size);
bool     nr_slice_get_rb_range(uint16_t rnti, uint16_t *rb_low, uint16_t *rb_high);
void     nr_slice_note_ctrl_t1(const char *op, uint16_t rnti, bool has_rnti, uint32_t slice_id, int64_t t1_us);
void     nr_slice_note_ctrl_t2(const char *op, uint16_t rnti, bool has_rnti, uint32_t slice_id, int64_t t1_us, int64_t t2_us);
void     nr_slice_note_sched_activation(uint16_t rnti,
                                        int frame,
                                        int slot,
                                        uint16_t rb_start,
                                        uint16_t rb_size,
                                        uint16_t rb_limit);

/* Control-plane helpers — caller must hold g_nr_slice_table.lock. */
void nr_slice_addmod(uint32_t id, const char *label,
                     nr_slice_alg_e alg,
                     float pct, uint16_t pos_low, uint16_t pos_high,
                     float min_pct, float max_pct);
void nr_slice_del(uint32_t id);
void nr_slice_ue_assoc(uint16_t rnti, uint32_t slice_id);
void nr_slice_ue_deassoc_slice(uint32_t slice_id);

#endif /* NR_SLICE_SCHED_H */
