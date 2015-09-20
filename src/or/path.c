#include "or.h"
#include "config.h"
#include "entrynodes.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "path.h"
#include "policies.h"
#include "reasons.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"

/****************************************************************************/

/* static function prototypes */
/* DON'T REMOVE */
/* TODO: does this need to be public? */
//static int compute_weighted_bandwidths(const smartlist_t *sl,
//                                       bandwidth_weight_rule_t rule,
//                                       u64_dbl_t **bandwidths_out);

/****************************************************************************/

/* TODO: make this public */
/* NOTE: this has to be public until path handles dirserver choices */
/* DON'T REMOVE */
/** Given an array of double/uint64_t unions that are currently being used as
 * doubles, convert them to uint64_t, and try to scale them linearly so as to
 * much of the range of uint64_t. If <b>total_out</b> is provided, set it to
 * the sum of all elements in the array _before_ scaling. */
//STATIC void
void
scale_array_elements_to_u64(u64_dbl_t *entries, int n_entries,
                            uint64_t *total_out)
{
  double total = 0.0;
  double scale_factor = 0.0;
  int i;
  /* big, but far away from overflowing an int64_t */
#define SCALE_TO_U64_MAX ((int64_t) (INT64_MAX / 4))

  for (i = 0; i < n_entries; ++i)
    total += entries[i].dbl;

  if (total > 0.0)
    scale_factor = SCALE_TO_U64_MAX / total;

  for (i = 0; i < n_entries; ++i)
    entries[i].u64 = tor_llround(entries[i].dbl * scale_factor);

  if (total_out)
    *total_out = (uint64_t) total;

#undef SCALE_TO_U64_MAX
}

/* DON'T REMOVE */
/** Time-invariant 64-bit greater-than; works on two integers in the range
 * (0,INT64_MAX). */
#if SIZEOF_VOID_P == 8
#define gt_i64_timei(a,b) ((a) > (b))
#else
static INLINE int
gt_i64_timei(uint64_t a, uint64_t b)
{
  int64_t diff = (int64_t) (b - a);
  int res = diff >> 63;
  return res & 1;
}
#endif

/* TODO: make this static */
/* NOTE: path has to handle dirserver choices before this can be static */
/* DON'T REMOVE */
/** Pick a random element of <b>n_entries</b>-element array <b>entries</b>,
 * choosing each element with a probability proportional to its (uint64_t)
 * value, and return the index of that element.  If all elements are 0, choose
 * an index at random. Return -1 on error.
 */
//STATIC int
int
choose_array_element_by_weight(const u64_dbl_t *entries, int n_entries)
{
  int i, i_chosen=-1, n_chosen=0;
  uint64_t total_so_far = 0;
  uint64_t rand_val;
  uint64_t total = 0;

  for (i = 0; i < n_entries; ++i)
    total += entries[i].u64;

  if (n_entries < 1)
    return -1;

  if (total == 0)
    return crypto_rand_int(n_entries);

  tor_assert(total < INT64_MAX);

  rand_val = crypto_rand_uint64(total);

  for (i = 0; i < n_entries; ++i) {
    total_so_far += entries[i].u64;
    if (gt_i64_timei(total_so_far, rand_val)) {
      i_chosen = i;
      n_chosen++;
      /* Set rand_val to INT64_MAX rather than stopping the loop. This way,
       * the time we spend in the loop does not leak which element we chose. */
      rand_val = INT64_MAX;
    }
  }
  tor_assert(total_so_far == total);
  tor_assert(n_chosen == 1);
  tor_assert(i_chosen >= 0);
  tor_assert(i_chosen < n_entries);

  return i_chosen;
}

/* TODO: should we remove this bridge stuff and make it public somewhere? */
/* DON'T REMOVE */
/** When weighting bridges, enforce these values as lower and upper
 * bound for believable bandwidth, because there is no way for us
 * to verify a bridge's bandwidth currently. */
#define BRIDGE_MIN_BELIEVABLE_BANDWIDTH 20000  /* 20 kB/sec */
#define BRIDGE_MAX_BELIEVABLE_BANDWIDTH 100000 /* 100 kB/sec */

/* DON'T REMOVE */
/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity, making sure to stay within the
 * interval between bridge-min-believe-bw and
 * bridge-max-believe-bw. */
static uint32_t
bridge_get_advertised_bandwidth_bounded(routerinfo_t *router)
{
  uint32_t result = router->bandwidthcapacity;
  if (result > router->bandwidthrate)
    result = router->bandwidthrate;
  if (result > BRIDGE_MAX_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MAX_BELIEVABLE_BANDWIDTH;
  else if (result < BRIDGE_MIN_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MIN_BELIEVABLE_BANDWIDTH;
  return result;
}

/* DON'T REMOVE */
/** Return bw*1000, unless bw*1000 would overflow, in which case return
 * INT32_MAX. */
static INLINE int32_t
kb_to_bytes(uint32_t bw)
{
  return (bw > (INT32_MAX/1000)) ? INT32_MAX : bw*1000;
}

/* DON'T REMOVE */
/** Helper function:
 * choose a random element of smartlist <b>sl</b> of nodes, weighted by
 * the advertised bandwidth of each element using the consensus
 * bandwidth weights.
 *
 * If <b>rule</b>==WEIGHT_FOR_EXIT. we're picking an exit node: consider all
 * nodes' bandwidth equally regardless of their Exit status, since there may
 * be some in the list because they exit to obscure ports. If
 * <b>rule</b>==NO_WEIGHTING, we're picking a non-exit node: weight
 * exit-node's bandwidth less depending on the smallness of the fraction of
 * Exit-to-total bandwidth.  If <b>rule</b>==WEIGHT_FOR_GUARD, we're picking a
 * guard node: consider all guard's bandwidth equally. Otherwise, weight
 * guards proportionally less.
 */
static const node_t *
smartlist_choose_node_by_bandwidth_weights(const smartlist_t *sl,
                                           bandwidth_weight_rule_t rule)
{
  u64_dbl_t *bandwidths=NULL;

  if (compute_weighted_bandwidths(sl, rule, &bandwidths) < 0)
    return NULL;

  scale_array_elements_to_u64(bandwidths, smartlist_len(sl), NULL);

  {
    int idx = choose_array_element_by_weight(bandwidths,
                                             smartlist_len(sl));
    tor_free(bandwidths);
    return idx < 0 ? NULL : smartlist_get(sl, idx);
  }
}

// TODO: make this static
/* DON'T REMOVE */
/** Given a list of routers and a weighting rule as in
 * smartlist_choose_node_by_bandwidth_weights, compute weighted bandwidth
 * values for each node and store them in a freshly allocated
 * *<b>bandwidths_out</b> of the same length as <b>sl</b>, and holding results
 * as doubles. Return 0 on success, -1 on failure. */
//static int
int
compute_weighted_bandwidths(const smartlist_t *sl,
                            bandwidth_weight_rule_t rule,
                            u64_dbl_t **bandwidths_out)
{
  int64_t weight_scale;
  double Wg = -1, Wm = -1, We = -1, Wd = -1;
  double Wgb = -1, Wmb = -1, Web = -1, Wdb = -1;
  uint64_t weighted_bw = 0;
  guardfraction_bandwidth_t guardfraction_bw;
  u64_dbl_t *bandwidths;

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD ||
             rule == WEIGHT_FOR_MID ||
             rule == WEIGHT_FOR_DIR);

  if (smartlist_len(sl) == 0) {
    log_info(LD_CIRC,
             "Empty routerlist passed in to consensus weight node "
             "selection for rule %s",
             bandwidth_weight_rule_to_string(rule));
    return -1;
  }

  weight_scale = networkstatus_get_weight_scale_param(NULL);

  if (rule == WEIGHT_FOR_GUARD) {
    Wg = networkstatus_get_bw_weight(NULL, "Wgg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wgm", -1); /* Bridges */
    We = 0;
    Wd = networkstatus_get_bw_weight(NULL, "Wgd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_MID) {
    Wg = networkstatus_get_bw_weight(NULL, "Wmg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wmm", -1);
    We = networkstatus_get_bw_weight(NULL, "Wme", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wmd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_EXIT) {
    // Guards CAN be exits if they have weird exit policies
    // They are d then I guess...
    We = networkstatus_get_bw_weight(NULL, "Wee", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wem", -1); /* Odd exit policies */
    Wd = networkstatus_get_bw_weight(NULL, "Wed", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Weg", -1); /* Odd exit policies */

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_DIR) {
    We = networkstatus_get_bw_weight(NULL, "Wbe", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wbm", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wbd", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Wbg", -1);

    Wgb = Wmb = Web = Wdb = weight_scale;
  } else if (rule == NO_WEIGHTING) {
    Wg = Wm = We = Wd = weight_scale;
    Wgb = Wmb = Web = Wdb = weight_scale;
  }

  if (Wg < 0 || Wm < 0 || We < 0 || Wd < 0 || Wgb < 0 || Wmb < 0 || Wdb < 0
      || Web < 0) {
    log_debug(LD_CIRC,
              "Got negative bandwidth weights. Defaulting to naive selection"
              " algorithm.");
    Wg = Wm = We = Wd = weight_scale;
    Wgb = Wmb = Web = Wdb = weight_scale;
  }

  Wg /= weight_scale;
  Wm /= weight_scale;
  We /= weight_scale;
  Wd /= weight_scale;

  Wgb /= weight_scale;
  Wmb /= weight_scale;
  Web /= weight_scale;
  Wdb /= weight_scale;

  bandwidths = tor_calloc(smartlist_len(sl), sizeof(u64_dbl_t));

  // Cycle through smartlist and total the bandwidth.
  static int warned_missing_bw = 0;
  SMARTLIST_FOREACH_BEGIN(sl, const node_t *, node) {
    int is_exit = 0, is_guard = 0, is_dir = 0, this_bw = 0;
    double weight = 1;
    double weight_without_guard_flag = 0; /* Used for guardfraction */
    double final_weight = 0;
    is_exit = node->is_exit && ! node->is_bad_exit;
    is_guard = node->is_possible_guard;
    is_dir = node_is_dir(node);
    if (node->rs) {
      if (!node->rs->has_bandwidth) {
        /* This should never happen, unless all the authorites downgrade
         * to 0.2.0 or rogue routerstatuses get inserted into our consensus. */
        if (! warned_missing_bw) {
          log_warn(LD_BUG,
                 "Consensus is missing some bandwidths. Using a naive "
                 "router selection algorithm");
          warned_missing_bw = 1;
        }
        this_bw = 30000; /* Chosen arbitrarily */
      } else {
        this_bw = kb_to_bytes(node->rs->bandwidth_kb);
      }
    } else if (node->ri) {
      /* bridge or other descriptor not in our consensus */
      this_bw = bridge_get_advertised_bandwidth_bounded(node->ri);
    } else {
      /* We can't use this one. */
      continue;
    }

    if (is_guard && is_exit) {
      weight = (is_dir ? Wdb*Wd : Wd);
      weight_without_guard_flag = (is_dir ? Web*We : We);
    } else if (is_guard) {
      weight = (is_dir ? Wgb*Wg : Wg);
      weight_without_guard_flag = (is_dir ? Wmb*Wm : Wm);
    } else if (is_exit) {
      weight = (is_dir ? Web*We : We);
    } else { // middle
      weight = (is_dir ? Wmb*Wm : Wm);
    }
    /* These should be impossible; but overflows here would be bad, so let's
     * make sure. */
    if (this_bw < 0)
      this_bw = 0;
    if (weight < 0.0)
      weight = 0.0;
    if (weight_without_guard_flag < 0.0)
      weight_without_guard_flag = 0.0;

    /* If guardfraction information is available in the consensus, we
     * want to calculate this router's bandwidth according to its
     * guardfraction. Quoting from proposal236:
     *
     *    Let Wpf denote the weight from the 'bandwidth-weights' line a
     *    client would apply to N for position p if it had the guard
     *    flag, Wpn the weight if it did not have the guard flag, and B the
     *    measured bandwidth of N in the consensus.  Then instead of choosing
     *    N for position p proportionally to Wpf*B or Wpn*B, clients should
     *    choose N proportionally to F*Wpf*B + (1-F)*Wpn*B.
     */
    if (node->rs && node->rs->has_guardfraction && rule != WEIGHT_FOR_GUARD) {
      /* XXX The assert should actually check for is_guard. However,
       * that crashes dirauths because of #13297. This should be
       * equivalent: */
      tor_assert(node->rs->is_possible_guard);

      guard_get_guardfraction_bandwidth(&guardfraction_bw,
                                        this_bw,
                                        node->rs->guardfraction_percentage);

      /* Calculate final_weight = F*Wpf*B + (1-F)*Wpn*B */
      final_weight =
        guardfraction_bw.guard_bw * weight +
        guardfraction_bw.non_guard_bw * weight_without_guard_flag;

      log_debug(LD_GENERAL, "%s: Guardfraction weight %f instead of %f (%s)",
                node->rs->nickname, final_weight, weight*this_bw,
                bandwidth_weight_rule_to_string(rule));
    } else { /* no guardfraction information. calculate the weight normally. */
      final_weight = weight*this_bw;
    }

    bandwidths[node_sl_idx].dbl = final_weight + 0.5;
  } SMARTLIST_FOREACH_END(node);

  log_debug(LD_CIRC, "Generated weighted bandwidths for rule %s based "
            "on weights "
            "Wg=%f Wm=%f We=%f Wd=%f with total bw "U64_FORMAT,
            bandwidth_weight_rule_to_string(rule),
            Wg, Wm, We, Wd, U64_PRINTF_ARG(weighted_bw));

  *bandwidths_out = bandwidths;

  return 0;
}

/* TODO: make this static */
/* NOTE: this is needed for some directory choices stuff currently */
/* DON'T REMOVE OK */
/** Choose a random element of status list <b>sl</b>, weighted by
 * the advertised bandwidth of each node */
const node_t *
node_sl_choose_by_bandwidth(const smartlist_t *sl,
                            bandwidth_weight_rule_t rule)
{ /*XXXX MOVE */
  return smartlist_choose_node_by_bandwidth_weights(sl, rule);
}

/* XXX THIS IS THE ONE WE WANT!! */

/** Return a random running node from the nodelist. Never
 * pick a node that is in
 * <b>excludedsmartlist</b>, or which matches <b>excludedset</b>,
 * even if they are the only nodes available.
 * If <b>CRN_NEED_UPTIME</b> is set in flags and any router has more than
 * a minimum uptime, return one of those.
 * If <b>CRN_NEED_CAPACITY</b> is set in flags, weight your choice by the
 * advertised capacity of each router.
 * If <b>CRN_ALLOW_INVALID</b> is not set in flags, consider only Valid
 * routers.
 * If <b>CRN_NEED_GUARD</b> is set in flags, consider only Guard routers.
 * If <b>CRN_WEIGHT_AS_EXIT</b> is set in flags, we weight bandwidths as if
 * picking an exit node, otherwise we weight bandwidths for picking a relay
 * node (that is, possibly discounting exit nodes).
 * If <b>CRN_NEED_DESC</b> is set in flags, we only consider nodes that
 * have a routerinfo or microdescriptor -- that is, enough info to be
 * used to build a circuit.
 */
const node_t *
path_choose_random_node(smartlist_t *excludedsmartlist,
                        routerset_t *excludedset,
                        router_crn_flags_t flags)
{ /* XXXX MOVE */
  const int need_uptime = (flags & CRN_NEED_UPTIME) != 0;
  const int need_capacity = (flags & CRN_NEED_CAPACITY) != 0;
  const int need_guard = (flags & CRN_NEED_GUARD) != 0;
  const int allow_invalid = (flags & CRN_ALLOW_INVALID) != 0;
  const int weight_for_exit = (flags & CRN_WEIGHT_AS_EXIT) != 0;
  const int need_desc = (flags & CRN_NEED_DESC) != 0;

  smartlist_t *sl=smartlist_new(),
    *excludednodes=smartlist_new();
  const node_t *choice = NULL;
  const routerinfo_t *r;
  bandwidth_weight_rule_t rule;

  tor_assert(!(weight_for_exit && need_guard));
  rule = weight_for_exit ? WEIGHT_FOR_EXIT :
    (need_guard ? WEIGHT_FOR_GUARD : WEIGHT_FOR_MID);

  /* Exclude relays that allow single hop exit circuits, if the user
   * wants to (such relays might be risky) */
  if (get_options()->ExcludeSingleHopRelays) {
    SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
      if (node_allows_single_hop_exits(node)) {
        smartlist_add(excludednodes, node);
      });
  }

  if ((r = routerlist_find_my_routerinfo()))
    routerlist_add_node_and_family(excludednodes, r);

  router_add_running_nodes_to_smartlist(sl, allow_invalid,
                                        need_uptime, need_capacity,
                                        need_guard, need_desc);
  log_debug(LD_CIRC,
           "We found %d running nodes.",
            smartlist_len(sl));

  smartlist_subtract(sl,excludednodes);
  log_debug(LD_CIRC,
            "We removed %d excludednodes, leaving %d nodes.",
            smartlist_len(excludednodes),
            smartlist_len(sl));

  if (excludedsmartlist) {
    smartlist_subtract(sl,excludedsmartlist);
    log_debug(LD_CIRC,
              "We removed %d excludedsmartlist, leaving %d nodes.",
              smartlist_len(excludedsmartlist),
              smartlist_len(sl));
  }
  if (excludedset) {
    routerset_subtract_nodes(sl,excludedset);
    log_debug(LD_CIRC,
              "We removed excludedset, leaving %d nodes.",
              smartlist_len(sl));
  }

  // Always weight by bandwidth
  choice = node_sl_choose_by_bandwidth(sl, rule);

  smartlist_free(sl);
  if (!choice && (need_uptime || need_capacity || need_guard)) {
    /* try once more -- recurse but with fewer restrictions. */
    log_info(LD_CIRC,
             "We couldn't find any live%s%s%s routers; falling back "
             "to list of all routers.",
             need_capacity?", fast":"",
             need_uptime?", stable":"",
             need_guard?", guard":"");
    flags &= ~ (CRN_NEED_UPTIME|CRN_NEED_CAPACITY|CRN_NEED_GUARD);
    choice = path_choose_random_node(
                     excludedsmartlist, excludedset, flags);
  }
  smartlist_free(excludednodes);
  if (!choice) {
    log_warn(LD_CIRC,
             "No available nodes when trying to choose node. Failing.");
  }
  return choice;
}

