#ifndef TOR_PATH_H
#define TOR_PATH_H

// return a list of nodes as a suitable path for a given purpose
//const smartlist_t *choose_circuit_path(uint8_t purpose, int flags);
// return a new, random entry guard
//const node_t *choose_new_entry_guard(void);
// return a random node n such that XXX
const node_t *path_choose_random_node(smartlist_t *excludedsmarlist,
                                      routerset_t *excludedset,
                                      router_crn_flags_t flags);

// TODO: all this shit should be static eventually
void scale_array_elements_to_u64(u64_dbl_t *entries,
                                 int n_entries,
                                 uint64_t *total_out);
int choose_array_element_by_weight(const u64_dbl_t *entries, int n_entries);
int compute_weighted_bandwidths(const smartlist_t *sl,
                                bandwidth_weight_rule_t rule,
                                u64_dbl_t **bandwidths_out);
const node_t *node_sl_choose_by_bandwidth(const smartlist_t *sl,
                                          bandwidth_weight_rule_t rule);
const node_t *node_sl_choose_by_bandwidth(const smartlist *sl,
                                          bandwidth_weight_rule_t rule);

#endif
