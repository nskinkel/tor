#ifndef TOR_PATHSEL_H
#define TOR_PATHSEL_H

// return a list of nodes as a suitable path for a given purpose
const smartlist_t *choose_circuit_path(uint8_t purpose, int flags);
// return a new, random entry guard
const node_t *choose_new_entry_guard(void);
// return a random node n such that XXX
const node_t *choose_random_node(smartlist_t *excludedsmarlist,
                                 routerset_t *excludedset,
                                 router_crn_flags_t flags);
#endif
