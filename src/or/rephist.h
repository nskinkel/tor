/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rephist.h
 * \brief Header file for rephist.c.
 **/

#ifndef _TOR_REPHIST_H
#define _TOR_REPHIST_H

void rep_hist_init(void);
void rep_hist_note_connect_failed(const char* nickname, time_t when);
void rep_hist_note_connect_succeeded(const char* nickname, time_t when);
void rep_hist_note_disconnect(const char* nickname, time_t when);
void rep_hist_note_connection_died(const char* nickname, time_t when);
void rep_hist_note_extend_succeeded(const char *from_name,
                                    const char *to_name);
void rep_hist_note_extend_failed(const char *from_name, const char *to_name);
void rep_hist_dump_stats(time_t now, int severity);
void rep_hist_note_bytes_read(size_t num_bytes, time_t when);
void rep_hist_note_bytes_written(size_t num_bytes, time_t when);
void rep_hist_note_exit_bytes_read(uint16_t port, size_t num_bytes);
void rep_hist_note_exit_bytes_written(uint16_t port, size_t num_bytes);
void rep_hist_note_exit_stream_opened(uint16_t port);
void rep_hist_exit_stats_init(time_t now);
void rep_hist_exit_stats_write(time_t now);
int rep_hist_bandwidth_assess(void);
char *rep_hist_get_bandwidth_lines(int for_extrainfo);
void rep_hist_update_state(or_state_t *state);
int rep_hist_load_state(or_state_t *state, char **err);
void rep_history_clean(time_t before);

void rep_hist_note_router_reachable(const char *id, time_t when);
void rep_hist_note_router_unreachable(const char *id, time_t when);
int rep_hist_record_mtbf_data(time_t now, int missing_means_down);
int rep_hist_load_mtbf_data(time_t now);

time_t rep_hist_downrate_old_runs(time_t now);
double rep_hist_get_stability(const char *id, time_t when);
double rep_hist_get_weighted_fractional_uptime(const char *id, time_t when);
long rep_hist_get_weighted_time_known(const char *id, time_t when);
int rep_hist_have_measured_enough_stability(void);
const char *rep_hist_get_router_stability_doc(time_t now);

void rep_hist_note_used_port(time_t now, uint16_t port);
smartlist_t *rep_hist_get_predicted_ports(time_t now);
void rep_hist_note_used_resolve(time_t now);
void rep_hist_note_used_internal(time_t now, int need_uptime,
                                 int need_capacity);
int rep_hist_get_predicted_internal(time_t now, int *need_uptime,
                                    int *need_capacity);

int any_predicted_circuits(time_t now);
int rep_hist_circbuilding_dormant(time_t now);

void note_crypto_pk_op(pk_op_t operation);
void dump_pk_ops(int severity);

void rep_hist_free_all(void);

/* for hidden service usage statistics */
void hs_usage_note_publish_total(const char *service_id, time_t now);
void hs_usage_note_publish_novel(const char *service_id, time_t now);
void hs_usage_note_fetch_total(const char *service_id, time_t now);
void hs_usage_note_fetch_successful(const char *service_id, time_t now);
void hs_usage_write_statistics_to_file(time_t now);
void hs_usage_free_all(void);

void rep_hist_buffer_stats_init(time_t now);
void rep_hist_buffer_stats_add_circ(circuit_t *circ,
                                    time_t end_of_interval);
void rep_hist_buffer_stats_write(time_t now);

#endif
