#ifndef PFWL_PROMETHEUS_H
#define PFWL_PROMETHEUS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_PROMETHEUS
void* pfwl_prometheus_counter_create(void* prometheus_stats,
                                    const char* counter_name,
                                    pfwl_pkt_infos_t* infos,
                                    pfwl_l7_prot_id protocol);
void pfwl_prometheus_counter_delete(void* prometheus_stats,
                                   const char* counter_name, void* counter);
void pfwl_prometheus_counter_increment(void* counter, double value);
uint8_t pfwl_prometheus_terminate(pfwl_library_state_t* state);
#endif

#ifdef __cplusplus
}
#endif

#endif