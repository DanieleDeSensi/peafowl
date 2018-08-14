#ifndef DPI_PROMETHEUS_H
#define DPI_PROMETHEUS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_PROMETHEUS
    void* dpi_prometheus_counter_create(void* prometheus_stats, const char* counter_name, dpi_pkt_infos_t* infos, dpi_l7_prot_id protocol);
    void dpi_prometheus_counter_delete(void* prometheus_stats, const char* counter_name, void* counter);
    void dpi_prometheus_counter_increment(void* counter, double value);    
    uint8_t dpi_prometheus_terminate(dpi_library_state_t* state);
#endif

#ifdef __cplusplus
}
#endif

#endif