#ifdef WITH_PROMETHEUS

#include <peafowl/api.h>

#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <map>

using namespace std;
using namespace prometheus;

extern "C" {

typedef struct dpi_prometheus_stats{
    Exposer* exposer;
    shared_ptr<Registry> registry;
    unordered_map<string, Family<Counter>&> counters;
    unordered_map<string, Family<Gauge>&> gauges;
    unordered_map<string, Family<Histogram>&> histograms;
    unordered_map<string, Family<Summary>&> summaries;
}dpi_prometheus_stats_t;

uint8_t dpi_prometheus_init(dpi_library_state_t* state, uint16_t port){
    dpi_prometheus_stats_t* stats = new dpi_prometheus_stats_t();
    Exposer* exposer = new Exposer{(string("127.0.0.1:") + to_string(port)).c_str()};
    stats->exposer = exposer;
    stats->registry = make_shared<Registry>();
    string key;

    // Packets
    key = "packets";
    auto& packets = BuildCounter().Name(key)
                                 .Help("Number of received packets.")
                                 .Register(*stats->registry);
    stats->counters.insert(pair<string, Family<Counter>&>(key, packets));

    // Bytes
    key = "bytes";
    auto& bytes = BuildCounter().Name(key)
                                 .Help("Number of received bytes.")
                                 .Register(*stats->registry);
    stats->counters.insert(pair<string, Family<Counter>&>(key, bytes));

    // ask the exposer to scrape the registry on incoming scrapes
    exposer->RegisterCollectable(stats->registry);

    state->prometheus_stats = static_cast<void*>(stats);
    return DPI_STATE_UPDATE_SUCCESS;
}

static bool dpi_prometheus_create_labels(dpi_pkt_infos_t& infos, map<string, string>& labels){
    string srcAddr, dstAddr;
    if(infos.ip_version == DPI_IP_VERSION_4){
        char str[INET_ADDRSTRLEN];
        struct in_addr ia;
        ia.s_addr = infos.src_addr_t.ipv4_srcaddr;
        inet_ntop(AF_INET, &ia, str, INET_ADDRSTRLEN);
        srcAddr = string(str);

        ia.s_addr = infos.dst_addr_t.ipv4_dstaddr;
        inet_ntop(AF_INET, &ia, str, INET_ADDRSTRLEN);
        dstAddr = string(str);
    }else if(infos.ip_version == DPI_IP_VERSION_6){
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &infos.src_addr_t.ipv6_srcaddr, str, INET6_ADDRSTRLEN);
        srcAddr = string(str);

        inet_ntop(AF_INET6, &infos.dst_addr_t.ipv6_dstaddr, str, INET6_ADDRSTRLEN);
        dstAddr = string(str);
    }else{
        return false;
    }
    labels.insert(pair<string, string>("srcaddr", srcAddr));
    labels.insert(pair<string, string>("dstaddr", dstAddr));
    labels.insert(pair<string, string>("srcport", to_string(ntohs(infos.srcport))));
    labels.insert(pair<string, string>("dstport", to_string(ntohs(infos.dstport))));
    labels.insert(pair<string, string>("l4prot", to_string(infos.l4prot)));
    //labels.insert(pair<string, string>("direction", to_string(infos.direction))); If we want to use direction, we need to have two different counters (one for direction 0 and one for direction 1, and we need to increment only the counter correpsonding to the pkt direction)
    return true;
}

void* dpi_prometheus_counter_create(void* prometheus_stats, const char* counter_name, dpi_pkt_infos_t* infos, dpi_l7_prot_id protocol){
    dpi_prometheus_stats* stats = static_cast<dpi_prometheus_stats*>(prometheus_stats);
    auto f = stats->counters.find(counter_name);
    if(f != stats->counters.end()){
        map<string, string> labels;
        if(dpi_prometheus_create_labels(*infos, labels)){
            if(protocol != DPI_PROTOCOL_NOT_DETERMINED){
                labels.insert(pair<string, string>("l7prot", dpi_get_protocol_string(protocol)));
            }
            return static_cast<void*>(&(f->second.Add(labels)));
        }else{
            return NULL;
        }
    }else{  
        throw runtime_error("Non existing prometheus counter.");
    }
}

void dpi_prometheus_counter_delete(void* prometheus_stats, const char* counter_name, void* counter){
    dpi_prometheus_stats* stats = static_cast<dpi_prometheus_stats*>(prometheus_stats);
    auto f = stats->counters.find(counter_name);
    if(f != stats->counters.end()){
        f->second.Remove(static_cast<Counter*>(counter));
    }else{  
        throw runtime_error("Non existing prometheus counter.");
    }
}

void dpi_prometheus_counter_increment(void* counter, double value){
    static_cast<Counter*>(counter)->Increment(value);
}

uint8_t dpi_prometheus_terminate(dpi_library_state_t* state){
    if(state->prometheus_stats){
        dpi_prometheus_stats* stats = static_cast<dpi_prometheus_stats*>(state->prometheus_stats);
        delete stats->exposer;
        delete stats;
    }
    return DPI_STATE_UPDATE_SUCCESS;
}

}
#endif


