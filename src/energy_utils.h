#include <sys/types.h>

typedef struct{
  int fd;
  int core; // A core of the socket
  double power_per_unit;
  double energy_per_unit;
  double time_per_unit;
  u_int32_t  energy_units_socket;
  u_int32_t  energy_units_cores;
  u_int32_t  energy_units_offcores;
  u_int32_t  energy_units_dram;
  double thermal_spec_power;
}socket_state;

typedef struct{
  unsigned int cpu_model;
  unsigned int num_sockets;
  socket_state* sockets; //One for each socket
}energy_counters_state;

typedef enum{
  OK=0,
  UNSUPPORTED_CPU_TYPE,
  NUMBER_OF_SOCKETS_NOT_FOUND,
  PROCESSOR_PER_SOCKET_NOT_FOUND,
  IMPOSSIBLE_TO_OPEN_MSR_FILE,
  OS_NOT_SUPPORTED
}energy_counters_init_res;

energy_counters_init_res energy_counters_init(energy_counters_state* state);

u_int32_t energy_counters_wrapping_time(energy_counters_state* state);

void energy_counters_terminate(energy_counters_state* state);

int energy_counters_read(energy_counters_state* state);

int energy_counters_get_available_frequencies(unsigned long** frequencies, unsigned int* num_frequencies);

int energy_counters_set_userspace_governor(unsigned int core_id);

int energy_counters_set_ondemand_governor(unsigned int core_id);

int energy_counters_set_performance_governor(unsigned int core_id);

int energy_counters_set_conservative_governor(unsigned int core_id);

int energy_counters_set_frequency(unsigned long frequency, unsigned int core_id);

int energy_counters_set_frequency(unsigned long frequency, unsigned int* cores_ids, unsigned int num_cores, short related);

int energy_counters_set_bounds(unsigned long lb, unsigned long ub, unsigned int core_id);

int energy_counters_get_ht_core_siblings(unsigned int core_id, char* siblings);

int energy_counters_get_num_real_cores(unsigned int* num_cores);

int energy_counters_get_real_cores_identifiers(unsigned int* identifiers, unsigned int num_identifiers);

int energy_counters_get_core_identifier_per_socket(unsigned int* identifiers_in, unsigned int num_identifiers_in, unsigned int** identifiers_out, unsigned int* num_identifiers_out);
