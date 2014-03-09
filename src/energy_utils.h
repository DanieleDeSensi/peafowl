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
