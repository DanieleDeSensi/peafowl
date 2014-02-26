typedef struct{
  int fd;
  int core; // A core of the socket
  double power_units;
  double energy_units;
  double time_units;
  double energy_package;
  double energy_cores;
  double energy_offcores;
  double energy_dram;
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
  OS_NOT_SUPPORTED
}energy_counters_init_res;

energy_counters_init_res energy_counters_init(energy_counters_state* state);

void energy_counters_terminate(energy_counters_state* state);

int energy_counters_read(energy_counters_state* state);
