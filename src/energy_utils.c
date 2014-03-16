/* Read the RAPL registers on a sandybridge-ep machine                */
/* Code based on Intel RAPL driver by Zhang Rui <rui.zhang@intel.com> */
/*                                                                    */
/* The /dev/cpu/??/msr driver must be enabled and permissions set     */
/* to allow read access for this to work.                             */
/*                                                                    */
/* Code to properly get this info from Linux through a real device    */
/*   driver and the perf tool should be available as of Linux 3.14    */
/* Compile with:   gcc -O2 -Wall -o rapl-read rapl-read.c -lm         */
/*                                                                    */
/* Vince Weaver -- vincent.weaver @ maine.edu -- 29 November 2013     */
/*                                                                    */
/* Additional contributions by:                                       */
/*   Romain Dolbeau -- romain @ dolbeau.org                           */

#include "energy_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <cmath>
#include <string.h>


#define MSR_RAPL_POWER_UNIT 0x606

/*
 * Platform specific RAPL Domains.
 * Note that PP1 RAPL Domain is supported on 062A only
 * And DRAM RAPL Domain is supported on 062D only
 */
/* Package RAPL Domain */
#define MSR_PKG_RAPL_POWER_LIMIT 0x610
#define MSR_PKG_ENERGY_STATUS 0x611
#define MSR_PKG_PERF_STATUS 0x613
#define MSR_PKG_POWER_INFO 0x614

/* PP0 RAPL Domain */
#define MSR_PP0_POWER_LIMIT 0x638
#define MSR_PP0_ENERGY_STATUS 0x639
#define MSR_PP0_POLICY 0x63A
#define MSR_PP0_PERF_STATUS 0x63B

/* PP1 RAPL Domain, may reflect to uncore devices */
#define MSR_PP1_POWER_LIMIT 0x640
#define MSR_PP1_ENERGY_STATUS 0x641
#define MSR_PP1_POLICY 0x642

/* DRAM RAPL Domain */
#define MSR_DRAM_POWER_LIMIT 0x618
#define MSR_DRAM_ENERGY_STATUS 0x619
#define MSR_DRAM_PERF_STATUS 0x61B
#define MSR_DRAM_POWER_INFO 0x61C

/* RAPL UNIT BITMASK */
#define POWER_UNIT_OFFSET 0
#define POWER_UNIT_MASK 0x0F

#define ENERGY_UNIT_OFFSET 0x08
#define ENERGY_UNIT_MASK 0x1F00

#define TIME_UNIT_OFFSET 0x10
#define TIME_UNIT_MASK 0xF000

static int open_msr(int core) {

  char msr_filename[BUFSIZ];
  int fd;

  sprintf(msr_filename, "/dev/cpu/%d/msr", core);
  fd = open(msr_filename, O_RDONLY);
  return fd;
}

static u_int64_t read_msr(int fd, int which) {

  u_int64_t data;

  if ( pread(fd, &data, sizeof(data), which) != sizeof(data) ) {
    perror("rdmsr:pread");
    exit(127);
  }

  return data;
}

#define CPU_SANDYBRIDGE 42
#define CPU_SANDYBRIDGE_EP 45
#define CPU_IVYBRIDGE 58
#define CPU_IVYBRIDGE_EP 62
#define CPU_HASWELL 60

static int detect_cpu(void) {

  FILE *fff;

  int family,model=-1;
  char buffer[BUFSIZ],*result;
  char vendor[BUFSIZ];

  fff=fopen("/proc/cpuinfo","r");
  if (fff==NULL) return -1;

  while(1) {
    result=fgets(buffer,BUFSIZ,fff);
    if (result==NULL) break;

    if (!strncmp(result,"vendor_id",8)) {
      sscanf(result,"%*s%*s%s",vendor);

      if (strncmp(vendor,"GenuineIntel",12)) {
	return -1;
      }
    }

    if (!strncmp(result,"cpu family",10)) {
      sscanf(result,"%*s%*s%*s%d",&family);
      if (family!=6) {
	return -1;
      }
    }

    if (!strncmp(result,"model",5)) {
      sscanf(result,"%*s%*s%d",&model);
    }

  }

  fclose(fff);

  switch(model) {
  case CPU_SANDYBRIDGE:
    break;
  case CPU_SANDYBRIDGE_EP:
    break;
  case CPU_IVYBRIDGE:
    break;
  case CPU_IVYBRIDGE_EP:
    break;
  case CPU_HASWELL:
    break;
  default:
    model=-1;
    break;
  }

  return model;
}

energy_counters_init_res energy_counters_init(energy_counters_state* state){
#if defined(__linux__)
  u_int64_t result;
  memset(state, 0, sizeof(energy_counters_state));
  state->cpu_model=detect_cpu();
  if(state->cpu_model<0){
    return UNSUPPORTED_CPU_TYPE;
  }

  FILE *f;
  int n=0;
  char command[512];
  f = popen("cat /proc/cpuinfo | grep 'physical id' | sort -u | wc -l", "r");
  if (!f || fscanf(f, "%d", &n) == EOF) { pclose(f); return NUMBER_OF_SOCKETS_NOT_FOUND;}
  pclose(f);
  state->num_sockets=n;
  state->sockets=(socket_state*)malloc(sizeof(socket_state)*state->num_sockets);
  memset(state->sockets, 0, sizeof(socket_state)*state->num_sockets);

  unsigned int i;
  for(i=0; i<state->num_sockets;i++){
    sprintf(command, "cat /proc/cpuinfo | egrep 'processor|physical id' | tr -d '\t' "
                     "| tr -d ' ' | paste -d'|' - - | grep 'physicalid:%d' "
                     "| cut -d '|' -f 1 | cut -d ':' -f 2 | head -1", i);
    f = popen(command,"r");
    if (!f || fscanf(f, "%d", &n) == EOF) { pclose(f); return PROCESSOR_PER_SOCKET_NOT_FOUND;}
    pclose(f);
    state->sockets[i].core=n;
    state->sockets[i].fd=open_msr(n);
    if(state->sockets[i].fd<0){
      return IMPOSSIBLE_TO_OPEN_MSR_FILE;
    }
    /* Calculate the units used */
    result=read_msr(state->sockets[i].fd,MSR_RAPL_POWER_UNIT);
    state->sockets[i].power_per_unit=pow(0.5,(double)(result&0xf));
    state->sockets[i].energy_per_unit=pow(0.5,(double)((result>>8)&0x1f));
    state->sockets[i].time_per_unit=pow(0.5,(double)((result>>16)&0xf));

    result=read_msr(state->sockets[i].fd,MSR_PKG_POWER_INFO);
    state->sockets[i].thermal_spec_power=state->sockets[i].power_per_unit*(double)(result&0x7fff);
  }
  return OK;
#else
  return OS_NOT_SUPPORTED;
#endif
}

u_int32_t energy_counters_wrapping_time(energy_counters_state* state){
  u_int32_t r=0xFFFFFFFF;
  unsigned int i;
  double wrapping_time;
  for(i=0; i<state->num_sockets; i++){
    wrapping_time=0xFFFFFFFF * state->sockets[i].energy_per_unit / state->sockets[i].thermal_spec_power;
    if(wrapping_time<r){
      r=std::floor(wrapping_time);
    }
  }
  return r;
}

void energy_counters_terminate(energy_counters_state* state){
  if(state){
    unsigned int i;
    for(i=0; i<state->num_sockets;i++){
      close(state->sockets[i].fd);
    }
    free(state->sockets);
  }
}


int energy_counters_read(energy_counters_state* state) {
  u_int64_t result;
  unsigned int i;
  for(i=0; i<state->num_sockets; i++){
    result=read_msr(state->sockets[i].fd,MSR_PKG_ENERGY_STATUS);
    state->sockets[i].energy_units_socket=result&0xFFFFFFFF;

    result=read_msr(state->sockets[i].fd,MSR_PP0_ENERGY_STATUS);
    state->sockets[i].energy_units_cores=result&0xFFFFFFFF;

    if ((state->cpu_model==CPU_SANDYBRIDGE) || (state->cpu_model==CPU_IVYBRIDGE) ||
        (state->cpu_model==CPU_HASWELL)) {
      result=read_msr(state->sockets[i].fd,MSR_PP1_ENERGY_STATUS);
      state->sockets[i].energy_units_offcores=result&0xFFFFFFFF;
    }else{
      result=read_msr(state->sockets[i].fd,MSR_DRAM_ENERGY_STATUS);
      state->sockets[i].energy_units_dram=result&0xFFFFFFFF;
    }
  }
  return 0;
}
