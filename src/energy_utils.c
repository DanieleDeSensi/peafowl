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

int energy_counters_get_available_frequencies(unsigned long** frequencies, unsigned int* num_frequencies){
#if defined(__linux__)
  unsigned long* r = NULL;
  FILE *f;
  unsigned int numfreqs = 0;
  unsigned int i = 0;
  unsigned long tmp = 0;
  f = popen("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies | wc -w", "r");
  if (!f || fscanf(f, "%u", &numfreqs) == EOF) { 
     pclose(f); 
     *frequencies = NULL;
     *num_frequencies = 0;
     return -1;
  }
  pclose(f);
  r = (unsigned long*) malloc(numfreqs*sizeof(unsigned long));
  f = popen("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies | tr ' ' '\n' |  sort -n |  grep -v '^$'", "r");

  if (!f) {
    pclose(f);
    *frequencies = NULL;
    *num_frequencies = 0;
    return -1;
  }

  for(i = 0; i<numfreqs; i++){
    if(fscanf(f, "%lu\n", &tmp) == EOF){
      pclose(f);
      free(r);
      *frequencies = NULL;
      *num_frequencies = 0;
      return -1;
    }
    r[i]=tmp;
  }
  pclose(f);
  *frequencies = r;
  *num_frequencies = numfreqs;
  return 0;
#else
  return -1;
#endif
}

static int energy_counters_set_governor(unsigned int core_id, const char* governor){
#if defined(__linux__)
  FILE *f;
  char dummy[512];
  char command[512];
  memset(command, 0, sizeof(command));
  snprintf(command, 512, "cat /sys/devices/system/cpu/cpu%u/cpufreq/scaling_available_governors | grep %s", core_id, governor);
  f = popen(command, "r");
  if (!f || fscanf(f, "%s", dummy) == EOF) {
    pclose(f);
    return -1;
  }
  pclose(f);

  memset(command, 0, sizeof(command));
  snprintf(command, 512,  "cpufreq-set -g %s -c %u", governor, core_id);
  system(command);
  return 0;
#else
  return -1;
#endif
}

int energy_counters_set_userspace_governor(unsigned int core_id){
  return energy_counters_set_governor(core_id, "userspace");
}

int energy_counters_set_ondemand_governor(unsigned int core_id){
  return energy_counters_set_governor(core_id, "ondemand");
}

int energy_counters_set_performance_governor(unsigned int core_id){
  return energy_counters_set_governor(core_id, "performance");
}

int energy_counters_set_conservative_governor(unsigned int core_id){
  return energy_counters_set_governor(core_id, "conservative");
}

int energy_counters_set_frequency(unsigned long frequency, unsigned int core_id){
#if defined(__linux__)
  char command[512];
  memset(command, 0, sizeof(command));
  snprintf(command, 512, "cpufreq-set -f %lu -c %u", frequency, core_id);
  system(command);
  return 0;
#else
  return -1;
#endif
}

int energy_counters_set_frequency(unsigned long frequency, unsigned int* cores_ids, unsigned int num_cores, short related){
#if defined(__linux__)
  char globcommand[4096];
  char command[512];
  unsigned int i = 0;
  memset(globcommand, 0, 1024);
  for(i=0; i<num_cores; i++){
  	memset(command, 0, sizeof(command));
 	snprintf(command, 512, "cpufreq-set -f %lu -c %u %s;", frequency, cores_ids[i], related?"-r":"");
	strcat(globcommand, command);
  }
  system(globcommand);
  return 0;
#else
  return -1;
#endif
}

int energy_counters_set_bounds(unsigned long lb, unsigned long ub, unsigned int core_id){
#if defined(__linux__)
  char command[512];

  memset(command, 0, sizeof(command));
  snprintf(command, 512, "cpufreq-set -d %lu -c %u", lb, core_id);
  system(command);

  memset(command, 0, sizeof(command));
  snprintf(command, 512, "cpufreq-set -u %lu -c %u", ub, core_id);
  system(command);

  return 0;
#else
  return -1;
#endif
}


/** 
 * Each line contains id of the virtual cores of a same physical core (separated by :).
 **/
#define GET_HT_MAPPING "egrep \"(( id|processo).*:|^ *$)\" /proc/cpuinfo | tr -d '\\t' | " \
                       "sed -e 's/^$/=/g' | tr '\\n' ' ' | tr '=' '\\n' | tr -d ' ' | " \
                       "sed -e 's/processor//g;s/physicalid//g;s/coreid//g' | cut -c 2- | " \
                       "awk -F \":\" '{ print $2 \":\" $3 \":\" $1}' | sort -n -t : -k 1,1 -k2,2 -k3,3 | " \
                       " awk -F ':' '{idx=$1\":\"$2}{a[idx]=(idx in a)?a[idx]\":\"$NF:$NF}END{for(i in a) print i\":\"a[i]}' | " \
                       "cut -d ':' -f 3,4 | sort -t : -n -k1,1"

#define GET_REAL_CORES_IDS GET_HT_MAPPING " | cut -d ':' -f 1"

#define GET_NUM_CPUS "grep \"physical id\" /proc/cpuinfo | sort -u | wc -l"

#define GET_NUM_REAL_CORES_PER_CPU "grep \"cpu cores\" /proc/cpuinfo | sort -u | cut -d\":\" -f2 | tr -d ' '"

#define GET_NUM_TOTAL_CORES "grep -c \"processor\" /proc/cpuinfo"

#define GET_ONE_ID_PER_SOCKET_PARAMETRIC "egrep \"(( id|processo).*:|^ *$)\" /proc/cpuinfo | tr -d '\\t' | sed -e 's/^$/=/g' | tr '\\n' ' ' | " \
                                         " tr '=' '\\n' | tr -d ' ' | sed -e 's/processor//g;s/physicalid//g;s/coreid//g' | cut -c 2- | " \
                                         "awk -F \":\" '{ print $2 \":\" $1}' | egrep \"%s\"  | sort -t : -k 1,1 -u | cut -d ':' -f 2"

int energy_counters_get_ht_core_siblings(unsigned int core_id, char* siblings){
#if defined(__linux__)
	FILE *f;
	char command[512];
	memset(command, 0, sizeof(command));
	snprintf(command, 512, "cat /sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", core_id);
	f = popen(command, "r");
	if (!f || fscanf(f, "%s", siblings) == EOF) {
	  pclose(f);
	  /** Fallback TODO **/
	  return -1;
	}
	pclose(f);
	return 0;
#else
	return -1;
#endif
}


int energy_counters_get_num_real_cores(unsigned int* num_cores){
#if defined(__linux__)
	FILE *f;
	unsigned int num_cpus = 0;
	unsigned int num_real_cores_per_cpu = 0;
	f = popen(GET_NUM_CPUS, "r");
	if (!f || fscanf(f, "%u", &num_cpus) == EOF) {
	  pclose(f);
	  *num_cores = 0;
	  return -1;
	}
	pclose(f);
        
	f = popen(GET_NUM_REAL_CORES_PER_CPU, "r");
        if (!f || fscanf(f, "%u", &num_real_cores_per_cpu) == EOF) {
          pclose(f);
          *num_cores = 0;
          return -1;
        }
	pclose(f);
	*num_cores = num_cpus * num_real_cores_per_cpu;
	return 0;
#else
	return -1;
#endif
}

int energy_counters_get_real_cores_identifiers(unsigned int* identifiers, unsigned int num_identifiers){
#if defined(__linux__)
  FILE *f;
  unsigned int i = 0;

  f = popen(GET_REAL_CORES_IDS, "r");

  if (!f) {
    pclose(f);
    return -1;
  }

  for(i = 0; i<num_identifiers; i++){
    if(fscanf(f, "%u\n", &(identifiers[i])) == EOF){
      pclose(f);
      return -1;
    }
  }
  pclose(f);
  return 0;
#else
  return -1;
#endif
}

int energy_counters_get_core_identifier_per_socket(unsigned int* identifiers_in, unsigned int num_identifiers_in, unsigned int** identifiers_out, unsigned int* num_identifiers_out){
#if defined(__linux__)
  FILE *f;
  unsigned int i = 0;
  char identifierslist[512];
  char command[1024];
  char tmp[32];
  memset(identifierslist, 0, sizeof(identifierslist));
  memset(command, 0, sizeof(command));

  for(i=0; i<num_identifiers_in; i++){
    memset(tmp, 0, sizeof(tmp));
    if(i == num_identifiers_in - 1){
      sprintf(tmp, ":%u$", identifiers_in[i]);
    }else{
       sprintf(tmp, ":%u$|", identifiers_in[i]);
    }
    strcat(identifierslist, tmp);
  }
  
  sprintf(command, GET_ONE_ID_PER_SOCKET_PARAMETRIC, identifierslist);

  f = popen(command, "r");

  if (!f) {
    pclose(f);
    return -1;
  }

  *identifiers_out = (unsigned int*) malloc(sizeof(double)*num_identifiers_in);
  *num_identifiers_out = 0;
  i = 0;

  while(fscanf(f, "%u\n", &((*identifiers_out)[i])) != EOF){
  	i++;
  }  
  *num_identifiers_out = i;
  pclose(f);
  return 0;
#else
  return -1;
#endif
}


