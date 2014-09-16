#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include <pcap.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <ff/mapping_utils.hpp>
#include <ff/utils.hpp>
#include <ff/ubuffer.hpp>

#define CAPACITY_CHUNK 1000
#define DPI_CACHE_LINE_SIZE 64
#define BURST_SIZE 100.0
#define CLOCK_FREQ 2000000000L
#define CLOCK_RESYNC 10


static unsigned char** packets;
static u_int32_t* sizes;
static u_int32_t num_packets=0;
static unsigned int intervals;
static double* rates;
static double* durations;
static unsigned int stats_collection_interval;
static u_int32_t current_interval=0;
static time_t last_sec=0;
static time_t start_time=0;
static double current_real_rate=0;
static u_int64_t processed_packets=0;
static int terminating=0;

inline ticks ticks_wait(ticks nticks) {
  ticks delta;
  ticks t0 = getticks();
  do { delta = (getticks()) - t0; } while (delta < nticks);
  return delta-nticks;
}

double getmstime(){
  struct timeval  tv;
  gettimeofday(&tv, NULL);

  return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ;
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

void* clock_thread(void*){
  int i = 0;
  time_t tmp;
  ff_mapThreadToCpu(0, -20);
  //  last_sec = time(NULL);
  while(!terminating){
    /**
    sleep(1);
    if(i++ == CLOCK_RESYNC){
      i = 0;
      tmp = time(NULL);
      if(tmp>=last_sec){
        last_sec = tmp;
      }
    }else{
      ++last_sec;
    }
    **/
    ;
  }
  return NULL;
}


static int dummy = 0;
void* spinner_thread(void*){
  while(!terminating){
    ++dummy;
  }
}

void load_packets_from_file(char* filename){
  pcap_t* handle = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char* packet;
  struct pcap_pkthdr header;
  u_int32_t current_capacity=0;
  FILE* sizesfile = NULL;
  sizesfile = fopen("sizes.txt", "w+");

  handle=pcap_open_offline(filename, errbuf);
  if(handle==NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n",
	    filename, errbuf);
    exit(EXIT_FAILURE);
  }

  packets=(unsigned char**)
    malloc(sizeof(unsigned char*)*CAPACITY_CHUNK);
  sizes=(u_int32_t*)
    malloc((sizeof(u_int32_t))*CAPACITY_CHUNK);
  assert(packets);
  assert(sizes);
  current_capacity+=CAPACITY_CHUNK;
  while((packet=pcap_next(handle, &header))!=NULL){
    if((((struct ether_header*) packet)->ether_type)!=
       htons(ETHERTYPE_IP) &&
       (((struct ether_header*) packet)->ether_type!=
	htons(ETHERTYPE_IPV6))){
      continue;
    }

    if(num_packets==current_capacity){
      packets=(unsigned char**)
	realloc(packets, sizeof(unsigned char*)*
		(current_capacity+CAPACITY_CHUNK));
      sizes=(u_int32_t*)
	realloc(sizes, sizeof(u_int32_t)*
		(current_capacity+CAPACITY_CHUNK));
      current_capacity+=CAPACITY_CHUNK;
      assert(packets);
      assert(sizes);
    }

    assert(header.len>sizeof(struct ether_header));

    posix_memalign((void**) &(packets[num_packets]),
		   DPI_CACHE_LINE_SIZE,
		   sizeof(unsigned char)*
		   (header.len-sizeof(struct ether_header)));
    assert(packets[num_packets]);
    memcpy(packets[num_packets],
	   packet+sizeof(struct ether_header),
	   (header.len-sizeof(struct ether_header)));
    sizes[num_packets]=
           (header.len-sizeof(struct ether_header));
    fprintf(sizesfile, "%u\n", sizes[num_packets]);
    ++num_packets;
  }
  fclose(sizesfile);
  printf("Read %llu packets.\n", num_packets);
  pcap_close(handle);
}


static void load_rates(char* fileName){
  FILE* f = NULL;
  char line[512];
  f = fopen(fileName, "r");
  float rate = 0;
  float duration = 0;
  unsigned int size = 0;
  rates = (double*) malloc(sizeof(double)*10);
  durations = (double*) malloc(sizeof(double)*10);
  size = 10;
  intervals = 0;
  if(f){
    while(fgets(line, 512, f) != NULL){
      sscanf(line, "%f %f", &rate, &duration);
      rates[intervals] = rate;
      durations[intervals] = duration;
      ++intervals;

      if(intervals == size){
        size += 10;
        rates = (double*) realloc(rates, sizeof(double)*size);
        durations = (double*) realloc(durations, sizeof(double)*size);
      }
    }
    fclose(f);
  }
  printf("Loaded %u rate intervals\n", intervals);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char* pcapfile = NULL;

    char buffer[256];

    time_t current_interval_start=0;
    u_int32_t current_burst_size = 0;
    ticks excess = 0;
    ticks def = getticks();
    double start_interval_ms;
    u_int32_t next_packet_to_send = 0;
    u_int64_t current_interval_packets = 0;
    u_int64_t current_interval_bytes = 0;

    if (argc < 4) {
       fprintf(stderr,"usage %s hostname port pcapfile\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    pcapfile = argv[3];
    sockfd = socket(AF_INET, SOCK_STREAM, 0 );
    if (sockfd < 0) {
        error("ERROR opening socket");
    }
    printf("Socket opened.\n");

    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    printf("Host found.\n");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
  
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    
    serv_addr.sin_port = htons(portno);

     if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        error("ERROR connecting");
    }
    printf("Connected.\n");


    pthread_t clock, spinner;
    pthread_create(&clock, NULL, clock_thread, NULL);
    pthread_create(&spinner, NULL, spinner_thread, NULL);
    load_packets_from_file(pcapfile);
    load_rates("rates.txt");

    unsigned long last_ts=getticks();
    FILE*  realratesfile = fopen("realrates.txt", "w+");

    while(true){
      if(next_packet_to_send==num_packets){
	next_packet_to_send=0;
      }

      if(current_interval >= intervals){
	printf("Finishing!\n");
	fflush(stdout);
	terminating = 1;
	pthread_join(clock, NULL);
	pthread_join(spinner, NULL);
	break;
      }

      if(current_burst_size == BURST_SIZE){
	/** Sleep to get the rate. **/
	double wait_interval_secs = 1.0 / rates[current_interval];
	ticks ticks_to_sleep = (((double)CLOCK_FREQ * wait_interval_secs - 0) * (double) BURST_SIZE);

	current_burst_size = 0;

	excess += (getticks()-def);

	if(excess >= ticks_to_sleep){
	  excess = 0;
	  //excess -= ticks_to_sleep;
	}else{
	  excess = ticks_wait(ticks_to_sleep - excess);
	}

	def = getticks();
      }


      ++current_burst_size;

      if(getticks()-last_ts>CLOCK_FREQ){
	last_ts = getticks();
	++last_sec;
      }



      if(current_interval_start == 0){
	current_interval_start = last_sec;
	start_interval_ms = getmstime();
      }

      ++processed_packets;
      ++current_interval_packets;
      current_interval_bytes+=sizes[next_packet_to_send];

      /** Go to the next rate **/
      if(last_sec - current_interval_start >= durations[current_interval]){
	printf("Sent: %lu packets in this interval. Error: %f Gbps: %f\n", current_interval_packets, (current_interval_packets/durations[current_interval] - rates[current_interval]) / rates[current_interval] * 100.0, (((double)current_interval_bytes*8.0)/1000000000.0)/durations[current_interval]);
	fprintf(realratesfile, "%f\n", current_interval_packets/durations[current_interval]);
	fflush(realratesfile);

        current_interval_packets = 0;
	current_interval_bytes = 0;

	current_interval_start = last_sec;
	current_interval++;
	start_interval_ms = getmstime();
      }

      n = write(sockfd,packets[next_packet_to_send],sizes[next_packet_to_send]);

      ++next_packet_to_send;

      if (n < 0) {
	error("ERROR writing to socket");
      }

    }
    printf("Sent %llu packets\n", processed_packets);
    printf("dummy: %d\n", dummy);
    close(sockfd);
    fclose(realratesfile);
    return 0;
}
