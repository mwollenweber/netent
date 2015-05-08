/*
 *  main.h
 *  netent
 *
 *  Created by mjw on 9/10/09.
 *  Copyright 2009. All rights reserved.
 *  Licensed under the GPL
 *
 */

#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <vector.h>
#include <signal.h>
#include "tdsplaytree.h"

typedef unsigned long DWORD; // 32 bits
typedef long long DWORD64;
typedef unsigned char BYTE;


#define BLOCKSIZE 1024
#define ETH_HEADER_SIZE 14
#define PROTO_TCP 6
//<tolerance -> zero
#define TOLERANCE .01
#define ALARMTIME 90
#define MINBYTETHRESH 1024
#define MAXDNSSTR 512
#define MAXSLEEP 30


#define IP_V(ip)   (((ip)->ip_hl & 0xf0) >> 4)
#define IP_HL(ip)  ((ip)->ip_hl & 0x0f)
#define TH_OFF(th) (((th)->th_off & 0xf0) >> 4)


#define CLOSED 0
#define ESTABLISHED 1
#define SYN	2
#define SYNACK 3


struct netflow
{
	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned long s_size;
	unsigned long d_size;
	short state;
	char * sbanner;
	char * dbanner;
	char * s_dnsname;
	char * d_dnsname;
	
	
	long long id;
	time_t start_time;
	time_t last_time;
	unsigned long packet_count;
	float ratio;
	bool capture; //packet capture
	bool interesting; //always mark as iteresting
	
};

struct netstats
{
	long long total_bytes;
	long long total_sent;
	long long total_recv;
	unsigned long avg_sent;
	unsigned long avg_recv;
	unsigned long num_connections;
	
	long long max_sent;
	long long max_recv;
	float max_ratio;
	float min_ratio;
	float avg_ratio;
	
};

/*
struct dnstrac
{
	char name[MAXDNSSTR];
	vector<unsigned long> vips;
};
 

 */
struct burst_delta
{
	unsigned long sqr_diff_sum;
	//int lasttime; could use this from the iv.
	int count;
	unsigned long id;
};

struct nstat
{
	float stddev;
	float avg;	
};

void init_netflow(struct netflow & f);
void check_packet();
void find_user_agent();
int Cmp(const netflow & , const netflow &);
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void process_packet (u_char *args, const struct pcap_pkthdr *pkthdr, const u_char * packet);
ostream& operator << (ostream & output, const netflow x);
int HashCmp(const netflow & x, const netflow & y);
netstats get_stats(vector <netflow *> * v);
ostream& operator << (ostream & output, const netstats x);
void sighandler (int param);
vector <netflow *> * GetInteresting(vector <netflow *> *v, const netstats  & s);
//stat compute_stddev(vector<netflow *> * v, size_t offset);
unsigned int alarm (unsigned int seconds);
void catch_alarm (int sig);
void print_stats();

//http://www.umiacs.com/sockaddr_inman.html
//http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
//http://yuba.stanford.edu/~casado/pcap/section4.html
