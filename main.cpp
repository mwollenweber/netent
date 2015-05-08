/*
 *  main.cpp
 *  netent
 *
 *  Created by mjw on 9/10/09.
 *  Copyright 2009. All rights reserved.
 *  Licensed under the GPL
 *
 *  Notes: This software is a proof of concept prototype. It is NOT suitable for 
 *		   for use on production networks. If you're a developer, this code will
 *         likely be difficult to maintain. It has many structures and quirks 
 *         designed to make the tool scale -- while at the same time having 
 *         artifacts relating to the prototype nature of the code.
 *
 *
 * Purpose:	This tool is designed to test various network sensing ideas. Below 
 *			is a partial list of included or to be included ideas:
 *				1. Statistical volume analysis of sent/received ratios to detect
 *				   exfiltration/botnets. 
 *				2. burst message time statistics
 *				3. Generic DPI
 *
 *	TODO:
 *		1. I want to be able to directed graphs
 *		2. Fastflux botnet. Track rapid dns changes. 
 *
 *		//boost library for directed graphs
 */

#include "netent.h"
#include <time.h>
#include <pthread.h>
#include <libnet.h>


#define SENT 1
#define RATIO 2
#define RECV 3
#define TIME 4

#define DEFAULTSLEEP 5
#define FFSLEEP		60
#define RECORDTIMEOUT 60*60*4
#define PRUNESLEEP 60*10

int run_stats = 0;
int start_exit = 0;
int compress_view = 0;
int track_timing = 0;
int do_dpi = 0;
int STATUS = 1;
int capture = 0;
float std_tune = 1.0;
int watch_fastflux = 0;

TD_Splay_Tree <netflow> * g_treeptr;
vector <netflow *> * g_vptr;
vector <ip *> * g_capvptr;

pthread_mutex_t g_tree_mutex    = PTHREAD_MUTEX_INITIALIZER;

static void *input_thread_func(void *vptr_args);
nstat compute_src_stddev(vector<netflow *> * v);
nstat compute_ratio_stddev(vector<netflow *> * v);
nstat compute_dest_stddev(vector<netflow *> * v);
vector <netflow *> * find_host_netflows(unsigned long target);


int main (int argc, char * const argv[]) 
{
    printf("Starting netent.\n");
	
	char * device;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */

	//time_t t1=time(NULL);

	int e = 0;
	char filter[] = "tcp and ip";
	
	void (*prev_fn)(int);
	prev_fn = signal (SIGINT,sighandler);
	signal (SIGALRM, catch_alarm); //callback on catching the alarm
	alarm(ALARMTIME);
	
	cout << "size of long long = " << sizeof(long long) << endl;
	cout << "size of dword=" << sizeof(DWORD) << endl;
	cout << "size of BYTE=" << sizeof(BYTE) << endl;
	cout << "size of double=" << sizeof(double) << endl;
	cout << "size of float=" << sizeof(float) << endl;
	
	//launch input thread
	//launch DPI thread
	
	pthread_t input_thread, dpi_thread, stats_thread;
	
    if (pthread_create(&input_thread, NULL, input_thread_func, NULL) != 0)
    {
        cerr << "Thread Error. Exiting\n";
		exit(EXIT_FAILURE);
    }
	
	

	
	device = pcap_lookupdev(errbuf);
	if(device == NULL)
	{
		fprintf(stderr, "defaulting device to en0");
		device = strdup("en0");
	}
	
	/* ask pcap for the network address and mask of the device */
    pcap_lookupnet(device,&netp,&maskp,errbuf);

	
	handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "%s", errbuf);
		exit(-2);
	}
	
	//EN10MB works for 100MB
	if(pcap_set_datalink(handle, DLT_EN10MB) == -1)
	{
		pcap_perror(handle, "ERROR setting datalink\n");
		exit(-3);
	}
	 
    if(pcap_compile(handle,&fp,filter,0,netp) == -1)
    { 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		fprintf(stderr, "Filter is: %s\n", filter);
		exit(-4); 
	}
	
    if(pcap_setfilter(handle,&fp) == -1)
    { 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
 
    e = pcap_loop(handle,-1,process_packet,NULL);
	
	
	fprintf(stderr, "Exiting\n");
    return 0;
}


void process_packet (u_char *args, const struct pcap_pkthdr *pkthdr, const u_char * packet)
{
	//static TD_Splay_Tree <netflow> flowtree(Cmp);
	static TD_Splay_Tree <netflow> flowtree(HashCmp);
	static unsigned long packet_count = 0;
	struct netflow myflow;
	struct ip * ippkt;
	struct tcphdr * tcppkt;

	int size_ip = 0, size_tcp = 0, data_size = 0;
	struct netflow * flow_ptr = NULL;

	char * data;
	g_treeptr = &flowtree;
	
	memset(&myflow, 0, sizeof(netflow));
	
	
	ippkt = (struct ip *) (packet + sizeof(struct ether_header));
	if(ippkt->ip_p != PROTO_TCP)
	{
		return;
	}
	size_ip = 4* IP_HL(ippkt);
	if(size_ip < 20)
	{
		cerr << "error. ip size is too small\n" << endl;
	}
	
	tcppkt = (struct tcphdr *) (packet + ETH_HEADER_SIZE + size_ip);
	size_tcp = TH_OFF(tcppkt) * 4;
	data_size = ntohs(ippkt->ip_len) - (size_ip + size_tcp);
	
	myflow.saddr = ippkt->ip_src.s_addr;
	myflow.daddr = ippkt->ip_dst.s_addr;
	myflow.sport = ntohs(tcppkt->th_sport);
	myflow.dport = ntohs(tcppkt->th_dport);
	myflow.s_size = data_size;
	myflow.d_size = 0;
	myflow.ratio = ((float) myflow.s_size)/myflow.d_size;
	myflow.start_time = time(NULL);
	myflow.last_time = myflow.start_time;
	
	//if you need perfection use the slower compare
	myflow.id = (myflow.saddr ^ myflow.daddr) << 32 ; (0x0000FFFF & ((myflow.dport ^ 0xC0ED) ^ (myflow.sport ^ 0xBABE)));
	
	
	pthread_mutex_lock( &g_tree_mutex);
	flow_ptr = flowtree.Find_Or_Insert(myflow);
	pthread_mutex_unlock( &g_tree_mutex);

	packet_count++;
	if(flow_ptr == NULL)
	{
		//printf("flow inserted\n");
	}
	else 
	{
		//temporary collision check
		if((myflow.saddr != flow_ptr->saddr && myflow.saddr != flow_ptr->daddr) || (myflow.daddr != flow_ptr->saddr && myflow.daddr != flow_ptr->daddr))
			{
				cerr << "ERROR: likely bad collision" << endl;
				cerr << "s1=" << myflow.saddr << " d1=" << myflow.daddr;
				cerr << "\ts2=" << flow_ptr->saddr <<" d2=" <<flow_ptr->daddr <<endl;
				
			}
	
		if(flow_ptr->saddr == myflow.saddr)
			flow_ptr->s_size += data_size;
		else 
			flow_ptr->d_size += data_size;
		
		flow_ptr->ratio = ((float) flow_ptr->s_size)/flow_ptr->d_size;
		
		//this might be unwise
		flow_ptr->last_time = time(NULL);
		
		/*
		 //if(capture > 0)
		 if(flow_ptr->capture)
		 {
			ip * capture_pkt; 
			capture_pkt = malloc(ip_size);
			if(!capture_pkt)
				break;
		 
			g_capvptr->push_back(capture_pkt)
		 }
		 
		 */
		
	}
	
	if(run_stats == 1)
	{
		g_treeptr = &flowtree;
		print_stats();  //ideally would remove this call and only toggle the flag on
		run_stats = 0;
	}	
	
	data = (char *) (tcppkt + size_tcp);
	

	return;
	
	
}

netstats get_stats(vector <netflow *> * v)
{
	netflow * nfptr;
	netstats s;
	int size = v->size();
	float tmp;
	
	memset(&s, 0, sizeof(struct netstats));
	
	cout << "computing stats for " << size << " netflows" <<endl;
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = *it;
		
		s.total_recv += nfptr->d_size;
		s.total_sent += nfptr->s_size;
		
		if(nfptr->d_size != 0)
		{
			tmp = ((float) nfptr->s_size)/nfptr->d_size;

			if(tmp > s.max_ratio)
				s.max_ratio = tmp;
			if(tmp < s.min_ratio || (s.min_ratio - TOLERANCE) < 0)
				s.min_ratio = tmp;
			
		}
	}
	
	s.total_bytes = s.total_recv + s.total_sent;
	s.avg_recv = ((float) s.total_recv)/size;
	s.avg_sent = ((float) s.total_sent)/size;
	s.avg_ratio = ((float) s.total_sent)/((float) s.total_recv);
	
	
	return s;
}

vector <netflow *> * GetInteresting(vector <netflow *> * v, const netstats  & s)
{
	netflow * nfptr;
	vector <netflow *> * IntV = new vector<netflow *>;
	nstat src_stat  = compute_src_stddev(v);
	nstat ratio_stat = compute_ratio_stddev(v);
	nstat dest_stat = compute_dest_stddev(v);
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = *it;
		//fix me. say s.avg_sent + 2*std_dev && greater than max. 
		//if (nfptr->s_size > 2 * s.avg_sent || nfptr->ratio > 2* s.avg_ratio)
		if((nfptr->s_size > (2 *src_stat.stddev*std_tune + src_stat.avg)) || (nfptr->ratio > (2 * ratio_stat.stddev*std_tune + ratio_stat.avg)))
		{
			if((nfptr->s_size + nfptr->d_size) >= MINBYTETHRESH) 
				IntV->push_back(nfptr);
		}
		else if(nfptr->interesting == true)
			IntV->push_back(nfptr);
	}
		

	return IntV;
}

int RatioCmp(const netflow & x, const netflow &y)
{
	//return x.ratio > y.ratio;
	return 0;
}

int HashCmp(const netflow & x, const netflow & y)
{
	if(x.id > y.id)
		return 1;
	else if(x.id < y.id)
		return -1;
	else 
		return 0;
	
}

int IgnorePortsCmp(const netflow & x, const netflow & y)
{
	if(x.saddr > y.saddr)
		return 1;
	else if (x.saddr < y.saddr)
		return -1;
	else //equal
	{
		if(x.daddr > y.daddr)
			return 1;
		else if(x.daddr < y.daddr)
			return -1;
		else //equal
		{
			return 0;
		}
	}
	
}




int Cmp(const netflow & x, const netflow & y)
{
	if(x.saddr > y.saddr)
		return 1;
	else if (x.saddr < y.saddr)
		return -1;
	else //equal
	{
		if(x.daddr > y.daddr)
			return 1;
		else if(x.daddr < y.daddr)
			return -1;
		else //equal
		{
			if(x.sport > y.sport)
				return 1;
			else if(x.sport < y.sport)
				return -1;
			else 
			{
				if(x.dport > y.dport)
					return 1;
				else if(x.dport < y.dport)
					return -1;
				else
					return 0;
				
			}

		}
	}

	
	return 0;
}

netflow * build_inverse(netflow &x)
{
	netflow * ret;
	ret = (netflow *) malloc(sizeof(struct netflow));
	
	ret->saddr = x.daddr;
	ret->daddr = x.saddr;
	ret->dport = x.sport;
	ret->sport = x.dport;
	
	return ret;
	
}

//call compute_stddev(v, offsetof(netflow, field));
nstat compute_src_stddev(vector<netflow *> * v)
{
	float avg = 0.0;
	float stddev = 0.0;
	float * ptr;
	netflow * nfptr;
	struct nstat s;
	memset(&s, 0, sizeof(struct stat));
		
	int size = v->size();
	
	if(size == 0)
		return s;
	
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		avg += nfptr->s_size;
	}
	
	avg = (float) avg/((float) size);
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		stddev += ((float) (nfptr->s_size - avg)) * (nfptr->s_size - avg);
	}
	cout << "avg=" << (float) avg;
	stddev = (float) stddev/((float) size);
	stddev = (float) sqrt(stddev);
	cout << "\tstddev=" << stddev <<endl;
	s.avg = avg;
	s.stddev = stddev;
	
	return s;
}


nstat compute_dest_stddev(vector<netflow *> * v)
{
	float avg = 0.0;
	float stddev = 0.0;
	netflow * nfptr;
	struct nstat s;
	memset(&s, 0, sizeof(struct stat));
	
	int size = v->size();
	
	if(size == 0)
		return s;
	
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		avg += nfptr->d_size;
	}
	
	avg = (float) avg/((float) size);
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		stddev += ((float) (nfptr->d_size - avg)) * (nfptr->d_size - avg);
	}
	cout << "avg=" << (float) avg;
	stddev = (float) stddev/((float) size);
	stddev = (float) sqrt(stddev);
	cout << "\tstddev=" << stddev <<endl;
	s.avg = avg;
	s.stddev = stddev;
	
	return s;
}

nstat compute_ratio_stddev(vector<netflow *> * v)
{
	double avg = 0.0;
	double stddev = 0.0;
	netflow * nfptr;
	struct nstat s;
	memset(&s, 0, sizeof(struct stat));
	
	int size = v->size();
	
	if(size == 0)
		return s;
	
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		
		if(!(nfptr->ratio > 1000 || nfptr->ratio < TOLERANCE))
		{
			avg += (double) nfptr->ratio;
		}
	}
	
	avg = (float) avg/((float) size);
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		nfptr = (netflow *) *it;
		if(!(nfptr->ratio > 1000 || nfptr->ratio < TOLERANCE))
		{
			stddev += ((float) (nfptr->ratio - avg)) * (nfptr->ratio - avg);
		}
		
	}
	cout << "avg=" << (float) avg;
	stddev = (float) stddev/((float) size);
	stddev = (float) sqrt(stddev);
	cout << "\tstddev=" << stddev <<endl;
	s.avg = (float) avg;
	s.stddev = (float) stddev;
	
	return s;
}




u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct ether_header *eptr;  /* net/ethernet.h */
	
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    return eptr->ether_type;
}

ostream& operator << (ostream & output, const netflow x)
{
	char saddr[INET_ADDRSTRLEN];
	char daddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(x.saddr), saddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(x.daddr), daddr, INET_ADDRSTRLEN);
	output << "ID="<< x.id << "\t" <<saddr <<":" << x.sport << "\t\t" << daddr << ":" <<x.dport <<"\t sbytes= "<< x.s_size <<" dbytes= " <<x.d_size;
	return output;
}

ostream& operator << (ostream & output, const netstats x)
{
	output << "total bytes= " << x.total_bytes << " total_sent=" << x.total_sent <<" total_recv= "<< x.total_recv <<  " avg_sent= " << x.avg_sent << " total_sent/total_recv= " << x.avg_ratio << " max_ratio= " << x.max_ratio << " min_ratio= " << x.min_ratio << endl;
	return output;
}


void sighandler (int param)
{
	cout << endl << "CTRL+C Caught. Computing stats and exiting!" << endl;
	
	exit(1);
}

unsigned int alarm (unsigned int seconds)
{
	struct itimerval old, neww;
	neww.it_interval.tv_usec = 0;
	neww.it_interval.tv_sec = 0;
	neww.it_value.tv_usec = 0;
	neww.it_value.tv_sec = (long int) seconds;
	if (setitimer (ITIMER_REAL, &neww, &old) < 0)
		return 0;
	else
		return old.it_value.tv_sec;
}


void catch_alarm (int sig)
{
	run_stats = 1;
	alarm(ALARMTIME);
}

void print_stats()
{
	vector <netflow *> * v = NULL;
	vector <netflow *> *IntV = NULL;
	vector <netflow> compressed;
	
	netstats ns;
	if(g_treeptr == NULL)
	{
		cerr << "wtf dude. g_treeptr == NULL" << endl;
		return;
	}
	cout << "tree_size = "<< g_treeptr->Get_Size() << endl;
	

	v = g_treeptr->GetTreeVector();
	if(v)
	{
	
		ns = get_stats(v);
		cout << ns;
		IntV = GetInteresting(v, ns);
		
		if(compress_view != 1)
		{
			cout << "================ Interesting =================" << endl;
			for(vector<netflow *>::iterator it = IntV->begin(); it != IntV->end(); it++)
			{
				//cout << *it << endl;
				netflow * nfptr= *it;
				cout << *nfptr << endl;
			}
		}
		else //compressed view
		{
			//use a simpler hash pushing it onto compressed
			//merge records into ip1 <-> ip2 pairs ignoring ports
			
			
			//clear compressed
		}
		
		IntV->clear();
		delete IntV;
		
		
	}	
	else 
		{
			cerr << "Get tree as vector failed for some reason" << endl;
		}
	
	
	v->clear();
	delete v;
	
	cout << endl << endl;
	run_stats = 0;
	
}

static void *input_thread_func(void *vptr_args)
{
	char buf[256];
	char * arg1, * arg2;
	
	while(STATUS)
	{
		cout << "netent> ";
		cin.getline(buf, 255);
		if(strstr(buf, "exit"))
		{
			STATUS = 0; //exit
			cout << "exiting program" << endl;
			cout << "exiting will complete in " << MAXSLEEP << " seconds" << endl;
			sleep(MAXSLEEP);
			exit(0);
		}
		else if (strstr(buf, "stats"))
		{
			cout << "printing stats\n" << endl;
			//this shouldn't be called like this. will segfault if not initiated
			print_stats();
			
		}
		else if(strstr(buf, "help"))
		{
			cout << "netent v0.0.1 ALPHA software. Use at your own risk" << endl;
			cout << "(c) 2009 Matthew Wollenweber\nmjw@cyberwart.com" <<endl;
			cout << "implementing help might be a good idea" << endl<<endl;
		}
		else if(strstr(buf, "info"))
		{
			//dump more detailed info on a particular host
			//total packets sent
			//timing std dev
			//hostnames
			
			cout << "you can get info later when i'm not lazy" << endl;
			
			
		}
		else if(strstr(buf, "find"))
		{
			struct sockaddr_in addr;
			unsigned long t; 
			vector <netflow *> * v;
			
			arg1 = strtok(buf, " ");
			arg1 = strtok(NULL, " ");
			
			if(!inet_aton(arg1, &addr.sin_addr))
				continue;
			
			//convert ip to long unsigned
			t = inet_addr(arg1);
			
			//call vector <netflow *> * find_host_netflows(unsigned long target)
			v = find_host_netflows(t);
			if(!v || v->size() == 0)
				continue;
			
		
			//print everything in it
			for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
			{
				netflow * nfptr= *it;
				cout << *nfptr << endl;
				
			}
	
			//cleanup
			v->clear();
			delete v;
			
		}
		else if(strstr(buf, "drop"))
		{
			cout << "drop not yet implmented" << endl;
			//if i'm going to drop a record i need to lock the tree
		}
		else if(strstr(buf, "enable"))
		{
			cout << "advanced option enabling not implemented" << endl;
		}
		else if(strstr(buf, "capture"))
		{
			//cout << "host capture not implemented" << endl;
			capture = 1;
			
		}
		else if(strstr(buf, "set_interesting"))
		{
			cout << "host inspection not implemented" << endl;
		}
		else if(strstr(buf, "kill"))
		{
			cout << "connection killing not implemented" << endl;
		}
		else if(strstr(buf, "ignore"))
		{
			cout << "ignore not implemented" << endl;
		}
		else if(strstr(buf, "std_tune"))
		{
			arg1 = strtok(buf, " ");
			arg1 = strtok(NULL, " ");
			if(arg1 != NULL)
			{
				std_tune = atof(arg1);
				cout << "standard deviation tuned to 2 * " << std_tune << endl;
				//still need to update the stats
			}
		}
		else if(strstr(buf, "all"))
		{
			cout << "--- Entire Tree ---" << endl;
			if(g_treeptr)
			{
				pthread_mutex_lock( &g_tree_mutex);
				g_treeptr->In_Order_Print();
				pthread_mutex_unlock( &g_tree_mutex);
				
			}
		}
		else 
		{
			cout << "wft man?" << endl;
		}
	
		//find scans. many hosts/ports
		
		
		//sleep(1);
	}
	//status == 0. clean up for exit
	
	
	return 0;
}

void *  capture_packets(void *vptr_args)
{
	/*
	netflow * nfptr;
	
	static FILE * f = NULL;
	static char * filename = "./netflow.cap";
	
	if (f == NULL)
	{
		f = fopen(filename, "wb");
		if(!f)
		{
			//cerr << 
		}
	}
	if(capture_packets < 0)
	{
		if(f)
			fclose(f);
		
		sleep(10);
	}
	
	v = g_treeptr->GetTreeVector();
	if(v == NULL)
	{
		cerr << "ERROR: cannot capture. tree is null" << endl;
		return NULL;
	}
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		///gah no this isn't right. we're writing the packet. not the netflow
		nfptr = (netflow *) *it;
		if(nfptr->capture)
		{
			//write to a file
			//fwrite(*nfptr, 
			
		}
	}
	
	if(v!= NULL)
	{
		v->clear();
		delete v;
	}
	*/	
}

void getdnsname()
{
/*
 #include <sys/socket.h>#include <netdb.h>
 int getnameinfo(const struct sockaddr *sa, socklen_t salen,
 char *host, size_t hostlen,                char *serv, size_t servlen,
 int flags);
 */
	
}

vector <netflow *> * find_host_netflows(unsigned long target)
{
	vector <netflow *> * v;
	vector <netflow *> * ret = new vector <netflow *>;
	netflow * nfptr; 
	
	if(g_treeptr == NULL)
		return NULL;
	
	if(ret == NULL)
		return NULL;
	
	v = g_treeptr->GetTreeVector();
	if(v == NULL)
		return NULL;
	
	for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
	{
		netflow * nfptr= *it;
		if(nfptr->saddr == target || nfptr->daddr == target)
		{
			//apparently erasing while iterating over is potentially bad
			//v->erase(it);
			
			ret->push_back(nfptr);
		}
	}
	
	v->clear();
	delete v;
	
	return ret;
}

static void *timeout_prune_func(void *vptr_args)
{
	vector <netflow *> * v;
	netflow * nfptr; 
	time_t curr_time;

	while(STATUS)
	{
		sleep(PRUNESLEEP);
		curr_time = time(NULL);
		
		if(g_treeptr == NULL)
			continue;

		
		v = g_treeptr->GetTreeVector();
		if(v == NULL)
			continue;
		
		for(vector<netflow *>::iterator it = v->begin(); it != v->end(); it++)
		{
			netflow * nfptr= *it;
			if(1) //test here
			{
				pthread_mutex_lock( &g_tree_mutex);
				g_treeptr->Delete(*nfptr);
				pthread_mutex_unlock( &g_tree_mutex);
			}
		}
		
		v->clear();
		delete v;
		
		
		
	}
	
}

static void *watch_fastflux_func(void *vptr_args)
{
	while(STATUS)
	{
		if(watch_fastflux == 0)
			sleep(DEFAULTSLEEP);
		
		else 
		{
			//for item in dns_tree
			   //if item.ip_count > FASTFLUXMIN
			        //alert to fast flux
			
			//sleep fastfluxstime;
			
		}
	}
	
	//clean up here. STATUS = 0 exiting
	
	
}
