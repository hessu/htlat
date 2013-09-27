
/*
 *	Get a HTTP object, see how fast it goes
 */

#include <pthread.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#ifndef __sun__
#include <getopt.h>
#endif
#include <limits.h>

#include "hmalloc.h"


#ifdef OpenSSL
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#define VER_STR "htlat 1.0.0 with OpenSSL\n"
#else
#define VER_STR "htlat 1.0.0\n"
#endif
#define AUTH_STR " by \tHeikki Hannikainen <hessu@hes.iki.fi>,\n\tOsmo Paananen\n"
#define HELP_STR "Usage: htlat [-c (ssl)] [-y (use sslv2)] [-r (refresh)] [-o <timeout>]\n\
\t[-i (stdin)] [-q (quiet)] [-v (verbose)] [-w waitsecs>]\n\
\t[-d <request|headers|data>] [-s <sourceaddr>] [-t <threads>]\n\
\t[-u <user-agent|none>] [-e <reqdir>] [<host>[:<port>] <uri>]\n\n\tExample: htlat www.inet.fi /\n\tProxy: htlat cache.inet.fi:800 http://www.inet.fi/\n\tstdin: htlat -i < get.urls\n\
\thttps: htlat -c solo3.merita.fi /\n\
\thttps with sslv2: htlat -c -y solo3.merita.fi /\n\
\thttps with proxy: htlat cache.inet.fi:800 https://solo3.merita.fi/\n\
\n\
Explanation of results:\n\
\tresolv\t\thow long did name resolving take\n\
\ttcp\t\thow long did tcp handshaking take\n\
\treq\t\thow long it took to get first header after GET request had been sent\n\
\tdata\t\ttime from end-of-headers to the beginning of data\n\
\ttotal\t\ttime from GET request to the end of data\n\
"

#define URLLEN 8192
#define BUFLEN 1024 * 64
#define RESOLVBUFLEN 10240

//#define THRDEBUGGING
#ifdef THRDEBUGGING
#define THR_DEBUG(s) \
        do { fprintf(stderr, "** [%ld] %s\n", (long)pthread_self(), s); } while (0)
#else
#define THR_DEBUG(s)
#endif

char nullstr[] = "";
char user_agent_base[] = "User-Agent: ";
char def_user_agent[] = "User-Agent: Mozilla/4.6 [en] (X11; I; Linux 2.2.5 i686)\r\n";
char referer_base[] = "Referer: ";

char port_80[] = "80";
char port_443[] = "443";

char *user_agent = def_user_agent;
char *host = NULL;
char *port = port_80;
char *uri = NULL;
char *referer = nullstr;
int verbose = 0;
int showurls = 1;
int dumpreq = 0;
int dumpdata = 0;
int dumpheaders = 0;
int timeout = 0;
int urlsin = 0;
char *reqdir = NULL;
int refresh = 0;
int alarmed = 0;
int sleepbet = 0;
int threads = 1;
struct sockaddr_in my_sa;

int ssl = 0, sslv2 = 0;

long long total_size = 0;
long long total_resolv_lat, total_tcpcon_lat, total_req_lat, total_data_lat, total_total_lat;
long long min_resolv_lat = 0, min_tcpcon_lat = 0, min_req_lat = 0, min_data_lat = 0, min_total_lat = 0;
long long max_resolv_lat = 0, max_tcpcon_lat = 0, max_req_lat = 0, max_data_lat = 0, max_total_lat = 0;

struct timeval tic_started, tic_stopped;

int tried = 0;
int succ = 0;
int neterr = 0;
int debug = 0;

struct req_t {
	char host[URLLEN];
	char port[URLLEN];
	char uri[URLLEN];
	int complete_req;
};

struct dnscache_t {
	char *hostname;
	struct addrinfo *ai;
	struct dnscache_t *next;
} *dnscache = NULL;

pthread_mutex_t done_sem = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t urlavail_sem = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t urlread_sem = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t resolv_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lat_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t count_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dnscache_mut = PTHREAD_MUTEX_INITIALIZER;

/*
 *	Convert return values of gethostbyname() to a string
 */

char *h_strerror(int i)
{
	static char host_not_found[] = "Host not found";
	static char no_address[] = "No IP address found for name";
	static char no_recovery[] = "A non-recovable name server error occurred";
	static char try_again[] = "A temporary error on an authoritative name server";
	static char unknown_error[] = "Unknown error result code from resolver";
	
	switch (i) {
		case HOST_NOT_FOUND:
			return host_not_found;
		case NO_ADDRESS:
			return no_address;
		case NO_RECOVERY:
			return no_recovery;
		case TRY_AGAIN:
			return try_again;
		case -1:
			return strerror(errno);
		default:
			return unknown_error;
	}
}

/*
 *	Stupid caching DNS resolver
 */

struct addrinfo *h_gethostbyname(const char *hostname, const char *service, int *my_h_errno)
{
	struct dnscache_t *c;
	int i;
	struct addrinfo req, *ai;
	
	/* Look for an entry in the cache */
	pthread_mutex_lock(&dnscache_mut);
	for (c = dnscache; (c); c = c->next)
		if (!strcmp(c->hostname, hostname)) {
			/* found it, reorder addresses (move the first entry to the end) */
			pthread_mutex_unlock(&dnscache_mut);
			return c->ai;
			break;
		}
	
	fprintf(stderr, "dnscache miss for %s\n", hostname);
	/* No match, get the data from the real thing */
	memset(&req, 0, sizeof(req));
	req.ai_family   = 0;
	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = 0;
	ai = NULL;
	
	i = getaddrinfo(hostname, service, &req, &ai);
	                                                
	c = hmalloc(sizeof(*c));
	c->hostname = hstrdup(hostname);
	c->ai = NULL;
	
	if (i == 0) {
		/* got it, let's add it to the cache */
		c->ai = ai;
		
		/* add the new entry to the cache list */
		c->next = dnscache;
		dnscache = c;
	}
	
	pthread_mutex_unlock(&dnscache_mut);
	return ai;
}

/*
 *	Parse arguments
 */
 
void parse_args(int argc, char *argv[])
{
	int s;
	char *p;
	struct hostent *hp;
	int reqargs;
	
	memset(&my_sa, 0, sizeof(struct sockaddr_in));
	my_sa.sin_family = AF_INET;
	my_sa.sin_port = htons(0);
 	
	while ((s = getopt(argc, argv, "ycvqd:e:iru:s:w:o:f:t:?h")) != -1) {
	  switch (s) {
		case 'v':
			verbose = 1;
			break;
		case 'q':
			showurls = 0;
			break;
		case 'd':
			if (!strcasecmp(optarg, "data")) {
				dumpdata = 1;
			} else if (!strcasecmp(optarg, "headers")) {
				dumpheaders = 1;
			} else if (!strcasecmp(optarg, "request")) {
				dumpreq = 1;
			} else {
				fprintf(stderr, "Unknown -d parameter: %s\n", optarg);
				exit(1);
			}
			break;
		case 'i':
			urlsin = 1;
			break;
		case 'e':
			reqdir = hstrdup(optarg);
			break;
		case 'o':
			timeout = atoi(optarg);
			break;
		case 's':
			if (!(hp = gethostbyname(optarg))) {
				printf("-1 Unknown host %s: %s\n", optarg, h_strerror(h_errno));
				exit(1);
			}
			memset(&my_sa, 0, sizeof(struct sockaddr_in));
			memcpy(&my_sa.sin_addr, hp->h_addr_list[0], hp->h_length);
			break;
		case 'u':
			if (!strcasecmp(optarg, "none"))
				user_agent = nullstr;
			else {
				user_agent = hmalloc(strlen(optarg) + strlen(user_agent_base) + 4);
				sprintf(user_agent, "%s%s\r\n", user_agent_base, optarg);
			}
			break;
		case 'f':
			if (!strcasecmp(optarg, "none"))
				referer = nullstr;
			else {
				referer = hmalloc(strlen(optarg) + strlen(referer_base) + 4);
				sprintf(referer, "%s%s\r\n", referer_base, optarg);
			}
			break;
		case 'w':
			sleepbet = atoi(optarg);
			break;
		case 'r':
			refresh = 1;
			break;
		case 't':
			threads = atoi(optarg);
			break;
		case 'y':
			sslv2 = 1;
			break;
		case 'c':		/* enable ssl */
#ifdef OpenSSL
			port = port_443;
			ssl = 1;
#else
			printf("Openssl is not compiled in!\n");
			exit(1);
#endif
			break;
		case '?':
		case 'h':
			fprintf(stderr, "%s%s%s", VER_STR, AUTH_STR, HELP_STR);
			exit(1);
	}
	}
	
	if ((urlsin) || (reqdir))
		reqargs = 0;
	else
		reqargs = 2;
	
	if (optind + reqargs > argc) {
		printf("-1 Too few arguments!\n\n%s%s%s", VER_STR, AUTH_STR, HELP_STR);
		exit(1);
	}
	
	if (optind + reqargs < argc) {
		printf("-1 Too many arguments!\n%s", HELP_STR);
		exit(1);
	}
	
	if (reqargs) {
		host = hstrdup(argv[optind]);
		optind++;
		uri = hstrdup(argv[optind]);
		optind++;
		
		if ((p = strchr(host, ':'))) {
			*p = '\0';
			p++;
			port = p;
		}
	}
	
	if (threads < 1) {
		printf("-1 At least 1 thread needed.\n%s", HELP_STR);
		exit(1);
	}
}

/*
 * 	Returns difference of tv1 and tv2 in microseconds.
 */
 
long long calc_rtt(struct timeval tv1, struct timeval tv2)
{
	struct timeval tv;
	long long f, b;

	tv.tv_usec = tv1.tv_usec - tv2.tv_usec;
	tv.tv_sec = tv1.tv_sec - tv2.tv_sec;
	if (tv.tv_usec < 0) {
		tv.tv_sec -= 1L;
		tv.tv_usec += 1000000L;
	}
	f = tv.tv_usec;
	b = 1000000 * tv.tv_sec;
	f += b;

	return f;
}

/*
 *	Print summary
 */
 
void printsummary(void)
{
	double total_realf;
	long long total_real = 0;
#ifdef THRDEBUGGING
	struct dnscache_t *c;
#endif
	
	total_real = calc_rtt(tic_stopped, tic_started);
	if (total_real < 1)
		total_real = 1;
	total_realf = ((double)total_real / 1000000);
	
	if (total_total_lat < 1)
		total_total_lat = 1;
	//total_timef = (double)total_total_lat / 1000000;
	
	printf("TOTAL %d tr %d ok %d err %d nerr %lld b %.2f s %.2Lf b/s %.2f tps\n",
		tried, succ, tried - succ, neterr, total_size, total_realf, (long double)total_size / (long double)total_realf, (double)succ / total_realf);
	printf("\tLatency\tmin ms\tavg ms\tmax ms\n");
	printf("\tresolv\t%2.2f\t%2.2f\t%2.2f\n", (double)min_resolv_lat / 1000, (succ) ? ((double)total_resolv_lat / (double)succ / 1000) : 0, (double)max_resolv_lat / 1000);
	printf("\ttcp\t%2.2f\t%2.2f\t%2.2f\n", (double)min_tcpcon_lat / 1000, (succ) ? ((double)total_tcpcon_lat / (double)succ / 1000) : 0, (double)max_tcpcon_lat / 1000);
	printf("\treq\t%2.2f\t%2.2f\t%2.2f\n", (double)min_req_lat / 1000, (succ) ? ((double)total_req_lat / (double)succ / 1000) : 0, (double)max_req_lat / 1000);
	printf("\tdata\t%2.2Lf\t%2.2Lf\t%2.2Lf\n", (long double)min_data_lat / 1000, (succ) ? ((long double)total_data_lat / (long double)succ / 1000) : 0, (long double)max_data_lat / 1000);
	printf("\ttotal\t%2.2f\t%2.2f\t%2.2f\n", (double)min_total_lat / 1000, (succ) ? ((double)total_total_lat / (double)succ / 1000) : 0, (double)max_total_lat / 1000);
	
#ifdef THRDEBUGGING
	printf("DNS cache:\n");
	for (c = dnscache; (c); c = c->next) {
		printf("\t%s\n", c->hostname);
	}
#endif
}

/*
 *	alarm() sig handler
 */
 
void alarm_handler(int sig)
{
	printf("INTERRUPTED\n");
	gettimeofday(&tic_stopped, NULL);
	printsummary();
	exit(0);
}

/*
 *	create a client socket connected to PORT on HOSTNAME
 */

int connect_to(char *hostname, char *port, char *resbuf, int *reslen, long long *tcpcon_lat, long long *resolv_lat)
{
	struct addrinfo *ai;
	int s;
	int my_h_errno;
	struct timeval tic_constart, tic_congot, tic_resstart, tic_resend;
	
	*tcpcon_lat = 0;
	*resolv_lat = 0;
	
	if (verbose)
		fprintf(stderr, "DNS lookup... ");
	
	gettimeofday(&tic_resstart, NULL);
	if (!(ai = h_gethostbyname(hostname, port, &my_h_errno))) {
		*reslen += sprintf(resbuf + *reslen, "-2 Lookup failed: %s\n", h_strerror(my_h_errno));
		return -2;
	}
	gettimeofday(&tic_resend, NULL);
	
	/*
	if (verbose)
		fprintf(stderr, "Connecting to %s:%d...\n", inet_ntoa(sa.sin_addr), port);
	*/
	if (verbose)
		fprintf(stderr, "socket()... ");
	
	if ((s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {	/* get socket */
		if (showurls)
			*reslen = sprintf(resbuf + *reslen, "-3 socket(): %s\n", strerror(errno));
		return -3;
	}
	
 	if (verbose)
		fprintf(stderr, "bind()... ");
		
	if (bind(s, (struct sockaddr *)&my_sa, sizeof(my_sa))) {
		if (showurls)
			*reslen = sprintf(resbuf + *reslen, "-3 bind(): %s\n", strerror(errno));
		return -3;
	}
	
	if (verbose)
		fprintf(stderr, "connect()... ");
	
	gettimeofday(&tic_constart, NULL);
	if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {	/* connect */
		if (showurls)
			*reslen = sprintf(resbuf + *reslen, "-2 Connect failed: %s\n", strerror(errno));
		close(s);
		return -2;
	}
	gettimeofday(&tic_congot, NULL);
	
	*resolv_lat = calc_rtt(tic_resend, tic_resstart);
	*tcpcon_lat = calc_rtt(tic_congot, tic_constart);
	
	return s;
}


#ifdef OpenSSL


/*
 *      fgets alike function implemented for to use with openssl
 *      this is intented to be thread safe (reason for external buffer)
 */

inline int htlat_sgets(char *line, int line_length, char *temp_buffer, SSL *con)
{
	/* NOTE: parameter temp_buffer must be able to store BUFLEN bytes */
	
	char *tmp, *tmp2;
	
	int bytes_left = 0,  return_bytes = 0;
	
	*line = '\0';
	
	memcpy(&bytes_left, temp_buffer + sizeof(char *), sizeof(int));  
	do {
		if (bytes_left == 0) {
			if (debug)
				printf("Empty buffer, reading in stuff..\n");
			bytes_left = SSL_read(con, temp_buffer + sizeof(char *) + sizeof(int), BUFLEN - 2 - sizeof(char *) - sizeof(int));
			if (ERR_peek_error()) {
				while (ERR_peek_error()) {
					ERR_print_errors_fp(stderr);
				}
				return -1;
			}
			
			/*      printf("received data %d: %s<<EOF>\n", bytes_left, temp_buffer + sizeof(char*) + sizeof(int));  */
			
			/* first bytes of temp_buffer contain the pointer to next byte which is to be returned */
			/* next bytes contain the actual length of the buffer */
			tmp = temp_buffer + sizeof(char *) + sizeof(int);
			memcpy(temp_buffer, &tmp, sizeof(char *));
			
			/* let's save the amount of data we have left to process */
			memcpy(temp_buffer + sizeof(char *), &bytes_left, sizeof(int));
		} else {
			memcpy(&bytes_left, temp_buffer + sizeof(char *), sizeof(int));
		}
		
		memcpy(&tmp, temp_buffer, sizeof(char *));
  		tmp2 = tmp;
  		while (*tmp2 != '\n' && bytes_left > 0 && return_bytes < line_length) {
  			/*
  			if (*tmp2 < 32)
  				printf("<[%d]%d: >", return_bytes, *tmp2);
  			else
  				printf("<[%d]%d:%c>", return_bytes, *tmp2, *tmp2);
  			*/
  			
  			tmp2++;
  			return_bytes++;
  			bytes_left--;
  		}
  		
  		if (bytes_left <= 0) {
  			*temp_buffer = 0;
  			if (return_bytes < line_length) {
  				strncat(line, tmp, tmp-tmp2);
  			} else {
  				strncat(line, tmp, line_length);
  				line[line_length - 1] = '\0';
  				return 0;
  			}
  		}
  	}
  	
  	while (return_bytes < line_length && *tmp2 != '\n');
  	if (return_bytes  < line_length) {    
  		strncat(line,  tmp, return_bytes);
  		line[return_bytes] = '\0';
  		/*    printf("Returning string [%d:%s]\n", return_bytes, line);   */
  		tmp2++;
  		bytes_left--;
  		
  		if (*tmp2 == '\r') {
  			tmp2++;
  			bytes_left--;
  		}
  	} else {
  		strncpy(line, tmp, line_length);
  		tmp2 = &(tmp[line_length]) + 1;
  	}
  	memcpy(temp_buffer, &tmp2, sizeof(char *));
  	memcpy(temp_buffer + sizeof(char *), &bytes_left, sizeof(int));
  	return 0;
}

#endif


int read_response_code(char *buf) 
{
	char *p1 = NULL, *p2 = NULL;
	int res = 0;
	char temp[BUFLEN];
	
	strncpy(temp, buf, BUFLEN-1);
	
	if (!((p1 = strchr(temp, ' ')))) { 
		return -4;
	}
	
	/* temp is now HTTP version */
	*p1 = '\0';
	p1++;
	
	if (!((p2 = strchr(p1, ' ')))) {
		return -4;
	}
	
	/* p2 is now the result code (200 = OK, 302 = Moved temporarily see:RFC2068 ) */
	*p2 = '\0';
	p2++;
	
	res = atoi(p1);
	while ((p1 = strchr(p2, '\n')) || (p1 = strchr(p2, '\r')))
		*p1 = '\0';
	
	return res;
}

#ifdef OpenSSLds

int handle_ssl_errors() {
	
	switch (SSL_get_error(con,k)){
		case SSL_ERROR_NONE:
			if (k <= 0)
				goto end;
			sbuf_off = 0;
			sbuf_len = k;
			read_ssl = 0;
			write_tty = 1;
			break;
		case SSL_ERROR_WANT_WRITE:
			BIO_printf(bio_c_out,"read W BLOCK\n");
			write_ssl = 1;
			read_tty = 0;
			break;
		case SSL_ERROR_WANT_READ:
			BIO_printf(bio_c_out,"read R BLOCK\n");
			write_tty = 0;
			read_ssl = 1;
			if ((read_tty == 0) && (write_ssl == 0))
				write_ssl = 1;
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			BIO_printf(bio_c_out,"read X BLOCK\n");
			break;
		case SSL_ERROR_SYSCALL:
			BIO_printf(bio_err,"read:errno=%d\n",get_last_socket_error());
			goto shut;
		case SSL_ERROR_ZERO_RETURN:
			BIO_printf(bio_c_out,"closed\n");
			goto shut;
		case SSL_ERROR_SSL:
			ERR_print_errors(bio_err);
			goto shut;
			/* break; */
	}
}
#endif

/*
 *	Decide which Host header to send, based on uri, host and port
 *	(need to figure out if this request is for a proxy or a normal
 *	HTTP server, either form the header form ghost:gport for a normal
 *	server or grab it from the URL)
 */

void decidehost(char *ghost, char *gport, char *guri, char *buf, int buflen)
{
	char *p;
	char *p2;
	
	*buf = '\0';
	
	if (*guri == '/') {
		if (strcmp(gport, "80") == 0)
			snprintf(buf, buflen, "Host: %s\r\n", ghost);
		else
			snprintf(buf, buflen, "Host: %s:%s\r\n", ghost, gport);
	} else {
		if (!(p = strchr(guri, ':')))
			return;
		p++;
		if (!(p2 = strchr(p, '/')))
			return;
		p2++;
		if (!(p = strchr(p2, '/')))
			return;
		p++;
		if (!(p2 = strchr(p, '/')))
			return;
		strncpy(buf, "Host: ", buflen);
		strncpy(buf + strlen(buf), p, p2 - p);
		strncat(buf, "\r\n", buflen);
	}
	buf[BUFLEN-1] = '\0';
}


/*
 *	Get an object
 */
 
int getobj(char *ghost, char *gport, char *guri, int complete_req)
{
	int fd;
	FILE *f = NULL;
	int i = 0;
	char resbuf[1024];
	char tmpbuf[1024];  /* we use this with ssl since we don't have fprintfssl function */
	int reslen = 0;
	int retval = 200;
	
	char refstr[] = "Cache-Control: no-cache\r\nPragma: no-cache\r\n";
	char *refptr;
	char buf[BUFLEN];
	int len;

	long size = 0;
	
#ifdef OpenSSL
	char ssltempbuf[BUFLEN];
	char *p1, *p2;

	SSL_CTX *ctx = NULL;
	SSL_METHOD *meth = NULL;
	BIO *sbio;
	SSL *con = NULL;


	int  use_ssl = 0; /* if = 1 then we are using ssl functions for rest of stuff */
			  /* this means that we are talking to https server via proxy */

	
#endif 

	struct timeval tic_reqsent, tic_hdrgot, tic_datagot = { 0, 0}, tic_datadone;
	long long resolv_lat, tcpcon_lat, req_lat, data_lat, total_lat;
	float tcpcon_lat_f, req_lat_f, data_lat_f, total_lat_f;

	fflush(stdout);

	
#ifdef OpenSSL
	i = 0;
	memcpy(ssltempbuf + sizeof(char *), &i, sizeof(int));
	if (ssl) {
		if (verbose)
			fprintf(stderr, "Initializing ssl\n");
		if (sslv2) {
			meth = SSLv2_client_method(); 
		} else {
			meth=SSLv23_client_method();  
		}
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
		ctx = SSL_CTX_new(meth);
		if (ctx == NULL) {
			//	  ERR_print_errors(bio_err);
			fprintf(stderr, "Failed to get SSL context: SSL_CTX_new() returned NULL\n");
			goto done;
		}
		SSL_CTX_set_options(ctx,0);
		*ssltempbuf = 0;
	} 
#endif 
	if (refresh)
		refptr = refstr;
	else
		refptr = nullstr;
	
	if (showurls)
		reslen = sprintf(resbuf, "%s:%s %s ", ghost, gport, guri);
	
	/*
	 *	Connect
	 */

	if (verbose)
		fprintf(stderr, "Connecting to %s:%s...\n", ghost, gport);
	
	if ((fd = connect_to(ghost, gport, resbuf, &reslen, &tcpcon_lat, &resolv_lat)) < 0) {
		retval = fd;
		goto done;
	}
	
	if (verbose)
		fprintf(stderr, "Connected to %s:%s.\n", ghost, gport);

#ifdef OpenSSL
	if (ssl) {
		con = SSL_new(ctx);
		sbio = BIO_new_socket(fd,BIO_NOCLOSE);
		SSL_set_bio(con,sbio,sbio);
		SSL_set_connect_state(con);
	}
#endif
	
	if (!(f = fdopen(fd, "r+"))) {
		if (showurls)
			reslen += sprintf(resbuf + reslen, "-3 fdopen() failed: %s\n", strerror(errno));
		retval = -3;
		goto done;
	}
	
	/*
	 *	Send request
	 */
	
	if (verbose)
		fprintf(stderr, "Sending request... ");
	
	decidehost(ghost, gport, guri, buf, BUFLEN);
	
#ifdef OpenSSL
	if (strstr(guri, "https://") == guri) {
		p1 = guri + 8; /* skip the https: from the uri */
		p1 = strchr(p1, '/');
		if (p1 == NULL) {
			fprintf(stderr, "Malformed URI\n");
			exit(1);
		}
		
		*p1 = '\0';
		p1++;
		
		p2 = NULL;
		if ((p2 = strchr(guri, ':')) != NULL) {
			if (*p2) {
				p2++;
				if (strchr(p2, ':') == NULL)
					fprintf(f, "CONNECT %s:443 HTTP/1.0\r\n\n", guri);
				else
					fprintf(f, "CONNECT %s HTTP/1.0\r\n\n", guri);
				} else
					fprintf(f, "CONNECT %s HTTP/1.0\r\n\n", guri);
			} else
				fprintf(f, "CONNECT %s HTTP/1.0\r\n\n", guri);
			
			if (ssl) {
				printf("SSL enabled connections to proxy are not supported. Specify only SSL-enabled connection or https-page via http-proxy.\n");
				goto done;
			}
			
			if (fgets(buf, sizeof(buf), f) <= 0) {
				if (showurls)
					reslen += sprintf(resbuf + reslen, "-2 Read failed: %s\n", strerror(errno));
					retval = -2;
					goto done;
				}
				switch (read_response_code(buf)) {
					case -4:
						if (showurls)
							reslen += sprintf(resbuf + reslen, "-4 HTTP protocol error: No space 1\n");
						retval = -4;
						goto done;
						break;
					default:
						break;
				}
				
				if (verbose)
					fprintf(stderr, "Reading headers..\n");
				
				/* read through the rest of the headers */
				while (fgets(buf, sizeof(buf), f) > 0) {
					if (dumpheaders)
						printf("%s\n", buf);
					if ((buf[0] == '\r') || (buf[0] == '\n'))
						break;
				}
				
				if (sslv2)
					meth = SSLv2_client_method();
				else
					meth=SSLv23_client_method();
					
				OpenSSL_add_ssl_algorithms();
				SSL_load_error_strings();
				ctx = SSL_CTX_new(meth);
				if (ctx == NULL) {
					fprintf(stderr, "Failed to get SSL context: SSL_CTX_new() returned NULL\n");
					goto done;
				}
				SSL_CTX_set_options(ctx,SSL_OP_ALL);
				SSL_CTX_set_default_verify_paths(ctx);
				
				*ssltempbuf = 0;
				
				con = SSL_new(ctx);
				sbio = BIO_new_socket(fd,BIO_NOCLOSE);	
				SSL_set_bio(con,sbio,sbio);
				SSL_set_connect_state(con);
				
				use_ssl = 1;
				if (verbose) 
					fprintf(stderr, "Opened SSL-tunnel via proxy, getting page\n");
				sprintf(tmpbuf, "GET /%s HTTP/1.0\r\n%s%s%s%s\r\n", p1, buf, user_agent, referer, refptr);
			} else {
				if (complete_req)
					strcpy(tmpbuf, guri);
				else
					sprintf(tmpbuf, "GET %s HTTP/1.0\r\n%s%s%s%s\r\n", guri, buf, user_agent, referer, refptr);
			}
#else /* not OpenSSL */
	if (complete_req)
		strcpy(tmpbuf, guri);
	else
		sprintf(tmpbuf, "GET %s HTTP/1.0\r\n%s%s%s%s\r\n", guri, buf, user_agent, referer, refptr);
#endif
	if (dumpreq)
		fputs(tmpbuf, stdout);

#ifdef OpenSSL
	if (ssl || use_ssl) {
		SSL_write(con, tmpbuf, strlen(tmpbuf)); 
		
		if (ERR_peek_error()) {
			while (ERR_peek_error())
				ERR_print_errors_fp(stderr);
			goto done;
		}
	} else {
		if (fputs(tmpbuf, f) < 0) {
			if (showurls)
				reslen += sprintf(resbuf + reslen, "-2 Write failed: %s\n", strerror(errno));
			retval = -2;
			goto done;
		}
	}
#else
	if (fputs(tmpbuf, f) < 0) {
		if (showurls)
			reslen += sprintf(resbuf + reslen, "-2 Write failed: %s\n", strerror(errno));
		retval = -2;
		goto done;
	}
#endif
	fflush(f);
	gettimeofday(&tic_reqsent, NULL);
	
	/*
	 *	Read and parse response result code
	 */
	
	if (verbose)
		fprintf(stderr, "Reading response...\n");
	
#ifdef OpenSSL
	if (ssl == 1 || use_ssl) {
		i = htlat_sgets(buf, sizeof(buf), ssltempbuf, con);
		if (i == -1)
			goto done;
		if (dumpheaders)
			printf("%s\n", buf);
	} else {
		if (fgets(buf, sizeof(buf), f) <= 0) {
			if (showurls)
				reslen += sprintf(resbuf + reslen, "-2 Read failed: %s\n", strerror(errno));
			retval = -2;
			goto done;
		}
		if (dumpheaders)
			fputs(buf, stdout);
	}

#else	
	if (fgets(buf, sizeof(buf), f) <= 0) {
		if (showurls)
			reslen += sprintf(resbuf + reslen, "-2 Read failed: %s\n", strerror(errno));
		retval = -2;
		goto done;
	}
	if (dumpheaders)
		fputs(buf, stdout);
#endif
	gettimeofday(&tic_hdrgot, NULL);

	/* the result we are expecting after the GET -request is something like this:
	   HTTP/1.1 200 OK
	   Date: Mon, 22 May 2000 12:35:47 GMT
	   Server: Apache/1.3.3 (Unix) mod_ssl/2.0.13 SSLeay/0.9.0b
	   Last-Modified: Wed, 17 May 2000 11:40:34 GMT
	   ETag: "1692-b66-39228532"
	   Accept-Ranges: bytes
	   Content-Length: 2918
	   Connection: close
	   Content-Type: text/html
	   
	   <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
	   <HTML>
	   <HEAD>
	   
	*/
	

	

	switch (i = read_response_code(buf)) {
		case -4:
			if (showurls)
				reslen += sprintf(resbuf + reslen, "-4 HTTP protocol error: No space 1\n");
			retval = -4;
			goto done;
			break;
		case 1:
			if (showurls)
				reslen += sprintf(resbuf + reslen, "0 HTTP server error, server replied: %s\n", buf);
			retval = -4;
			goto done;
		default:
			retval = i;
			break;
	}
	
	/*
	 *	Read rest of headers
	 */
#ifdef OpenSSL
	if (ssl || use_ssl) {
		while (!(i = htlat_sgets(buf, sizeof(buf), ssltempbuf, con)) ) {
			if (dumpheaders) 
				printf("%s\n", buf);
			
			if ((buf[0] == '\r') || (buf[0] == '\n') || (buf[0] == '\0'))
				break;
		}
		
		if (i == -1)
			goto done;
	} else {
		while (fgets(buf, sizeof(buf), f) > 0) {
			if (dumpheaders)
				fputs(buf, stdout);
			if ((buf[0] == '\r') || (buf[0] == '\n'))
				break;
		}
	}
	
#else
	while (fgets(buf, sizeof(buf), f) > 0) {
		if (dumpheaders)
			fputs(buf, stdout);
		if ((buf[0] == '\r') || (buf[0] == '\n'))
			break;
	}

#endif	
	/*
	 *	Read data
	 */
	if (verbose)
		fprintf(stderr, "Reading in data, starting data timing.\n");
	fflush(stderr);
#ifdef OpenSSL
	if (ssl == 1 || use_ssl) {
		memcpy(&i, ssltempbuf + sizeof(char *), sizeof(int));  /* extract the lenght of data remaining in buff */
		memcpy(&p1, ssltempbuf, sizeof(char *));
		
		if (i > 0) {
			gettimeofday(&tic_datagot, NULL);
			if (verbose)
				printf("Receiving data, stopping data timing.\n");
			size += i;
			p1[i] = 0;
			if (dumpdata)
				printf("%s\n", p1);
		} else {
			fprintf(stderr, "warning: undisplayed data. %d, not gonna work. FIXME // Odie\n", i);
		}
		
		if (!SSL_read(con, buf, 1)) {
			if (i < 1) {
				fprintf(stderr, "No data available!\n");
				goto done;
			}
			if (dumpdata)
				printf("%c", *buf);
		}
		
		if (verbose && i < 1)
			printf("Receiving data, stopping data timing.\n");
			
		while ((len = SSL_read(con, buf, sizeof(buf))) > 0) {
			size += len;
			if (dumpdata)
				fwrite(buf, 1, len, stdout);
		}
	} else {
		if ((len = fread(&buf, 1, 1, f)) > 0) {
			gettimeofday(&tic_datagot, NULL);
			size += len;
			if (dumpdata)
				fwrite(&buf, 1, len, stdout);
		}
		
		while ((len = fread(&buf, 1, sizeof(buf), f)) > 0) {
			size += len;
			if (dumpdata)
				fwrite(&buf, 1, len, stdout);
		}
	}
#else
	
	if ((len = fread(&buf, 1, 1, f)) > 0) {
		gettimeofday(&tic_datagot, NULL);
		size += len;
		if (dumpdata)
			fwrite(&buf, 1, len, stdout);
	}
	
	while ((len = fread(&buf, 1, sizeof(buf), f)) > 0) {
		size += len;
		if (dumpdata)
			fwrite(&buf, 1, len, stdout);
	}
#endif	

	gettimeofday(&tic_datadone, NULL);
	if (verbose) 
		fprintf(stderr, "Data transfer completed.\n");
	fflush(stderr);
	
	if (ferror(f)) {
		if (showurls)
			reslen = sprintf(resbuf + reslen, "-2 Read failed: %s\n", strerror(errno));
		retval = -2;
		goto done;
	}
	
	/*
	 *	Print out results
	 */
	
	if (tcpcon_lat < 1) tcpcon_lat = 1;
	if (resolv_lat < 1) resolv_lat = 1;
	
	req_lat = calc_rtt(tic_hdrgot, tic_reqsent);


	/* tic_reqsent = time when GET request was made */
	/* tic_hdrgot  = time when first header line arrived */

	if (req_lat < 1) req_lat = 1;
	
	if (tic_datagot.tv_sec || tic_datagot.tv_usec)
		data_lat = calc_rtt(tic_datagot, tic_reqsent);
	else
		data_lat = 1;
	if (data_lat < 1) data_lat = 1;

	total_lat = calc_rtt(tic_datadone, tic_reqsent);
	if (total_lat < 1) total_lat = 1;
	if ((total_lat < min_total_lat) || (min_total_lat == 0)) min_total_lat = total_lat;
	if ((total_lat > max_total_lat) || (max_total_lat == 0)) max_total_lat = total_lat;
	
	if (dumpdata)
		fprintf(stdout, "\n\n");
	
	if (showurls) {
		tcpcon_lat_f = (float)tcpcon_lat / 1000;
		req_lat_f = (float)req_lat / 1000;
		data_lat_f = (float)data_lat / 1000;
		total_lat_f = (float)total_lat / 1000;
		
		reslen += sprintf(resbuf + reslen, "%d %ld bytes %.2f tcp %.2f req %.2f data %.2f ms %ld b/s\n",
			retval, size, tcpcon_lat_f, req_lat_f, data_lat_f, total_lat_f, (long)(size / (total_lat_f / 1000)));
	}
	
	
	/* Add to statistics */
	pthread_mutex_lock(&lat_mut);
	if ((resolv_lat < min_resolv_lat) || (min_resolv_lat == 0)) min_resolv_lat = resolv_lat;
	if ((resolv_lat > max_resolv_lat) || (max_resolv_lat == 0)) max_resolv_lat = resolv_lat;
	if ((tcpcon_lat < min_tcpcon_lat) || (min_tcpcon_lat == 0)) min_tcpcon_lat = tcpcon_lat;
	if ((tcpcon_lat > max_tcpcon_lat) || (max_tcpcon_lat == 0)) max_tcpcon_lat = tcpcon_lat;
	if ((req_lat < min_req_lat) || (min_req_lat == 0)) min_req_lat = req_lat;
	if ((req_lat > max_req_lat) || (max_req_lat == 0)) max_req_lat = req_lat;
	if ((data_lat < min_data_lat) || (min_data_lat == 0)) min_data_lat = data_lat;
	if ((data_lat > max_data_lat) || (max_data_lat == 0)) max_data_lat = data_lat;
	total_size += size;
	total_total_lat += total_lat;
	total_resolv_lat += resolv_lat;
	total_tcpcon_lat += tcpcon_lat;
	total_req_lat += req_lat;

	total_data_lat += data_lat;
	pthread_mutex_unlock(&lat_mut);

done:	
	if (f)
		fclose(f);
	if (showurls)
		printf("%s", resbuf);
	return retval;
}


/*
 *	Copy URL's from the main thread, and get them with getobj()
 */

void getthread(void *buf)
{
	struct req_t r;
	sigset_t sigs_to_block;
	int i;
#ifdef THRDEBUGGING
	long thr_got = 0;
#endif

	sigemptyset(&sigs_to_block);
	sigaddset(&sigs_to_block, SIGALRM);
	sigaddset(&sigs_to_block, SIGINT);
	sigaddset(&sigs_to_block, SIGTERM);
	sigaddset(&sigs_to_block, SIGQUIT);
	sigaddset(&sigs_to_block, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sigs_to_block, NULL);
	
	while (1) {
		THR_DEBUG("wait urlavail");
		if (pthread_mutex_lock(&urlavail_sem)) {
			perror("pthread_mutex_lock urlavail_sem failed");
			exit(3);
		}
		
		THR_DEBUG("got urlavail");
		memcpy((void *)&r, (void *)buf, sizeof(struct req_t));
		
		THR_DEBUG("copied url");
		if (pthread_mutex_unlock(&urlread_sem)) {
			perror("sem_post urlread_sem failed");
			exit(3);
		}
		
		if (r.port[0] == 0) {
#ifdef THRDEBUGGING
			fprintf(stderr, "** thread %ld did %ld objects\n", (long)pthread_self(), thr_got);
#endif
			return;
		}

		THR_DEBUG("getting");
		i = getobj(r.host, r.port, r.uri, r.complete_req);
		
		pthread_mutex_lock(&count_mut);
		tried++;
		if (i > 0)
			succ++;
		else if (i < 0)
			neterr++;
		pthread_mutex_unlock(&count_mut);
		
#ifdef THRDEBUGGING
		thr_got++;
#endif
	}
}

/*
 *	Main
 */

int main(int argc, char **argv)
{
	char s[URLLEN], *p;
	int i, l;
	pthread_t th[512];
	struct req_t r;
	DIR *d;
	struct dirent *de;
	char fname[PATH_MAX];

	parse_args(argc, argv);
	
	signal(SIGALRM, &alarm_handler);
	signal(SIGINT, &alarm_handler);
	signal(SIGTERM, &alarm_handler);
	signal(SIGQUIT, &alarm_handler);
	signal(SIGHUP, &alarm_handler);
	signal(SIGPIPE, SIG_IGN);
	
	if (timeout)
		alarm(timeout);

#if 0
	urlavail_sem = sem_open("htlat_urlavail", O_CREAT);
	urlread_sem = sem_open("htlat_urlread", O_CREAT);
	done_sem = sem_open("htlat_done", O_CREAT);
#elsif 0
	if (sem_init(&urlavail_sem, 0, 0)) {
	        perror("sem_init urlavail_sem failed");
	        exit(3);
	}
	if (sem_init(&urlread_sem, 0, 0)) {
	        perror("sem_init urlread_sem failed");
	        exit(3);
	}
	if (sem_init(&done_sem, 0, 0)) {
	        perror("sem_init done_sem failed");
	        exit(3);
	}
#endif
	pthread_mutex_lock(&urlread_sem);
	pthread_mutex_lock(&urlavail_sem);
	
	r.complete_req = 0;
	
	gettimeofday(&tic_started, NULL);
	
	if ((urlsin) || (reqdir)) {
		/* start up threads */
		for (i = 0; i < threads; i++) {
			if (pthread_create(&th[i], NULL, (void *)getthread, (void *)&r)) {
				perror("pthread_create failed");
				exit(3);
			}
			//pthread_detach(th);
		}
		
		gettimeofday(&tic_started, NULL);
		
		if (urlsin) {
			/* read requests from stdin */
			while (fgets(s, URLLEN, stdin)) {
				if ((p = strchr(s, '\n')))
					*p = '\0';
				
				host = s;
				if ((uri = strchr(host, ' '))) {
					*uri = '\0';
					uri++;
				} else {
					if (showurls)
						printf("/ -1 AIEE No URI on line!\n");
					continue;
				}
				
				if ((p = strchr(host, ':'))) {
					*p = '\0';
					p++;
					port = p;
				} else
					port = port_80;
					
				if ((p = strchr(uri, ' ')))
					*p = '\0';
				if ((p = strchr(host, ' ')))
					*p = '\0';
				
				strcpy(r.host, host);
				strcpy(r.port, port);
				strcpy(r.uri, uri);
				
				/* Let a worker thread catch the request */
	                	THR_DEBUG("post urlavail");
				if (pthread_mutex_unlock(&urlavail_sem)) {
				        perror("sem_post urlavail_sem failed");
				        exit(3);
                                }
	                	THR_DEBUG("wait urlread");
				pthread_mutex_lock(&urlread_sem);
	
				if (sleepbet)
					sleep(sleepbet);
			}
		} else if (reqdir) {
			/* read complete requests from files in a directory */
			r.complete_req = 1;
			if (!(d = opendir(reqdir))) {
				perror("Could not open request pool directory");
				exit(3);
			}
			while ((de = readdir(d))) {
				if (de->d_name[0] == '.' || de->d_name[0] == '#' || de->d_name[strlen(de->d_name)-1] == '~') {
					fprintf(stderr, "Skipping request file: %s\n", de->d_name);
					continue;
				}
				snprintf(fname, sizeof(fname), "%s/%s", reqdir, de->d_name);
				if ((i = open(fname, O_RDONLY)) < 0) {
					fprintf(stderr, "Could not open request file %s: %s\n", fname, strerror(errno));
					continue;
				}
				if ((l = read(i, s, sizeof(s))) < 0) {
					fprintf(stderr, "Could not read from request file %s: %s\n", fname, strerror(errno));
					close(i);
					continue;
				}
				if (close(i))
					fprintf(stderr, "Could not close request file %s: %s\n", fname, strerror(errno));
				i = -1;
				
				if (l < sizeof(s))
					s[l] = 0;
				s[sizeof(s)-1] = 0;
				
				if ((uri = strchr(s, '\n')))
					*uri++ = '\0';
				else {
					fprintf(stderr, "No EOL on first line of request file %s!\n", fname);
					continue;
				}
				
				host = s;
				
				if ((p = strchr(host, ' ')))
					*p = '\0';
				if ((p = strchr(host, ':'))) {
					*p = '\0';
					p++;
					port = p;
				} else
					port = port_80;
				
				fprintf(stderr, "host: '%s' port: '%s' (%s) uri: '%s'\n", host, p, port, uri);
				
				strcpy(r.host, host);
				strcpy(r.port, port);
				strcpy(r.uri, uri);
				
				THR_DEBUG("posting url for req");
				/* Let a worker thread catch the request */
				pthread_mutex_unlock(&urlavail_sem);
				pthread_mutex_lock(&urlread_sem);
				
				if (sleepbet)
					sleep(sleepbet);
			}
			if (closedir(d)) {
				perror("Could not close pool directory");
				exit(3);
			}
		}
		
		/* Signal workers to quit */
		THR_DEBUG("signalling end");
		r.host[0] = 0;
		r.port[0] = 0;
		r.uri[0] = 0;
		for (i = 0; i < threads; i++) {
			pthread_mutex_unlock(&urlavail_sem);
			pthread_mutex_lock(&urlread_sem);
		}
		
		/* Wait for workers to finish */
		for (i = 0; i < threads; i++) {
			pthread_join(th[i], NULL);
                }
		gettimeofday(&tic_stopped, NULL);
		
	} else {
		gettimeofday(&tic_started, NULL);
		i = getobj(host, port, uri, 0);
		gettimeofday(&tic_stopped, NULL);
		tried = 1;
		if (i > 0)
			succ = 1;
		else {
			succ = 0;
			if (i < 0)
				neterr++;
		}
	}
	
	printsummary();
	exit(0);
}

