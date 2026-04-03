#ifndef _DNS_SERVER_THREAT_INTELLIGENCE_H
#define _DNS_SERVER_THREAT_INTELLIGENCE_H

#include "dns_server.h"

typedef enum {
	DNS_THREAT_QUERY_SAFE = 0,
	DNS_THREAT_QUERY_MALICIOUS = 1,
	DNS_THREAT_QUERY_ERROR = 2,
} dns_threat_query_result;

dns_threat_query_result _dns_server_threat_check_domain(struct dns_request *request);
dns_threat_query_result _dns_server_threat_check_ip(struct dns_request *request, const char *ioc, int is_ipv6);
int _dns_server_threat_check_ips_batch(struct dns_request *request, const char **ioc, int is_ipv6,
									   dns_threat_query_result *results, int count);
int _dns_server_threat_block_request(struct dns_request *request);

#endif
