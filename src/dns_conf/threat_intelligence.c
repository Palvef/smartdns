/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "threat_intelligence.h"

#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <getopt.h>
#include <string.h>

int _config_threat_intelligence(void *data, int argc, char *argv[])
{
	(void)data;
	int opt = 0;
	int optind_last = 1;

	/* clang-format off */
	static struct option long_options[] = {
		{"es", required_argument, NULL, 'e'},
		{"username", required_argument, NULL, 'u'},
		{"password", required_argument, NULL, 'p'},
		{"skip-tls", required_argument, NULL, 'k'},
		{"ca", required_argument, NULL, 'c'},
		{"index", required_argument, NULL, 'i'},
		{"block-ipv4", required_argument, NULL, '4'},
		{"block-ipv6", required_argument, NULL, '6'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "e:u:p:k:c:i:4:6:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'e': {
			safe_strncpy(dns_conf.threat_intelligence_es, optarg, sizeof(dns_conf.threat_intelligence_es));
			break;
		}
		case 'u': {
			safe_strncpy(dns_conf.threat_intelligence_username, optarg,
						 sizeof(dns_conf.threat_intelligence_username));
			break;
		}
		case 'p': {
			safe_strncpy(dns_conf.threat_intelligence_password, optarg,
						 sizeof(dns_conf.threat_intelligence_password));
			break;
		}
		case 'k': {
			if (strcasecmp(optarg, "yes") == 0 || strcasecmp(optarg, "true") == 0 || strcmp(optarg, "1") == 0) {
				dns_conf.threat_intelligence_skip_tls = 1;
			} else {
				dns_conf.threat_intelligence_skip_tls = 0;
			}
			break;
		}
		case 'c': {
			conf_get_conf_fullpath(optarg, dns_conf.threat_intelligence_ca_file, DNS_MAX_PATH);
			break;
		}
		case 'i': {
			safe_strncpy(dns_conf.threat_intelligence_index, optarg, sizeof(dns_conf.threat_intelligence_index));
			break;
		}
		case '4': {
			if (check_is_ipaddr(optarg) != 0) {
				tlog(TLOG_ERROR, "invalid block ipv4 address.");
				return -1;
			}
			safe_strncpy(dns_conf.threat_intelligence_block_ipv4, optarg,
						 sizeof(dns_conf.threat_intelligence_block_ipv4));
			break;
		}
		case '6': {
			if (check_is_ipaddr(optarg) != 0) {
				tlog(TLOG_ERROR, "invalid block ipv6 address.");
				return -1;
			}
			safe_strncpy(dns_conf.threat_intelligence_block_ipv6, optarg,
						 sizeof(dns_conf.threat_intelligence_block_ipv6));
			break;
		}
		default:
			goto errout;
		}

		optind_last = optind;
	}

	if (optind_last < argc) {
		tlog(TLOG_ERROR, "unknown options at '%s'", argv[optind_last]);
		goto errout;
	}

	if (dns_conf.threat_intelligence_es[0] == '\0' || dns_conf.threat_intelligence_index[0] == '\0') {
		tlog(TLOG_ERROR, "threat-intelligence must set -es and -index");
		goto errout;
	}

	if (dns_conf.threat_intelligence_skip_tls == 0 && dns_conf.threat_intelligence_ca_file[0] == '\0') {
		tlog(TLOG_WARN, "threat-intelligence TLS enabled without -ca; use system trust store");
	}

	return 0;

errout:
	return -1;
}
