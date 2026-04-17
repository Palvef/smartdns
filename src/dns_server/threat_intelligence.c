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

#include "context.h"
#include "ptr.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DNS_THREAT_BUF_SIZE (1024 * 1024)
#define DNS_THREAT_MAX_BATCH 2048
#define DNS_THREAT_CACHE_TTL_MS_DEFAULT (5 * 60 * 1000)
#define DNS_THREAT_CACHE_MAX_DEFAULT 65536
#define DNS_THREAT_CACHE_COMPACT_INTERVAL_MS (5 * 60 * 1000)
#define DNS_THREAT_CACHE_COMPACT_APPEND_MIN 256
#define DNS_THREAT_CACHE_COMPACT_APPEND_DIVISOR 4

struct dns_threat_cache_entry {
	struct hlist_node node;
	struct list_head list;
	uint32_t key;
	int is_ip;
	char ioc[DNS_MAX_CNAME_LEN];
	dns_threat_query_result result;
	time_t expired_time;  /* Use absolute time_t instead of tick count */
};

struct dns_threat_whitelist_entry {
	struct hlist_node node;
	char domain[DNS_MAX_CNAME_LEN];
};

static pthread_mutex_t dns_threat_cache_lock = PTHREAD_MUTEX_INITIALIZER;
/* 2^18 = 256K buckets. Sized so lookups remain near-O(1) for multi-million
   entry caches (e.g. 1.5M entries -> ~6 per bucket). 2MB static overhead. */
static DECLARE_HASHTABLE(dns_threat_cache, 18);
static struct list_head dns_threat_cache_list;
static int dns_threat_cache_num;
static pthread_once_t dns_threat_cache_once = PTHREAD_ONCE_INIT;
static pthread_once_t dns_threat_curl_once = PTHREAD_ONCE_INIT;
static pthread_once_t dns_threat_cache_file_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t dns_threat_cache_file_lock = PTHREAD_MUTEX_INITIALIZER;
static int dns_threat_cache_loaded;
static unsigned long dns_threat_cache_last_save;
static int dns_threat_cache_append_since_save;
/* Persistent append handle; reused across misses to avoid per-insert fopen/fclose.
   Protected by dns_threat_cache_file_lock. Closed before rename in compaction so
   later appends reopen to the replacement inode. */
static FILE *dns_threat_cache_append_fp;
static pthread_mutex_t dns_threat_whitelist_lock = PTHREAD_MUTEX_INITIALIZER;
static DECLARE_HASHTABLE(dns_threat_whitelist, 10);
static time_t dns_threat_whitelist_mtime;
static int dns_threat_whitelist_loaded;

static uint32_t _dns_threat_cache_key(const char *ioc, int is_ip);
static int _dns_threat_is_expired(time_t expired_time);
static void _dns_threat_whitelist_load(void);
static int _dns_threat_is_domain_whitelisted(const char *domain);
static void _dns_threat_cache_file_init(void);
static void _dns_threat_cache_save_atexit(void);
static void _dns_threat_cache_append_to_file(const char *ioc, int is_ip, dns_threat_query_result result, time_t expired_time);
static void _dns_threat_cache_maybe_compact_file(void);
static void _dns_threat_cache_save_to_file(int force);

static void _dns_threat_cache_init(void)
{
	hash_init(dns_threat_cache);
	INIT_LIST_HEAD(&dns_threat_cache_list);
	dns_threat_cache_num = 0;
	dns_threat_cache_last_save = get_tick_count();
	dns_threat_cache_append_since_save = 0;
	/* Register atexit handler to save cache when program exits */
	pthread_once(&dns_threat_cache_file_once, _dns_threat_cache_file_init);
}

static void _dns_threat_whitelist_clear_unlocked(void)
{
	struct dns_threat_whitelist_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long bucket = 0;

	hash_for_each_safe(dns_threat_whitelist, bucket, tmp, entry, node)
	{
		hash_del(&entry->node);
		free(entry);
	}
	hash_init(dns_threat_whitelist);
	dns_threat_whitelist_loaded = 0;
	dns_threat_whitelist_mtime = 0;
}

static void _dns_threat_trim_line(char *line)
{
	char *start = line;
	char *end = NULL;

	while (*start != '\0' && isspace((unsigned char)*start)) {
		start++;
	}
	if (start != line) {
		memmove(line, start, strlen(start) + 1);
	}

	end = line + strlen(line);
	while (end > line && isspace((unsigned char)*(end - 1))) {
		end--;
	}
	*end = '\0';
}

static void _dns_threat_whitelist_load(void)
{
	const char *path = dns_conf.threat_intelligence_whitelist;
	struct stat st;
	FILE *fp = NULL;
	char line[DNS_MAX_CNAME_LEN * 2];

	pthread_mutex_lock(&dns_threat_whitelist_lock);
	if (path[0] == '\0') {
		_dns_threat_whitelist_clear_unlocked();
		pthread_mutex_unlock(&dns_threat_whitelist_lock);
		return;
	}

	if (stat(path, &st) != 0) {
		_dns_threat_whitelist_clear_unlocked();
		pthread_mutex_unlock(&dns_threat_whitelist_lock);
		return;
	}

	if (dns_threat_whitelist_loaded == 1 && dns_threat_whitelist_mtime == st.st_mtime) {
		pthread_mutex_unlock(&dns_threat_whitelist_lock);
		return;
	}

	_dns_threat_whitelist_clear_unlocked();
	fp = fopen(path, "r");
	if (fp == NULL) {
		pthread_mutex_unlock(&dns_threat_whitelist_lock);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		struct dns_threat_whitelist_entry *entry = NULL;
		uint32_t key = 0;

		_dns_threat_trim_line(line);
		if (line[0] == '\0' || line[0] == '#') {
			continue;
		}
		if (strlen(line) >= DNS_MAX_CNAME_LEN) {
			continue;
		}

		entry = zalloc(1, sizeof(*entry));
		if (entry == NULL) {
			continue;
		}

		safe_strncpy_lower(entry->domain, line, sizeof(entry->domain), NULL);
		key = hash_string(entry->domain);
		hash_add(dns_threat_whitelist, &entry->node, key);
	}

	fclose(fp);
	dns_threat_whitelist_loaded = 1;
	dns_threat_whitelist_mtime = st.st_mtime;
	pthread_mutex_unlock(&dns_threat_whitelist_lock);
}

static int _dns_threat_is_domain_whitelisted(const char *domain)
{
	struct dns_threat_whitelist_entry *entry = NULL;
	uint32_t key = hash_string(domain);
	int found = 0;

	if (dns_conf.threat_intelligence_whitelist[0] == '\0') {
		return 0;
	}

	_dns_threat_whitelist_load();
	pthread_mutex_lock(&dns_threat_whitelist_lock);
	hash_for_each_possible(dns_threat_whitelist, entry, node, key)
	{
		if (strcasecmp(entry->domain, domain) == 0) {
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&dns_threat_whitelist_lock);

	return found;
}

static int _dns_threat_cache_ttl_ms(void)
{
	if (dns_conf.threat_intelligence_cache_ttl <= 0) {
		return DNS_THREAT_CACHE_TTL_MS_DEFAULT;
	}

	return dns_conf.threat_intelligence_cache_ttl * 1000;
}

static int _dns_threat_cache_max(void)
{
	if (dns_conf.threat_intelligence_cache_size <= 0) {
		return DNS_THREAT_CACHE_MAX_DEFAULT;
	}

	return dns_conf.threat_intelligence_cache_size;
}

static const char *_dns_threat_cache_file(void)
{
	static char cache_file[DNS_MAX_PATH];

	if (dns_conf.threat_intelligence_cache_file[0] != '\0') {
		return dns_conf.threat_intelligence_cache_file;
	}

	snprintf(cache_file, sizeof(cache_file), "%s/%s", dns_conf_get_data_dir(), "threat_intelligence.cache");
	return cache_file;
}

static int _dns_threat_cache_compact_threshold(void)
{
	/* Scale the append threshold with cache size so full-cache rewrite cost stays
	   amortized: at most 1/DIVISOR of the cache can accumulate in the append log
	   before compaction. Racy read of dns_threat_cache_num is acceptable — this
	   is a scheduling heuristic, not a correctness check. */
	int num = dns_threat_cache_num;
	int scaled = num / DNS_THREAT_CACHE_COMPACT_APPEND_DIVISOR;
	return scaled < DNS_THREAT_CACHE_COMPACT_APPEND_MIN ? DNS_THREAT_CACHE_COMPACT_APPEND_MIN : scaled;
}

static void _dns_threat_cache_save_atexit(void)
{
	_dns_threat_cache_save_to_file(1);
}

static void _dns_threat_cache_append_fp_close_locked(void)
{
	if (dns_threat_cache_append_fp != NULL) {
		fclose(dns_threat_cache_append_fp);
		dns_threat_cache_append_fp = NULL;
	}
}

static void _dns_threat_cache_append_to_file(const char *ioc, int is_ip, dns_threat_query_result result, time_t expired_time)
{
	if (dns_conf.threat_intelligence_cache_enable == 0) {
		return;
	}

	if (result == DNS_THREAT_QUERY_ERROR) {
		return;
	}

	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	pthread_mutex_lock(&dns_threat_cache_file_lock);
	if (dns_threat_cache_append_fp == NULL) {
		dns_threat_cache_append_fp = fopen(_dns_threat_cache_file(), "a");
	}
	if (dns_threat_cache_append_fp == NULL) {
		pthread_mutex_unlock(&dns_threat_cache_file_lock);
		return;
	}

	if (fprintf(dns_threat_cache_append_fp, "%d\t%d\t%lu\t%s\n", is_ip, result,
				(unsigned long)expired_time, ioc) >= 0) {
		/* No fsync and no fclose on the hot path: stdio block-buffers ~4KB worth
		   of entries; compaction/atexit flushes them. Per-append fsync serialized
		   every miss on disk latency and was the primary cause of long-running
		   throughput regression. */
		dns_threat_cache_append_since_save++;
	}
	pthread_mutex_unlock(&dns_threat_cache_file_lock);
}

static void _dns_threat_cache_load_from_file(void)
{
	FILE *fp = NULL;
	char line[2048];

	if (dns_conf.threat_intelligence_cache_enable == 0 || dns_threat_cache_loaded) {
		return;
	}

	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	pthread_mutex_lock(&dns_threat_cache_file_lock);
	if (dns_threat_cache_loaded) {
		pthread_mutex_unlock(&dns_threat_cache_file_lock);
		return;
	}

	fp = fopen(_dns_threat_cache_file(), "r");
	if (fp == NULL) {
		if (errno != ENOENT) {
			tlog(TLOG_WARN, "open threat cache file failed: %s", strerror(errno));
		}
		dns_threat_cache_loaded = 1;
		pthread_mutex_unlock(&dns_threat_cache_file_lock);
		return;
	}

	pthread_mutex_lock(&dns_threat_cache_lock);
	while (fgets(line, sizeof(line), fp) != NULL) {
		struct dns_threat_cache_entry *entry = NULL;
		struct dns_threat_cache_entry *exist = NULL;
		int is_ip = 0;
		int result = DNS_THREAT_QUERY_SAFE;
		unsigned long expired_tick = 0;
		char ioc[DNS_MAX_CNAME_LEN] = {0};
		char *p = NULL;
		uint32_t key = 0;

		p = strchr(line, '\n');
		if (p) {
			*p = '\0';
		}

		if (sscanf(line, "%d\t%d\t%lu\t%255s", &is_ip, &result, &expired_tick, ioc) != 4) {
			continue;
		}

		if (_dns_threat_is_expired((time_t)expired_tick)) {
			continue;
		}

		entry = zalloc(1, sizeof(*entry));
		if (entry == NULL) {
			continue;
		}

		key = _dns_threat_cache_key(ioc, is_ip);
		hash_for_each_possible(dns_threat_cache, exist, node, key)
		{
			if (exist->key != key || exist->is_ip != is_ip || strcmp(exist->ioc, ioc) != 0) {
				continue;
			}
			exist->result = result;
			exist->expired_time = (time_t)expired_tick;
			list_del(&exist->list);
			list_add_tail(&exist->list, &dns_threat_cache_list);
			free(entry);
			entry = NULL;
			break;
		}

		if (entry != NULL) {
			entry->key = key;
			entry->is_ip = is_ip;
			entry->result = result;
			entry->expired_time = (time_t)expired_tick;
			safe_strncpy(entry->ioc, ioc, sizeof(entry->ioc));
			hash_add(dns_threat_cache, &entry->node, key);
			list_add_tail(&entry->list, &dns_threat_cache_list);
			dns_threat_cache_num++;
		}

		while (dns_threat_cache_num > _dns_threat_cache_max() && !list_empty(&dns_threat_cache_list)) {
			struct dns_threat_cache_entry *oldest = NULL;
			oldest = list_first_entry(&dns_threat_cache_list, struct dns_threat_cache_entry, list);
			hash_del(&oldest->node);
			list_del(&oldest->list);
			free(oldest);
			dns_threat_cache_num--;
		}
	}
	pthread_mutex_unlock(&dns_threat_cache_lock);
	fclose(fp);

	dns_threat_cache_loaded = 1;
	pthread_mutex_unlock(&dns_threat_cache_file_lock);
	tlog(TLOG_INFO, "threat cache loaded from file, cache_size=%d", dns_threat_cache_num);
}

static void _dns_threat_cache_file_init(void)
{
	atexit(_dns_threat_cache_save_atexit);
}

static void _dns_threat_cache_save_to_file(int force)
{
	FILE *fp = NULL;
	struct dns_threat_cache_entry *entry = NULL;
	struct list_head *pos = NULL;
	char tmp_file[DNS_MAX_PATH + 16];
	int entry_count = 0;
	int save_failed = 0;
	char *buf = NULL;
	size_t buf_len = 0;
	size_t buf_cap = 0;

	if (dns_conf.threat_intelligence_cache_enable == 0) {
		return;
	}

	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	pthread_mutex_lock(&dns_threat_cache_file_lock);

	/* Re-check threshold under lock so concurrent callers that both crossed the
	   threshold don't each run a full O(N) rewrite. */
	if (!force) {
		unsigned long now = get_tick_count();
		if (dns_threat_cache_append_since_save < _dns_threat_cache_compact_threshold() &&
			(now - dns_threat_cache_last_save) < DNS_THREAT_CACHE_COMPACT_INTERVAL_MS) {
			pthread_mutex_unlock(&dns_threat_cache_file_lock);
			return;
		}
	}

	/* Serialize the cache to an in-memory buffer while holding cache_lock.
	   Disk I/O is then done after releasing cache_lock so concurrent cache
	   reads/writes aren't blocked on file writes. */
	pthread_mutex_lock(&dns_threat_cache_lock);
	buf_cap = (size_t)dns_threat_cache_num * 64 + 4096;
	buf = malloc(buf_cap);
	if (buf == NULL) {
		pthread_mutex_unlock(&dns_threat_cache_lock);
		/* Mark as attempted so sustained memory pressure doesn't cause every
		   cache_set to retry the malloc; data is still in the append log. */
		dns_threat_cache_last_save = get_tick_count();
		dns_threat_cache_append_since_save = 0;
		pthread_mutex_unlock(&dns_threat_cache_file_lock);
		tlog(TLOG_WARN, "threat cache compact alloc failed, retry on next interval");
		return;
	}

	time_t now_sec = time(NULL);
	list_for_each(pos, &dns_threat_cache_list)
	{
		char line[64 + DNS_MAX_CNAME_LEN];
		int len = 0;

		entry = list_entry(pos, struct dns_threat_cache_entry, list);
		/* Inline expiry check to avoid 1.5M time() syscalls under cache_lock. */
		if (entry->expired_time == 0 || entry->expired_time < now_sec) {
			continue;
		}
		/* Persist both SAFE and MALICIOUS results so cache survives restart and
		   avoids re-querying upstream threat intelligence for benign domains/IPs. */
		if (entry->result == DNS_THREAT_QUERY_ERROR) {
			continue;
		}

		len = snprintf(line, sizeof(line), "%d\t%d\t%lu\t%s\n", entry->is_ip, entry->result,
					   (unsigned long)entry->expired_time, entry->ioc);
		if (len <= 0 || (size_t)len >= sizeof(line)) {
			continue;
		}
		if (buf_len + (size_t)len > buf_cap) {
			size_t new_cap = buf_cap * 2;
			char *new_buf = NULL;
			while (new_cap < buf_len + (size_t)len) {
				new_cap *= 2;
			}
			new_buf = realloc(buf, new_cap);
			if (new_buf == NULL) {
				save_failed = 1;
				break;
			}
			buf = new_buf;
			buf_cap = new_cap;
		}
		memcpy(buf + buf_len, line, (size_t)len);
		buf_len += (size_t)len;
		entry_count++;
	}
	pthread_mutex_unlock(&dns_threat_cache_lock);

	if (!save_failed && entry_count > 0) {
		snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", _dns_threat_cache_file());
		fp = fopen(tmp_file, "w");
		if (fp == NULL) {
			save_failed = 1;
		} else {
			if (fwrite(buf, 1, buf_len, fp) != buf_len) {
				save_failed = 1;
			}
			if (!save_failed && (fflush(fp) != 0 || ferror(fp))) {
				save_failed = 1;
			}
			if (!save_failed && fsync(fileno(fp)) != 0) {
				save_failed = 1;
			}
			fclose(fp);
		}

		if (save_failed) {
			remove(tmp_file);
			tlog(TLOG_WARN, "threat cache save failed, keep old cache file");
		} else {
			/* Close the append handle before rename so later appends reopen
			   against the new inode; the stdio-buffered tail is a strict subset
			   of what we just wrote into the replacement file. */
			_dns_threat_cache_append_fp_close_locked();
			if (rename(tmp_file, _dns_threat_cache_file()) != 0) {
				remove(tmp_file);
				tlog(TLOG_WARN, "rename threat cache file failed: %s", strerror(errno));
			}
		}
	}

	free(buf);

	dns_threat_cache_last_save = get_tick_count();
	dns_threat_cache_append_since_save = 0;
	pthread_mutex_unlock(&dns_threat_cache_file_lock);
	tlog(TLOG_DEBUG, "threat cache saved to file, cache_size=%d, entries_saved=%d", dns_threat_cache_num, entry_count);
}

static void _dns_threat_cache_maybe_compact_file(void)
{
	unsigned long now;
	unsigned long last_save = 0;
	int append_since_save = 0;

	if (dns_conf.threat_intelligence_cache_enable == 0) {
		return;
	}

	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	pthread_mutex_lock(&dns_threat_cache_file_lock);
	last_save = dns_threat_cache_last_save;
	append_since_save = dns_threat_cache_append_since_save;
	pthread_mutex_unlock(&dns_threat_cache_file_lock);

	now = get_tick_count();
	if (append_since_save >= _dns_threat_cache_compact_threshold() ||
		(now - last_save) >= DNS_THREAT_CACHE_COMPACT_INTERVAL_MS) {
		_dns_threat_cache_save_to_file(0);
	}
}

static void _dns_threat_curl_global_init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int _dns_threat_intelligence_enabled(void)
{
	if (dns_conf.threat_intelligence_query == 0) {
		return 0;
	}

	if (dns_conf.threat_intelligence_es[0] == '\0' || dns_conf.threat_intelligence_index[0] == '\0') {
		return 0;
	}

	return 1;
}

static int _dns_threat_calc_iochash(const char *ioc, char output[17])
{
	unsigned char digest[MD5_DIGEST_LENGTH];
	char buffer[DNS_MAX_CNAME_LEN + 32];
	char hex[33];

	if (snprintf(buffer, sizeof(buffer), "pdt_20210129!@3_%s", ioc) <= 0) {
		return -1;
	}

	MD5((unsigned char *)buffer, strlen(buffer), digest);

	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	}
	memcpy(output, hex + 8, 16);
	output[16] = '\0';
	return 0;
}

static uint32_t _dns_threat_cache_key(const char *ioc, int is_ip)
{
	uint32_t key = hash_string(ioc);
	return jhash(&is_ip, sizeof(is_ip), key);
}

static int _dns_threat_is_expired(time_t expired_time)
{
	if (expired_time == 0) {
		return 1;
	}

	if (expired_time < time(NULL)) {
		return 1;
	}

	return 0;
}

static int _dns_threat_cache_get(const char *ioc, int is_ip, dns_threat_query_result *result)
{
	uint32_t key = _dns_threat_cache_key(ioc, is_ip);
	struct dns_threat_cache_entry *entry = NULL;

	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	/* Load cache file only once, not every query */
	if (!dns_threat_cache_loaded) {
		_dns_threat_cache_load_from_file();
	}
	pthread_mutex_lock(&dns_threat_cache_lock);
	hash_for_each_possible(dns_threat_cache, entry, node, key)
	{
		if (entry->key != key || entry->is_ip != is_ip || strcmp(entry->ioc, ioc) != 0) {
			continue;
		}

		if (_dns_threat_is_expired(entry->expired_time)) {
			hash_del(&entry->node);
			list_del(&entry->list);
			free(entry);
			dns_threat_cache_num--;
			break;
		}

		*result = entry->result;
		list_del(&entry->list);
		list_add_tail(&entry->list, &dns_threat_cache_list);
		pthread_mutex_unlock(&dns_threat_cache_lock);
		tlog(TLOG_DEBUG, "threat cache hit: %s type=%s result=%d cache_size=%d", ioc, is_ip ? "ip" : "domain", *result, dns_threat_cache_num);
		return 0;
	}
	pthread_mutex_unlock(&dns_threat_cache_lock);

	return -1;
}

static void _dns_threat_cache_set(const char *ioc, int is_ip, dns_threat_query_result result)
{
	uint32_t key = _dns_threat_cache_key(ioc, is_ip);
	struct dns_threat_cache_entry *entry = NULL;
	struct dns_threat_cache_entry *oldest = NULL;
	time_t expired_time = time(NULL) + _dns_threat_cache_ttl_ms() / 1000;

	/* Cache all results (SAFE and MALICIOUS). Keep ERROR out of cache to avoid
	   extending transient backend failures. */
	if (result == DNS_THREAT_QUERY_ERROR) {
		return;
	}
	
	pthread_once(&dns_threat_cache_once, _dns_threat_cache_init);
	/* Load cache file only once, not every set operation */
	if (!dns_threat_cache_loaded) {
		_dns_threat_cache_load_from_file();
	}
	pthread_mutex_lock(&dns_threat_cache_lock);
	hash_for_each_possible(dns_threat_cache, entry, node, key)
	{
		if (entry->key != key || entry->is_ip != is_ip || strcmp(entry->ioc, ioc) != 0) {
			continue;
		}

		entry->result = result;
		entry->expired_time = expired_time;
		list_del(&entry->list);
		list_add_tail(&entry->list, &dns_threat_cache_list);
		pthread_mutex_unlock(&dns_threat_cache_lock);
		/* Persist updated IOC immediately to avoid losing fresher result/TTL on restart. */
		_dns_threat_cache_append_to_file(ioc, is_ip, result, expired_time);
		_dns_threat_cache_maybe_compact_file();
		return;
	}

	entry = zalloc(1, sizeof(*entry));
	if (entry == NULL) {
		pthread_mutex_unlock(&dns_threat_cache_lock);
		return;
	}

	entry->key = key;
	entry->is_ip = is_ip;
	entry->result = result;
	entry->expired_time = expired_time;
	safe_strncpy(entry->ioc, ioc, sizeof(entry->ioc));
	hash_add(dns_threat_cache, &entry->node, key);
	list_add_tail(&entry->list, &dns_threat_cache_list);
	dns_threat_cache_num++;
	tlog(TLOG_DEBUG, "threat cache entry added: %s result=%d cache_size=%d/%d", ioc, result, dns_threat_cache_num, _dns_threat_cache_max());

	while (dns_threat_cache_num > _dns_threat_cache_max() && !list_empty(&dns_threat_cache_list)) {
		oldest = list_first_entry(&dns_threat_cache_list, struct dns_threat_cache_entry, list);
		hash_del(&oldest->node);
		list_del(&oldest->list);
		free(oldest);
		dns_threat_cache_num--;
	}
	pthread_mutex_unlock(&dns_threat_cache_lock);

	/* New IOC append keeps miss path O(1); periodic compaction deduplicates file. */
	_dns_threat_cache_append_to_file(ioc, is_ip, result, expired_time);
	_dns_threat_cache_maybe_compact_file();
}

static int _dns_threat_is_whitelist(const char *response)
{
	if (strstr(response, "\"mclass\":\"/WhiteList\"") != NULL || strstr(response, "\"mclass\":[\"/WhiteList\"") != NULL) {
		return 1;
	}

	if (strstr(response, "\"sclass\":\"/WhiteList") != NULL || strstr(response, "\"sclass\":[\"/WhiteList") != NULL) {
		return 1;
	}

	if (strstr(response, "\"IoCThreatName\":\"白名单\"") != NULL || strstr(response, "\"IoCThreatName\":[\"白名单\"") != NULL) {
		return 1;
	}

	return 0;
}

static dns_threat_query_result _dns_threat_parse_single_response(const char *response, int is_ip)
{
	if (response == NULL) {
		return DNS_THREAT_QUERY_ERROR;
	}

	if (strstr(response, "\"error\"") != NULL || strstr(response, "\"timed_out\":true") != NULL) {
		return DNS_THREAT_QUERY_ERROR;
	}

	if (strstr(response, "\"hits\":[]") != NULL) {
		return DNS_THREAT_QUERY_SAFE;
	}

	if (_dns_threat_is_whitelist(response)) {
		return DNS_THREAT_QUERY_SAFE;
	}

	if (is_ip && strstr(response, "\"IoCType\":\"ip\"") == NULL) {
		return DNS_THREAT_QUERY_SAFE;
	}

	if (!is_ip && strstr(response, "\"IoCType\":\"ip\"") != NULL) {
		return DNS_THREAT_QUERY_SAFE;
	}

	if (strstr(response, "\"IoCLevel\":") != NULL) {
		return DNS_THREAT_QUERY_MALICIOUS;
	}

	return DNS_THREAT_QUERY_SAFE;
}

static int _dns_threat_extract_next_json(const char *src, const char **next, int *len)
{
	int in_string = 0;
	int escaped = 0;
	int depth = 0;
	const char *start = NULL;
	const char *p = src;

	while (*p != '\0' && *p != '{') {
		p++;
	}
	if (*p == '\0') {
		return -1;
	}

	start = p;
	for (; *p != '\0'; p++) {
		char c = *p;
		if (in_string) {
			if (escaped) {
				escaped = 0;
				continue;
			}
			if (c == '\\') {
				escaped = 1;
				continue;
			}
			if (c == '"') {
				in_string = 0;
			}
			continue;
		}

		if (c == '"') {
			in_string = 1;
			continue;
		}

		if (c == '{') {
			depth++;
		} else if (c == '}') {
			depth--;
			if (depth == 0) {
				*len = p - start + 1;
				*next = p + 1;
				return 0;
			}
		}
	}

	return -1;
}

struct dns_threat_http_response {
	char *data;
	size_t len;
	size_t cap;
};

static size_t _dns_threat_http_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	size_t n = size * nmemb;
	struct dns_threat_http_response *resp = userdata;
	size_t new_len = resp->len + n;

	if (new_len + 1 > resp->cap) {
		size_t new_cap = resp->cap == 0 ? 4096 : resp->cap;
		while (new_cap < new_len + 1) {
			new_cap *= 2;
		}
		char *new_data = realloc(resp->data, new_cap);
		if (new_data == NULL) {
			return 0;
		}
		resp->data = new_data;
		resp->cap = new_cap;
	}

	memcpy(resp->data + resp->len, ptr, n);
	resp->len = new_len;
	resp->data[resp->len] = '\0';
	return n;
}

static char *_dns_threat_build_msearch_payload(const char **ioc, int count)
{
	size_t payload_cap = count * 192 + 256;
	char *payload = malloc(payload_cap);
	size_t off = 0;

	if (payload == NULL) {
		return NULL;
	}

	for (int i = 0; i < count; i++) {
		char iochash[17] = {0};
		int len = 0;

		if (_dns_threat_calc_iochash(ioc[i], iochash) != 0) {
			free(payload);
			return NULL;
		}

		if (off + 192 >= payload_cap) {
			payload_cap *= 2;
			char *new_payload = realloc(payload, payload_cap);
			if (new_payload == NULL) {
				free(payload);
				return NULL;
			}
			payload = new_payload;
		}

		len = snprintf(payload + off, payload_cap - off, "{\"index\":\"%s\"}\n", dns_conf.threat_intelligence_index);
		if (len <= 0 || (size_t)len >= payload_cap - off) {
			free(payload);
			return NULL;
		}
		off += len;

		len = snprintf(payload + off, payload_cap - off, "{\"size\":5,\"query\":{\"term\":{\"IoCHash\":\"%s\"}}}\n", iochash);
		if (len <= 0 || (size_t)len >= payload_cap - off) {
			free(payload);
			return NULL;
		}
		off += len;
	}

	return payload;
}

static int _dns_threat_query_batch_from_es(const char **ioc, int count, int is_ip, dns_threat_query_result *result)
{
	char url[DNS_MAX_URL_LEN + DNS_MAX_CNAME_LEN + 16] = {0};
	char auth[DNS_MAX_CNAME_LEN * 2 + 2] = {0};
	char *payload = NULL;
	struct curl_slist *headers = NULL;
	struct dns_threat_http_response resp = {0};
	CURL *curl = NULL;
	CURLcode code = CURLE_OK;
	int ret = -1;
	const char *responses = NULL;
	const char *next = NULL;
	unsigned long start_tick = get_tick_count();

	pthread_once(&dns_threat_curl_once, _dns_threat_curl_global_init);
	payload = _dns_threat_build_msearch_payload(ioc, count);
	if (payload == NULL) {
		goto out;
	}

	if (dns_conf.threat_intelligence_username[0] != '\0') {
		snprintf(auth, sizeof(auth), "%s:%s", dns_conf.threat_intelligence_username, dns_conf.threat_intelligence_password);
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		goto out;
	}

	snprintf(url, sizeof(url), "%s/%s/_msearch", dns_conf.threat_intelligence_es, dns_conf.threat_intelligence_index);
	headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 800L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _dns_threat_http_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

	if (dns_conf.threat_intelligence_skip_tls) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	} else if (dns_conf.threat_intelligence_ca_file[0] != '\0') {
		curl_easy_setopt(curl, CURLOPT_CAINFO, dns_conf.threat_intelligence_ca_file);
	}

	if (dns_conf.threat_intelligence_username[0] != '\0') {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
	}

	code = curl_easy_perform(curl);
	if (code != CURLE_OK || resp.data == NULL || resp.len == 0) {
		tlog(TLOG_WARN, "threat msearch query failed, code=%d", (int)code);
		goto out;
	}
	tlog(TLOG_DEBUG, "threat msearch query done, ioc_count=%d, cost=%lums", count, get_tick_count() - start_tick);

	responses = strstr(resp.data, "\"responses\":");
	if (responses == NULL) {
		goto out;
	}

	next = responses;
	for (int i = 0; i < count; i++) {
		int len = 0;
		if (_dns_threat_extract_next_json(next, &next, &len) != 0) {
			goto out;
		}

		if (len <= 0 || len >= 32768) {
			goto out;
		}

		char *one = malloc(len + 1);
		if (one == NULL) {
			goto out;
		}
		memcpy(one, next - len, len);
		one[len] = '\0';
		result[i] = _dns_threat_parse_single_response(one, is_ip);
		free(one);
	}

	ret = 0;
out:
	if (headers != NULL) {
		curl_slist_free_all(headers);
	}
	if (curl != NULL) {
		curl_easy_cleanup(curl);
	}
	if (payload != NULL) {
		free(payload);
	}
	if (resp.data != NULL) {
		free(resp.data);
	}
	return ret;
}

static dns_threat_query_result _dns_server_threat_query_eval(dns_threat_query_result ret)
{
	if (ret == DNS_THREAT_QUERY_ERROR && dns_conf.threat_intelligence_fail_bypass == 0) {
		return DNS_THREAT_QUERY_MALICIOUS;
	}

	if (ret == DNS_THREAT_QUERY_ERROR) {
		return DNS_THREAT_QUERY_SAFE;
	}

	return ret;
}

int _dns_server_threat_check_ips_batch(struct dns_request *request, const char **ioc, int is_ipv6,
									   dns_threat_query_result *results, int count)
{
	(void)request;
	int is_ip = 1;
	const char **query_ioc = NULL;
	int *query_map = NULL;
	dns_threat_query_result *query_results = NULL;

	if (count <= 0 || count > DNS_THREAT_MAX_BATCH) {
		return -1;
	}

	for (int i = 0; i < count; i++) {
		results[i] = DNS_THREAT_QUERY_SAFE;
	}

	if (_dns_threat_intelligence_enabled() == 0) {
		return 0;
	}

	/* First pass: check cache for all IPs (cache has SAFE and MALICIOUS entries). */
	int query_num = 0;
	query_ioc = malloc(sizeof(*query_ioc) * count);
	query_map = malloc(sizeof(*query_map) * count);
	if (query_ioc == NULL || query_map == NULL) {
		goto out;
	}

	for (int i = 0; i < count; i++) {
		dns_threat_query_result cached = DNS_THREAT_QUERY_SAFE;
		if (_dns_threat_cache_get(ioc[i], is_ip, &cached) == 0) {
			results[i] = cached;
		} else {
			/* Not in cache - need to query */
			query_ioc[query_num] = ioc[i];
			query_map[query_num] = i;
			query_num++;
		}
	}

	if (query_num > 0) {
		int msearch_size = dns_conf.threat_intelligence_msearch_size;
		query_results = malloc(sizeof(*query_results) * query_num);
		if (query_results == NULL) {
			goto out;
		}
		if (msearch_size <= 0) {
			msearch_size = 100;
		}
		for (int i = 0; i < query_num; i++) {
			query_results[i] = DNS_THREAT_QUERY_ERROR;
		}

		for (int i = 0; i < query_num; i += msearch_size) {
			int chunk = query_num - i;
			if (chunk > msearch_size) {
				chunk = msearch_size;
			}

			if (_dns_threat_query_batch_from_es(query_ioc + i, chunk, is_ip, query_results + i) != 0) {
				for (int j = i; j < i + chunk; j++) {
					query_results[j] = DNS_THREAT_QUERY_ERROR;
				}
			}
		}

		for (int i = 0; i < query_num; i++) {
			dns_threat_query_result final_result = _dns_server_threat_query_eval(query_results[i]);
			results[query_map[i]] = final_result;
			_dns_threat_cache_set(query_ioc[i], is_ip, final_result);
		}
	}

out:
	if (query_ioc != NULL) {
		free(query_ioc);
	}
	if (query_map != NULL) {
		free(query_map);
	}
	if (query_results != NULL) {
		free(query_results);
	}

	(void)is_ipv6;
	return 0;
}

dns_threat_query_result _dns_server_threat_check_domain(struct dns_request *request)
{
	dns_threat_query_result result = DNS_THREAT_QUERY_SAFE;
	char domain[DNS_MAX_CNAME_LEN] = {0};
	const char *query_domain = domain;

	if (_dns_threat_intelligence_enabled() == 0) {
		return DNS_THREAT_QUERY_SAFE;
	}

	safe_strncpy_lower(domain, request->domain, sizeof(domain), NULL);
	/* Check cache for previous SAFE/MALICIOUS verdicts. */
	if (_dns_threat_cache_get(query_domain, 0, &result) == 0) {
		return result;
	}

	/* Check whitelist */
	if (_dns_threat_is_domain_whitelisted(query_domain)) {
		tlog(TLOG_DEBUG, "threat whitelist hit: %s", query_domain);
		return DNS_THREAT_QUERY_SAFE;
	}

	/* Query threat intelligence service */
	if (_dns_threat_query_batch_from_es(&query_domain, 1, 0, &result) != 0) {
		result = DNS_THREAT_QUERY_ERROR;
	}

	result = _dns_server_threat_query_eval(result);
	tlog(TLOG_DEBUG, "threat domain result: %s result=%d", query_domain, result);
	/* Cache SAFE/MALICIOUS result to reduce upstream pressure. */
	_dns_threat_cache_set(query_domain, 0, result);
	return result;
}

dns_threat_query_result _dns_server_threat_check_ip(struct dns_request *request, const char *ioc, int is_ipv6)
{
	dns_threat_query_result result = DNS_THREAT_QUERY_SAFE;
	const char *ioc_arr[1];
	(void)request;
	ioc_arr[0] = ioc;
	if (_dns_server_threat_check_ips_batch(request, ioc_arr, is_ipv6, &result, 1) != 0) {
		return DNS_THREAT_QUERY_SAFE;
	}
	return result;
}

int _dns_server_threat_block_request(struct dns_request *request)
{
	struct dns_server_post_context context;
	unsigned char addr[DNS_RR_AAAA_LEN] = {0};
	char ip[DNS_MAX_IPLEN] = {0};
	int port = PORT_NOT_DEFINED;
	int parse_ok = 0;
	const char *block_ip = dns_conf.threat_intelligence_block_ipv4;

	if (request->qtype == DNS_T_AAAA) {
		block_ip = dns_conf.threat_intelligence_block_ipv6;
	}

	if (block_ip[0] == '\0') {
		block_ip = request->qtype == DNS_T_AAAA ? "::" : "0.0.0.0";
	}

	if (parse_ip(block_ip, ip, &port) == 0) {
		if (request->qtype == DNS_T_AAAA) {
			parse_ok = (inet_pton(AF_INET6, ip, addr) == 1);
		} else {
			parse_ok = (inet_pton(AF_INET, ip, addr) == 1);
		}
	}

	if (parse_ok == 0) {
		tlog(TLOG_WARN, "parse threat block ip failed, fallback to local null route.");
		if (request->qtype == DNS_T_AAAA) {
			memset(addr, 0, DNS_RR_AAAA_LEN);
		} else {
			memset(addr, 0, DNS_RR_A_LEN);
		}
	}

	request->is_blackhole = 1;
	request->has_ip = 1;
	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->ip_addr_type = request->qtype;
	if (request->qtype == DNS_T_AAAA) {
		memcpy(request->ip_addr, addr, DNS_RR_AAAA_LEN);
	} else {
		memcpy(request->ip_addr, addr, DNS_RR_A_LEN);
	}

	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	context.do_ipset = 1;
	context.select_all_best_ip = 1;
	_dns_request_post(&context);

	return 0;
}
