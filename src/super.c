/*
 *	CC Network Filesystem (ccgfs)
 *	Storage and Mount Supervisor Daemon
 *
 *	© Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX.h>
#include <libxml/parser.h>
#include <openssl/sha.h>
#include "ccgfs.h"

/* Definitions */
enum mount_type {
	CCGFS_SUPER_EXPORT, /* push-based */
	CCGFS_SUPER_IMPORT, /* pull-based */
};

struct subprocess {
	unsigned char checksum[SHA_DIGEST_LENGTH];
	enum mount_type mount_type;
	char *engine, *srcpath, *auth_data, *destpath;
	pid_t pid;
	unsigned int mark;
};

/* Functions */
static inline int strcmp_1u(const xmlChar *, const char *);
static inline char *xmlGetProp_2s(xmlNode *, const char *);
static int parse_config(const char *);
static void parse_export(struct HXdeque *, xmlNode *);
static void parse_import(struct HXdeque *, xmlNode *);
static void build_checksum(struct subprocess *);
static void signal_init(void);
static void sighup_handler(int);

/* Variables */
static unsigned char signal_triggered[SIGHUP];
struct HXdeque *subproc_list;

//-----------------------------------------------------------------------------
int main(int argc, const char **argv)
{
	subproc_list = HXdeque_init();
	signal_init();
	parse_config("exports.xml");
	while (1) {
		
	}
	return EXIT_SUCCESS;
}

static int parse_config(const char *filename)
{
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(filename)) == NULL)
		return -1;
	if ((ptr = xmlDocGetRootElement(doc)) == NULL ||
	    strcmp_1u(ptr->name, "ccgfs") != 0) {
		xmlFreeDoc(doc);
		return -1;
	}
	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp_1u(ptr->name, "export") == 0)
			parse_export(subproc_list, ptr);
		else if (strcmp_1u(ptr->name, "import") == 0)
			parse_import(subproc_list, ptr);
	}
	xmlFreeDoc(doc);
	return 1;
}

static void parse_export(struct HXdeque *dq, xmlNode *ptr)
{
	struct subprocess su = {};
	void *d;

	su.mount_type = CCGFS_SUPER_EXPORT;
	su.engine     = xmlGetProp_2s(ptr, "engine");
	su.srcpath    = xmlGetProp_2s(ptr, "srcpath");
	su.auth_data  = xmlGetProp_2s(ptr, "target");
	su.destpath   = xmlGetProp_2s(ptr, "destpath");
	build_checksum(&su);
	if ((d = HX_memdup(&su, sizeof(su))) == NULL) {
		perror("HX_memdup");
		abort();
	}
	HXdeque_push(dq, d);
	return;
}

static void parse_import(struct HXdeque *dq, xmlNode *ptr)
{
	struct subprocess su = {};
	void *d;

	su.mount_type = CCGFS_SUPER_IMPORT;
	su.engine     = xmlGetProp_2s(ptr, "engine");
	su.auth_data  = xmlGetProp_2s(ptr, "source");
	su.srcpath    = xmlGetProp_2s(ptr, "srcpath");
	su.destpath   = xmlGetProp_2s(ptr, "destpath");
	build_checksum(&su);
	if ((d = HX_memdup(&su, sizeof(su))) == NULL) {
		perror("HX_memdup");
		abort();
	}
	HXdeque_push(dq, d);
	return;
}

static void build_checksum(struct subprocess *su)
{
	SHA_CTX ctx;
	SHA_Init(&ctx);
	SHA_Update(&ctx, &su->mount_type, sizeof(su->mount_type));
	SHA_Update(&ctx, su->engine, strlen(su->engine));
	SHA_Update(&ctx, su->srcpath, strlen(su->srcpath));
	SHA_Update(&ctx, su->auth_data, strlen(su->auth_data));
	SHA_Update(&ctx, su->destpath, strlen(su->destpath));
	SHA_Final(su->checksum, &ctx);
	return;
}

static void signal_init(void)
{
	struct sigaction sa;
	sa.sa_handler = sighup_handler;
	sa.sa_flags   = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		perror("sigaction");
		abort();
	}
	return;
}

static void sighup_handler(int s)
{
	signal_triggered[s-1] = 1;
	return;
}

static inline int strcmp_1u(const xmlChar *a, const char *b)
{
	return strcmp(reinterpret_cast(const char *, a), b);
}

static inline char *xmlGetProp_2s(xmlNode *p, const char *v)
{
	return reinterpret_cast(char *, xmlGetProp(p,
	       reinterpret_cast(const xmlChar *, v)));
}
