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
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
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

enum subp_status {
	SUBP_INACTIVE,
	SUBP_ACTIVE,
	SUBP_SIGTERM,
	SUBP_STOPPED,
};

static const char *const status_string[] = {
	[SUBP_INACTIVE] = "SUBP_INACTIVE",
	[SUBP_ACTIVE]   = "SUBP_ACTIVE",
	[SUBP_SIGTERM]  = "SUBP_SIGTERM",
	[SUBP_STOPPED]  = "SUBP_STOPPED",
};

struct subprocess {
	unsigned char checksum[SHA_DIGEST_LENGTH];
	enum mount_type mount_type;
	char *engine, *src_path, *auth_data, *dest_path;
	enum subp_status status;
	time_t start_time;
	pid_t pid;
};

/* Functions */
static void mainloop(void);
static int config_parse(const char *);
static void config_parse_export(struct HXdeque *, xmlNode *);
static void config_parse_import(struct HXdeque *, xmlNode *);
static void config_checksum(struct subprocess *);
static void subproc_autorun(void);
static void subproc_post_cleanup(struct subprocess *);
static struct subprocess *subproc_find(pid_t);
static int subproc_launch(struct subprocess *);
static void subproc_stop(struct subprocess *);
static void subproc_stop_all(void);
static void signal_init(void);
static void signal_flag(int);
static void signal_ignore(int);
static inline int strcmp_1u(const xmlChar *, const char *);
static inline char *xmlGetProp_2s(xmlNode *, const char *);

/* Variables */
static unsigned int signal_event[32];
static unsigned int subproc_running;
static struct HXdeque *subproc_list;

//-----------------------------------------------------------------------------
int main(int argc, const char **argv)
{
	subproc_list = HXdeque_init();
	signal_init();
	config_parse("exports.xml");
	subproc_autorun();
	mainloop();
	return EXIT_SUCCESS;
}

static void mainloop(void)
{
	bool exit_triggered = false, stop = false;
	pid_t pid;

	while (subproc_running > 0 || !stop) {
		fprintf(stderr, "%s: %u active procs\n", __func__, subproc_running);

		pid = waitpid(-1, NULL, 0);
		if (pid == -1 && errno != EINTR) {
			fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
			exit_triggered = true;
		} else if (pid >= 0) {
			subproc_post_cleanup(subproc_find(pid));
		}

		if (signal_event[SIGINT] > 0) {
			--signal_event[SIGINT];
			exit_triggered = true;
		}
		if (signal_event[SIGTERM] > 0) {
			--signal_event[SIGTERM];
			exit_triggered = true;
		}
		if (exit_triggered && !stop) {
			stop = true;
			fprintf(stderr, "%s: Sending SIGTERM (active: %u)\n", __func__, subproc_running);
			subproc_stop_all();
			fprintf(stderr, "%s: Done (active %u)\n", __func__, subproc_running);
			continue;
		}
		if (signal_event[SIGHUP] > 0) {
			--signal_event[SIGHUP];
			config_parse("exports.xml");
			subproc_autorun();
			continue;
		}
	}

	fprintf(stderr, "%s: Exited main loop\n", __func__);
	return;
}


static void signal_init(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = signal_flag;
	sa.sa_flags   = SA_RESTART;
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		perror("sigaction SIGHUP");
		abort();
	}
	sa.sa_handler = signal_ignore;
	sa.sa_flags   = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		perror("sigaction SIGCHLD");
		abort();
	}

	sa.sa_handler = signal_flag;
	sa.sa_flags   = SA_RESETHAND;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		perror("sigaction SIGINT");
		abort();
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("sigaction SIGTERM");
		abort();
	}

	return;
}

static void signal_flag(int s)
{
	++signal_event[s];
	return;
}

static void signal_ignore(int s)
{
	return;
}

static void sigchld_handler(int signum)
{
	struct subprocess *subp;
	pid_t pid;

	pid = waitpid(-1, NULL, 0);
	if (pid == -1)
		return;

	return;
}

/*
 * subproc_autorun -
 */
static void subproc_autorun(void)
{
	const struct HXdeque_node *node;
	struct subprocess *s;

	for (node = subproc_list->first; node != NULL; node = node->next) {
		s = node->ptr;
		if (s->status == SUBP_INACTIVE) {
			subproc_launch(s);
			continue;
		}
	}

	return;
}

/*
 * subproc_post_cleanup -
 *
 * Called after the process has terminated.
 */
static void subproc_post_cleanup(struct subprocess *s)
{
	fprintf(stderr, "%s: (%d) %s->", __func__, s->pid,
	        status_string[s->status]);

	s->pid = -1;
	if (s->status == SUBP_SIGTERM)
		s->status = SUBP_STOPPED;
	else
		s->status = SUBP_INACTIVE;

	--subproc_running;
	fprintf(stderr, "%s; %u active procs\n",
	        status_string[s->status], subproc_running);
	return;
}

static struct subprocess *subproc_find(pid_t pid)
{
	const struct HXdeque_node *node;
	struct subprocess *subp;

	for (node = subproc_list->first; node != NULL; node = node->next) {
		subp = node->ptr;
		if (subp->pid == pid)
			return subp;
	}

	return NULL;
}

static int subproc_launch(struct subprocess *s)
{
	s->pid = fork();
	if (s->pid == -1) {
		perror("fork");
		return -errno;
	}
	if (s->pid == 0) {
		char exe[NAME_MAX];
		int ret;

		snprintf(exe, sizeof(exe), "ccgfs-%s", s->engine);
		execlp(exe, exe, s->src_path, s->auth_data, s->dest_path, NULL);
		exit(-errno);
	}
	s->start_time = time(NULL);
	s->status     = SUBP_ACTIVE;
	++subproc_running;
	fprintf(stderr, "%s: %u procs active\n", __func__, subproc_running);
	return 1;
}

static void subproc_stop(struct subprocess *s)
{
	if (s->pid > 0)
		kill(s->pid, SIGTERM);
	fprintf(stderr, "I want to kill %d\n", s->pid);
	s->status = SUBP_SIGTERM;
	return;
}

static void subproc_stop_all(void)
{
	const struct HXdeque_node *node;
	struct subprocess *s;

	fprintf(stderr, "%s\n", __func__);
	for (node = subproc_list->first; node != NULL; node = node->next) {
		s = node->ptr;
		if (s->status == SUBP_ACTIVE)
			subproc_stop(node->ptr);
	}

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

static int config_parse(const char *filename)
{
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(filename)) == NULL)
		return -1;
	if ((ptr = xmlDocGetRootElement(doc)) == NULL ||
	    strcmp_1u(ptr->name, "ccgfs-super") != 0) {
		xmlFreeDoc(doc);
		return -1;
	}
	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp_1u(ptr->name, "export") == 0)
			config_parse_export(subproc_list, ptr);
		else if (strcmp_1u(ptr->name, "import") == 0)
			config_parse_import(subproc_list, ptr);
	}
	xmlFreeDoc(doc);
	return 1;
}

static void config_parse_export(struct HXdeque *dq, xmlNode *ptr)
{
	struct subprocess su = {};
	void *d;

	su.mount_type = CCGFS_SUPER_EXPORT;
	su.engine     = xmlGetProp_2s(ptr, "engine");
	su.src_path   = xmlGetProp_2s(ptr, "srcpath");
	su.auth_data  = xmlGetProp_2s(ptr, "target");
	su.dest_path  = xmlGetProp_2s(ptr, "destpath");
	su.status     = SUBP_INACTIVE;
	su.pid        = -1;
	config_checksum(&su);
	if ((d = HX_memdup(&su, sizeof(su))) == NULL) {
		perror("HX_memdup");
		abort();
	}
	HXdeque_push(dq, d);
	return;
}

static void config_parse_import(struct HXdeque *dq, xmlNode *ptr)
{
	struct subprocess su = {};
	void *d;

	su.mount_type = CCGFS_SUPER_IMPORT;
	su.engine     = xmlGetProp_2s(ptr, "engine");
	su.auth_data  = xmlGetProp_2s(ptr, "source");
	su.src_path   = xmlGetProp_2s(ptr, "srcpath");
	su.dest_path  = xmlGetProp_2s(ptr, "destpath");
	su.status     = SUBP_INACTIVE;
	su.pid        = -1;
	config_checksum(&su);
	if ((d = HX_memdup(&su, sizeof(su))) == NULL) {
		perror("HX_memdup");
		abort();
	}
	HXdeque_push(dq, d);
	return;
}

static void config_checksum(struct subprocess *su)
{
	SHA_CTX ctx;
	SHA_Init(&ctx);
	SHA_Update(&ctx, &su->mount_type, sizeof(su->mount_type));
	SHA_Update(&ctx, su->engine, strlen(su->engine));
	SHA_Update(&ctx, su->src_path, strlen(su->src_path));
	SHA_Update(&ctx, su->auth_data, strlen(su->auth_data));
	SHA_Update(&ctx, su->dest_path, strlen(su->dest_path));
	SHA_Final(su->checksum, &ctx);
	return;
}
