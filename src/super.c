/*
 *	CC Network Filesystem (ccgfs)
 *	Storage and Mount Supervisor Daemon
 *
 *	Copyright © Jan Engelhardt <jengelh [at] computergmbh de>, 2007 - 2008
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <libHX/clist.h>
#include <libHX.h>
#include <libxml/parser.h>
#include <openssl/sha.h>
#include "ccgfs.h"

/* Definitions */
enum subp_status {
	SUBP_INACTIVE,
	SUBP_ACTIVE,
	SUBP_SIGNALLED,
};

struct subprocess {
	unsigned char checksum[SHA_DIGEST_LENGTH];
	char **args;
	struct HXlist_head list;
	enum subp_status status;
	time_t timestamp;
	pid_t pid;
};

/* Functions */
static void mainloop(void);
static void config_free(struct HXclist_head *);
static struct HXclist_head *config_parse(const char *);
static bool config_parse_subproc(struct HXclist_head *, const xmlNode *);
static void config_parse_uint(unsigned int *, const xmlNode *);
static void config_reload(const char *);
static void pidfile_init(void);
static void subproc_autorun(void);
static void subproc_post_cleanup(struct subprocess *);
static struct subprocess *subpnode_find_by_pid(pid_t);
static struct subprocess *subpnode_find_by_SHA(const struct HXclist_head *, const void *);
static void subproc_launch(struct subprocess *);
static void subproc_stats(void);
static void subproc_stop(struct subprocess *);
static void subproc_stop_all(void);
static void signal_init(void);
static void signal_flag(int);
static void signal_ignore(int);
static inline int strcmp_1u(const xmlChar *, const char *);
static inline char *xmlGetProp_2s(xmlNode *, const char *);
static void xprintf(unsigned int level, const char *, ...);

/* Variables */
static unsigned int signal_event[32];
static struct HXclist_head *subproc_list;
static struct {
	char *config_file, *pid_file;
	unsigned int kill_margin, restart_wait, use_syslog;
} Opt = {
	.config_file    = "exports.xml",
	.kill_margin    = 5,
	.pid_file       = NULL,
	.restart_wait   = 10,
	.use_syslog     = true,
};

//-----------------------------------------------------------------------------
int main(int argc, const char **argv)
{
	static const struct HXoption options_table[] = {
		{.sh = 'f', .type = HXTYPE_STRING, .ptr = &Opt.config_file,
		 .help = "Path to configuration file", .htyp = "FILE"},
		{.sh = 'p', .type = HXTYPE_STRING, .ptr = &Opt.pid_file,
		 .help = "Path to the PID file (read doc)", .htyp = "FILE"},
		{.sh = 's', .type = HXTYPE_NONE, .ptr = &Opt.use_syslog,
		 .help = "Enable logging to syslog"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) <= 0)
		return EXIT_FAILURE;

	if (Opt.use_syslog)
		openlog(HX_basename(*argv), LOG_PID, LOG_DAEMON);

	signal_init();
	subproc_list = config_parse(Opt.config_file);
	if (subproc_list == NULL) {
		xprintf(LOG_CRIT, "Failed to parse %s\n", Opt.config_file);
		return EXIT_FAILURE;
	}
	pidfile_init();
	subproc_autorun();
	mainloop();
	config_free(subproc_list);
	unlink(Opt.pid_file);
	return EXIT_SUCCESS;
}

static void mainloop(void)
{
	bool exit_triggered = false, shutdown_in_progress = false;
	pid_t pid;

	while (subproc_list->items > 0 || !shutdown_in_progress) {
		pid = waitpid(-1, NULL, WNOHANG);
		if (pid > 0) {
			subproc_post_cleanup(subpnode_find_by_pid(pid));
		} else if (pid == 0 || errno == ECHILD) {
			sleep(1);
		} else if (errno != EINTR) {
			xprintf(LOG_ERR, "wait: %s\n", strerror(errno));
			exit_triggered = true;
		}

		if (signal_event[SIGINT] > 0) {
			--signal_event[SIGINT];
			exit_triggered = true;
		}
		if (signal_event[SIGTERM] > 0) {
			--signal_event[SIGTERM];
			exit_triggered = true;
		}
		if (exit_triggered || shutdown_in_progress) {
			shutdown_in_progress = true;
			subproc_stop_all();
			continue;
		}
		if (signal_event[SIGHUP] > 0) {
			--signal_event[SIGHUP];
			config_reload(Opt.config_file);
		}
		subproc_autorun();
	}

	return;
}

static void pidfile_init(void)
{
	FILE *fp;

	if (Opt.pid_file == NULL)
		return;

	fp = fopen(Opt.pid_file, "w");
	if (fp == NULL) {
		xprintf(LOG_ERR, "fopen pidfile %s: %s\n",
		        Opt.pid_file, strerror(errno));
		return;
	}
	fprintf(fp, "%u", getpid());
	fclose(fp);
	return;	
}

static void signal_init(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = signal_flag;
	sa.sa_flags   = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		xprintf(LOG_CRIT, "sigaction SIGHUP: %s\n", strerror(errno));
		abort();
	}

	/*
	 * Need a dummy handler, since %SIG_IGN will not do the right thing.
	 * No mention in manpages what %SIG_DFL would do.
	 */
	sa.sa_handler = signal_ignore;
	sa.sa_flags   = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		xprintf(LOG_CRIT, "sigaction SIGCHLD: %s\n", strerror(errno));
		abort();
	}

	sa.sa_handler = signal_flag;
	sa.sa_flags   = SA_RESETHAND;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		xprintf(LOG_CRIT, "sigaction SIGINT: %s\n", strerror(errno));
		abort();
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		xprintf(LOG_CRIT, "sigaction SIGTERM: %s\n", strerror(errno));
		abort();
	}

	return;
}

/*
 * signal_flag - asynchronously notify the mainloop
 */
static void signal_flag(int s)
{
	++signal_event[s];
	return;
}

static void signal_ignore(int s)
{
	return;
}

/*
 * subproc_autorun - activate all outstanding subprocesses.
 */
static void subproc_autorun(void)
{
	struct subprocess *s;
	time_t now = time(NULL);

	HXlist_for_each_entry(s, subproc_list, list) {
		if (s->status == SUBP_ACTIVE || s->status == SUBP_SIGNALLED)
			continue;
		if (s->timestamp + Opt.restart_wait > now)
			continue;
		subproc_launch(s);
	}
}

/*
 * subproc_post_cleanup -
 * @s:	subprocess
 *
 * Called after the process has terminated.
 */
static void subproc_post_cleanup(struct subprocess *s)
{
	xprintf(LOG_INFO, "Process %u(%s) terminated\n", s->pid, *s->args);
#ifdef DEBUG
	subproc_stats();
#endif

	if (s->status == SUBP_SIGNALLED) {
		/* signalled and terminated - remove subprocess from list */
		HX_zvecfree(s->args);
		HXclist_del(subproc_list, &s->list);
		free(s);
	} else {
		s->status = SUBP_INACTIVE;
	}
}

/*
 * subproc_find - find a process by pid
 * @pid:	pid to search for
 *
 * Returns the struct subprocess that is associated with @pid,
 * or %NULL when none could be found.
 */
static struct subprocess *subpnode_find_by_pid(pid_t pid)
{
	struct subprocess *subp;

	HXlist_for_each_entry(subp, subproc_list, list)
		if (subp->pid == pid)
			return subp;

	return NULL;
}

static struct subprocess *subpnode_find_by_SHA(const struct HXclist_head *dq,
    const void *checksum)
{
	struct subprocess *subp;

	HXlist_for_each_entry(subp, dq, list)
		if (memcmp(subp->checksum, checksum,
		    sizeof(subp->checksum)) == 0)
			return subp;

	return NULL;
}

static void subproc_launch(struct subprocess *s)
{
	if (s->status == SUBP_ACTIVE) {
		xprintf(LOG_WARNING, "process %u already active\n", s->pid);
		return;
	}

	s->pid = fork();
	if (s->pid == -1) {
		xprintf(LOG_WARNING, "fork: %s\n", strerror(errno));
		return;
	}
	if (s->pid == 0) {
		execvp(*s->args, s->args);
		exit(-errno);
	}
	s->timestamp = time(NULL);
	s->status    = SUBP_ACTIVE;
	xprintf(LOG_INFO, "Process %u(%s) started\n", s->pid, *s->args);
#ifdef DEBUG
	subproc_stats();
#endif
}

static void subproc_stats(void)
{
	const struct subprocess *s;

	HXlist_for_each_entry(s, subproc_list, list)
		fprintf(stderr, " [%s]", s->args);

	fprintf(stderr, "\n");
}

static void subproc_stop(struct subprocess *s)
{
	time_t now;

	if (s->pid <= 0) {
		fprintf(stderr, "%s: Illegal PID %d\n", __func__, s->pid);
		return;
	}

	now = time(NULL);
	if (s->status == SUBP_ACTIVE) {
		fprintf(stderr, "Sending SIGTERM to %u\n", s->pid);
		kill(s->pid, SIGTERM);
		s->timestamp = now;
		s->status    = SUBP_SIGNALLED;
	} else if (s->status == SUBP_SIGNALLED &&
	    s->timestamp + Opt.kill_margin < now) {
		/* Subprocess has not died within X seconds after SIGTERM. */
		fprintf(stderr, "Sending SIGKILL to %u\n", s->pid);
		kill(s->pid, SIGKILL);
		s->timestamp = now;
		s->status    = SUBP_SIGNALLED;
	}
	/* else: do NOT update s->timestamp */
}

static void subproc_stop_all(void)
{
	struct subprocess *s, *next;

	HXlist_for_each_entry_safe(s, next, subproc_list, list) {
		if (s->status == SUBP_ACTIVE || s->status == SUBP_SIGNALLED)
			subproc_stop(s);
		HXclist_del(subproc_list, &s->list);
	}
}

/*
 * Wrappers for I think needless troublemaker typedefs of libxml.
 */
static inline int strcmp_1u(const xmlChar *a, const char *b)
{
	return strcmp(reinterpret_cast(const char *, a), b);
}

static inline char *xmlGetProp_2s(xmlNode *p, const char *v)
{
	return reinterpret_cast(char *, xmlGetProp(p,
	       reinterpret_cast(const xmlChar *, v)));
}

/*
 * config_free - deallocate config
 * @dq:	subprocess list
 */
static void config_free(struct HXclist_head *dq)
{
	struct subprocess *subp, *next;

	HXlist_for_each_entry_safe(subp, next, &dq->list, list) {
		HX_zvecfree(subp->args);
		HXclist_del(dq, &subp->list);
		free(subp);
	}

	free(dq);
}

/*
 * config_parse - parse file and create subprocess list
 * @filename:	file to parse
 *
 * Creates a subprocess list from @filename. All processes will be start with
 * %SUBP_INACTIVE. Merging the list is not handled here.
 */
static struct HXclist_head *config_parse(const char *filename)
{
	struct HXclist_head *subp_list;
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(filename)) == NULL)
		return NULL;

	if ((ptr = xmlDocGetRootElement(doc)) == NULL ||
	    strcmp_1u(ptr->name, "ccgfs-super") != 0) {
		xprintf(LOG_ERR, "%s: Could not find root element\n", filename);
		xmlFreeDoc(doc);
		return NULL;
	}

	if ((subp_list = malloc(sizeof(struct HXclist_head))) == NULL) {
		xprintf(LOG_ERR, "malloc: %s\n", strerror(errno));
		return NULL;
	}

	HXclist_init(subp_list);
	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp_1u(ptr->name, "kill-margin") == 0) {
			config_parse_uint(&Opt.kill_margin, ptr);
		} else if (strcmp_1u(ptr->name, "restart-wait") == 0) {
			config_parse_uint(&Opt.restart_wait, ptr);
		} else if (strcmp_1u(ptr->name, "s") == 0) {
			if (!config_parse_subproc(subp_list, ptr)) {
				config_free(subp_list);
				subp_list = NULL;
				break;
			}
		}
	}

	xmlFreeDoc(doc);
	return subp_list;
}

/*
 * config_parse_subproc - parse an <s> element
 * @dq:		subprocess list to append to
 * @xml_ptr:	libxml stuff
 */
static bool config_parse_subproc(struct HXclist_head *dq,
    const xmlNode *xml_ptr)
{
	const struct HXdeque_node *node;
	struct subprocess *subp;
	struct HXdeque *args;
	SHA_CTX ctx;

	if ((args = HXdeque_init()) == NULL) {
		xprintf(LOG_ERR, "malloc: %s\n", strerror(errno));
		return false;
	}
	if ((subp = malloc(sizeof(struct subprocess))) == NULL) {
		xprintf(LOG_ERR, "malloc: %s\n", strerror(errno));
		return false;
	}
	subp->timestamp = 0;
	subp->status    = SUBP_INACTIVE;
	subp->pid       = -1;

	for (xml_ptr = xml_ptr->children; xml_ptr != NULL;
	    xml_ptr = xml_ptr->next)
	{
		char *dup_ptr, *free_ptr, *in;

		if (xml_ptr->type != XML_TEXT_NODE)
			continue;
		/*
		 * Split at whitespace (it is kept simple for now),
		 * copy i => o, record string start pointers in @args.
		 */
		in = free_ptr = HX_strdup(xml_ptr->content);
		while (*in != '\0') {
			while (*in != '\0' && (isspace(*in) || *in == '\n'))
				++in;
			if (*in == '\0')
				break;

			dup_ptr = in;
			while (*in != '\0' && !isspace(*in) && *in != '\n')
				++in;
			if (*in == '\0') {
				HXdeque_push(args, HX_strdup(dup_ptr));
				break;
			}
			*in++ = '\0';
			HXdeque_push(args, HX_strdup(dup_ptr));
		}
		free(free_ptr);
	}

	/* Calculate checksum and convert to vector */
	SHA_Init(&ctx);
	for (node = args->first; node != NULL; node = node->next)
		SHA_Update(&ctx, node->ptr, strlen(node->ptr) + 1);
	SHA_Final(subp->checksum, &ctx);
	subp->args = (char **)HXdeque_to_vec(args, NULL);
	HXdeque_free(args);

	if (subpnode_find_by_SHA(dq, subp->checksum) != NULL) {
		char *const *p = subp->args;
		hmc_t *tmp = NULL;

		hmc_strasg(&tmp, "Ignoring duplicate entry in config file:");
		while (*p != NULL) {
			hmc_strcat(&tmp, " ");
			hmc_strcat(&tmp, *p++);
		}
		xprintf(LOG_WARNING, "%s\n", tmp);
		hmc_free(tmp);
		HX_zvecfree(subp->args);
		free(subp);
		return true;
	}

	HXlist_init(&subp->list);
	HXclist_push(dq, &subp->list);
	return true;
}

static void config_parse_uint(unsigned int *var, const xmlNode *ptr)
{
	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_TEXT_NODE || ptr->content == NULL)
			continue;

		*var = strtoul(ptr->content, NULL, 0);
		break;
	}
}

/*
 * config_reload - reread configuration
 * @file:	configuration file
 *
 * Reads the configuration file from scratch. Kills old processes and moves
 * their waiting state (%STATUS_SIGTERM) to the new subprocess list.
 */
static void config_reload(const char *file)
{
	struct subprocess *new_subp, *old_subp, *next;
	struct HXclist_head *new_proclist;

	new_proclist = config_parse(file);
	if (new_proclist == NULL) {
		xprintf(LOG_ERR, "Failed to reparse %s: %s\n"
		        "Nothing changed - continuing to use current "
		        "subprocess list\n",
		        file, strerror(errno));
		return;
	}

	HXlist_for_each_entry(new_subp, new_proclist, list) {
		old_subp = subpnode_find_by_SHA(subproc_list,
		           new_subp->checksum);
		if (old_subp == NULL)
			continue;

		/* in both lists */
		new_subp->pid       = old_subp->pid;
		new_subp->status    = old_subp->status;
		new_subp->timestamp = old_subp->timestamp;
		HX_zvecfree(old_subp->args);
		HXclist_del(subproc_list, &old_subp->list);
		free(old_subp);
	}

	/* What remains: only in old list */
	HXlist_for_each_entry_safe(old_subp, next, subproc_list, list) {
		subproc_stop(old_subp);
		HXclist_del(subproc_list, &old_subp->list);
		HXclist_push(new_proclist, &old_subp->list);
	}

	free(subproc_list);
	subproc_list = new_proclist;
#ifdef DEBUG
	subproc_stats();
#endif
}

static void xprintf(unsigned int level, const char *format, ...)
{
	va_list args, arg2;

	va_start(args, format);
	va_copy(arg2, args);
	vfprintf(stderr, format, args);
	if (Opt.use_syslog)
		vsyslog(level, format, arg2);
	va_end(args);
	va_end(arg2);
	return;
}
