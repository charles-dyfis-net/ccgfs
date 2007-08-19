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
#include <sys/time.h>
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
enum subp_status {
	SUBP_INACTIVE,
	SUBP_ACTIVE,
	SUBP_SIGNALLED,
};

struct subprocess {
	unsigned char checksum[SHA_DIGEST_LENGTH];
	char **args;
	enum subp_status status;
	time_t timestamp;
	pid_t pid;
};

/* Functions */
static void mainloop(void);
static void config_free(struct HXdeque *);
static struct HXdeque *config_parse(const char *);
static bool config_parse_subproc(struct HXdeque *, const xmlNode *);
static void config_reload(const char *);
static void subproc_autorun(void);
static void subproc_post_cleanup(struct HXdeque_node *);
static struct HXdeque_node *subpnode_find_by_pid(pid_t);
static struct HXdeque_node *subpnode_find_by_SHA(struct HXdeque *, const void *);
static void subproc_launch(struct subprocess *);
static void subproc_stats(void);
static void subproc_stop(struct subprocess *);
static void subproc_stop_all(void);
static void signal_init(void);
static void signal_flag(int);
static void signal_ignore(int);
static inline int strcmp_1u(const xmlChar *, const char *);
static inline char *xmlGetProp_2s(xmlNode *, const char *);

/* Variables */
static unsigned int signal_event[32];
static struct HXdeque *subproc_list;
static char *config_file = "exports.xml";

//-----------------------------------------------------------------------------
int main(int argc, const char **argv)
{
	static const struct HXoption options_table[] = {
		{.sh = 'f', .type = HXTYPE_STRING, .ptr = &config_file,
		 .help = "Path to configuration file", .htyp = "FILE"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) <= 0)
		return EXIT_FAILURE;

	signal_init();
	subproc_list = config_parse(config_file);
	if (subproc_list == NULL) {
		fprintf(stderr, "Failed to parse %s\n", config_file);
		return EXIT_FAILURE;
	}
	subproc_autorun();
	mainloop();
	config_free(subproc_list);
	return EXIT_SUCCESS;
}

static void mainloop(void)
{
	bool exit_triggered = false, shutdown_in_progress = false;
	pid_t pid;

	while (subproc_list->items > 0 || !shutdown_in_progress) {
		pid = wait(NULL);
		if (pid >= 0) {
			subproc_post_cleanup(subpnode_find_by_pid(pid));
		} else if (errno != EINTR && errno != ECHILD) {
			fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
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
			config_reload(config_file);
		}
		subproc_autorun();
	}

	fprintf(stderr, "%s: Exited main loop\n", __func__);
	return;
}

static void signal_init(void)
{
	struct itimerval timer;
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = signal_flag;
	sa.sa_flags   = SA_RESTART;
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		perror("sigaction SIGHUP");
		abort();
	}

	/*
	 * Need a dummy handler, since %SIG_IGN will not do the right thing.
	 * No mention in manpages what %SIG_DFL would do.
	 */
	sa.sa_handler = signal_ignore;
	sa.sa_flags   = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		perror("sigaction SIGCHLD");
		abort();
	}

	/*
	 * ALRM is used to throw the mainloop out of waitpid() so that
	 * subproc_autorun() can run every once in a while.
	 * *Must not* set %SA_RESTART here because it restarts wait()
	 * without going through the mainloop.
	 *
	 * Also need the dummy handler here, since using %SIG_IGN does not
	 * does not interrupt wait().
	 */
	sa.sa_handler = signal_ignore;
	sa.sa_flags   = 0;
	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		perror("sigaction SIGALRMN");
		abort();
	}
	timer.it_interval.tv_sec  = 1;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec     = 1;
	timer.it_value.tv_usec    = 0;
	if (setitimer(ITIMER_REAL, &timer, NULL) < 0) {
		perror("setitimer");
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
	const struct HXdeque_node *node;
	struct subprocess *s;
	time_t now = time(NULL);

	for (node = subproc_list->first; node != NULL; node = node->next) {
		s = node->ptr;
		if (s->status == SUBP_ACTIVE || s->status == SUBP_SIGNALLED)
			continue;
		if (s->timestamp + 10 > now)
			continue;
		subproc_launch(s);
	}

	return;
}

/*
 * subproc_post_cleanup -
 * @s:	subprocess
 *
 * Called after the process has terminated.
 */
static void subproc_post_cleanup(struct HXdeque_node *node)
{
	struct subprocess *s = node->ptr;

	fprintf(stderr, "Process %u(%s) terminated\n", s->pid, *s->args);
	subproc_stats();

	if (s->status == SUBP_SIGNALLED) {
		/* signalled and terminated - remove subprocess from list */
		HX_zvecfree(s->args);
		free(s);
		HXdeque_del(node);
	} else {
		s->status = SUBP_INACTIVE;
	}
	return;
}

/*
 * subproc_find - find a process by pid
 * @pid:	pid to search for
 *
 * Returns the struct subprocess that is associated with @pid,
 * or %NULL when none could be found.
 */
static struct HXdeque_node *subpnode_find_by_pid(pid_t pid)
{
	struct HXdeque_node *node;
	struct subprocess *subp;

	for (node = subproc_list->first; node != NULL; node = node->next) {
		subp = node->ptr;
		if (subp->pid == pid)
			return node;
	}

	return NULL;
}

static struct HXdeque_node *subpnode_find_by_SHA(struct HXdeque *dq,
    const void *checksum)
{
	const struct subprocess *subp;
	struct HXdeque_node *node;

	for (node = dq->first; node != NULL; node = node->next) {
		subp = node->ptr;
		if (memcmp(subp->checksum, checksum,
		    sizeof(subp->checksum)) == 0)
			return node;
	}

	return NULL;
}

static void subproc_launch(struct subprocess *s)
{
	if (s->status == SUBP_ACTIVE) {
		fprintf(stderr, "%s: process %d already active\n",
		        __func__, s->pid);
		return;
	}

	s->pid = fork();
	if (s->pid == -1) {
		perror("fork");
		return;
	}
	if (s->pid == 0) {
		execvp(*s->args, s->args);
		exit(-errno);
	}
	s->timestamp = time(NULL);
	s->status    = SUBP_ACTIVE;
	fprintf(stderr, "Process %u(%s) started\n", s->pid, *s->args);
	subproc_stats();
	return;
}

static void subproc_stats(void)
{
	const struct HXdeque_node *node;

	for (node = subproc_list->first; node != NULL; node = node->next) {
		const struct subprocess *s = node->ptr;
		fprintf(stderr, " [%s]", *s->args);
	}

	fprintf(stderr, "\n");
	return;
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
	} else if (s->status == SUBP_SIGNALLED && s->timestamp + 5 < now) {
		/* Subprocess has not died within 5 seconds after SIGTERM. */
		fprintf(stderr, "Sending SIGKILL to %u\n", s->pid);
		kill(s->pid, SIGKILL);
		s->timestamp = now;
		s->status    = SUBP_SIGNALLED;
	}
	/* else: do NOT update s->timestamp */

	return;
}

static void subproc_stop_all(void)
{
	struct HXdeque_node *node, *next;
	struct subprocess *s;

	for (node = subproc_list->first; node != NULL; node = next) {
		s = node->ptr;
		if (s->status == SUBP_ACTIVE || s->status == SUBP_SIGNALLED)
			subproc_stop(node->ptr);
		if (s->status != SUBP_INACTIVE)
			abort();
		next = node->next;
		HXdeque_del(node);
	}

	return;
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
static void config_free(struct HXdeque *dq)
{
	struct HXdeque_node *node;
	struct subprocess *subp;

	for (node = dq->first; node != NULL; node = node->next) {
		subp = node->ptr;
		HX_zvecfree(subp->args);
		free(subp);
	}

	HXdeque_free(dq);
	return;
}

/*
 * config_parse - parse file and create subprocess list
 * @filename:	file to parse
 *
 * Creates a subprocess list from @filename. All processes will be start with
 * %SUBP_INACTIVE. Merging the list is not handled here.
 */
static struct HXdeque *config_parse(const char *filename)
{
	struct HXdeque *subp_list;
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(filename)) == NULL)
		return NULL;

	if ((ptr = xmlDocGetRootElement(doc)) == NULL ||
	    strcmp_1u(ptr->name, "ccgfs-super") != 0) {
		fprintf(stderr, "%s: Could not find root element\n", filename);
		xmlFreeDoc(doc);
		return NULL;
	}

	if ((subp_list = HXdeque_init()) == NULL) {
		perror("malloc");
		return NULL;
	}

	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp_1u(ptr->name, "s") == 0)
			if (!config_parse_subproc(subp_list, ptr)) {
				config_free(subp_list);
				subp_list = NULL;
				break;
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
static bool config_parse_subproc(struct HXdeque *dq, const xmlNode *xml_ptr)
{
	const struct HXdeque_node *node;
	struct subprocess *subp;
	struct HXdeque *args;
	SHA_CTX ctx;

	if ((args = HXdeque_init()) == NULL) {
		perror("malloc");
		return false;
	}
	if ((subp = malloc(sizeof(struct subprocess))) == NULL) {
		perror("malloc");
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

		fprintf(stderr, "Ignoring duplicate entry in config file:");
		while (*p != NULL)
			fprintf(stderr, " %s", *p++);
		fprintf(stderr, "\n");
		HX_zvecfree(subp->args);
		free(subp);
		return true;
	}

	HXdeque_push(dq, subp);
	return true;
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
	struct subprocess *new_subp, *old_subp;
	const struct HXdeque_node *new_node;
	struct HXdeque_node *old_node;
	struct HXdeque *new_proclist;

	new_proclist = config_parse(file);
	if (new_proclist == NULL) {
		fprintf(stderr, "Failed to reparse %s: %s\n"
		        "Nothing changed - continuing to use current "
		        "subprocess list\n",
		        file, strerror(errno));
		return;
	}

	for (new_node = new_proclist->first; new_node != NULL;
	    new_node = new_node->next)
	{
		new_subp = new_node->ptr;
		old_node = subpnode_find_by_SHA(subproc_list, new_subp->checksum);
		if (old_node == NULL)
			/* only in new list */
			continue;

		/* in both lists */
		old_subp            = old_node->ptr;
		new_subp->pid       = old_subp->pid;
		new_subp->status    = old_subp->status;
		new_subp->timestamp = old_subp->timestamp;
		HX_zvecfree(old_subp->args);
		free(old_subp);
		HXdeque_del(old_node);
	}

	/* What remains: only in old list */
	for (old_node = subproc_list->first; old_node != NULL;
	    old_node = old_node->next)
	{
		old_subp = old_node->ptr;
		subproc_stop(old_subp);
		HXdeque_push(new_proclist, old_subp);
	}

	HXdeque_free(subproc_list);
	subproc_list = new_proclist;
	subproc_stats();
	return;
}
