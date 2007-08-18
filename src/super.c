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
	char **args;
	enum subp_status status;
	time_t start_time;
	pid_t pid;
};

/* Functions */
static void mainloop(void);
static struct HXdeque *config_parse(const char *);
static void config_parse_subproc(struct HXdeque *, const xmlNode *);
static void subproc_autorun(void);
static void subproc_post_cleanup(struct subprocess *);
static struct subprocess *subproc_find(pid_t);
static void subproc_launch(struct subprocess *);
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
	signal_init();
	subproc_list = config_parse("exports.xml");
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

		pid = wait(NULL);
		if (pid == -1 && errno != EINTR) {
			fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
			exit_triggered = true;
		} else if (pid >= 0) {
			subproc_post_cleanup(subproc_find(pid));
		}

		if (stop)
			/* oxymoron, heh. */
			continue;

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
			//config_parse("exports.xml");
			continue;
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
 * subproc_autorun - activate all outstanding subprocesses.
 */
static void subproc_autorun(void)
{
	const struct HXdeque_node *node;
	struct subprocess *s;
	time_t now;

	fprintf(stderr, "%s: autorun\n", __func__);
	now = time(NULL);

	for (node = subproc_list->first; node != NULL; node = node->next) {
		s = node->ptr;
		if (s->status == SUBP_STOPPED)
			/* terminated forever */
			continue;
		if (s->status != SUBP_INACTIVE)
			/* running */
			continue;
		if (s->start_time + 10 > now) {
			fprintf(stderr, "%s: skipping \"%s\" (%lu+10>%lu)\n",
			        __func__, *s->args,
			        (long)s->start_time,(long)now);
			continue;
		}
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

/*
 * subproc_find - find a process by pid
 * @pid:	pid to search for
 *
 * Returns the struct subprocess that is associated with @pid,
 * or %NULL when none could be found.
 */
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
	s->start_time = time(NULL);
	s->status     = SUBP_ACTIVE;
	++subproc_running;
	fprintf(stderr, "%s: %u procs active\n", __func__, subproc_running);
	return;
}

static void subproc_stop(struct subprocess *s)
{
	if (s->pid <= 0)
		fprintf(stderr, "%s: Illegal PID %d\n", __func__, s->pid);
	else
		kill(s->pid, SIGTERM);
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

	if ((doc = xmlParseFile(filename)) == NULL) {
		abort();
	}
	if ((ptr = xmlDocGetRootElement(doc)) == NULL ||
	    strcmp_1u(ptr->name, "ccgfs-super") != 0) {
		fprintf(stderr, "%s: Could not find root element\n", filename);
		xmlFreeDoc(doc);
		abort();
	}

	if ((subp_list = HXdeque_init()) == NULL) {
		perror("malloc");
		abort();
	}

	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp_1u(ptr->name, "s") == 0)
			config_parse_subproc(subp_list, ptr);
	}
	xmlFreeDoc(doc);
	return subp_list;
}

/*
 * config_parse_subproc - parse an <s> element
 * @dq:		subprocess list to append to
 * @xml_ptr:	libxml stuff
 */
static void config_parse_subproc(struct HXdeque *dq, const xmlNode *xml_ptr)
{
	const struct HXdeque_node *node;
	struct HXdeque *str_ptrs;
	struct subprocess *subp;
	unsigned int i = 0;
	SHA_CTX ctx;

	if ((str_ptrs = HXdeque_init()) == NULL) {
		perror("malloc");
		abort();
	}
	if ((subp = malloc(sizeof(struct subprocess))) == NULL) {
		perror("malloc");
		abort();
	}
	subp->start_time = 0;
	subp->status     = SUBP_INACTIVE;
	subp->pid        = -1;

	for (xml_ptr = xml_ptr->children; xml_ptr != NULL;
	    xml_ptr = xml_ptr->next)
	{
		const char *in;
		char *out;

		if (xml_ptr->type != XML_TEXT_NODE)
			continue;
		/*
		 * Split at whitespace (it is kept simple for now),
		 * copy i => o, record string start pointers in @args.
		 */
		in = out = HX_strdup(xml_ptr->content);
		while (*in != '\0') {
			while (isspace(*in) || *in == '\n')
				++in;
			HXdeque_push(str_ptrs, out);
			while (!isspace(*in) && *in != '\n')
				*out++ = *in++;
			*out++ = '\0';
			++in;
		}
	}

	/* Convert to vector and calculate checksum */
	subp->args = malloc(sizeof(char *) * (str_ptrs->items + 1));
	SHA_Init(&ctx);

	for (node = str_ptrs->first, i = 0; node != NULL; node = node->next) {
		SHA_Update(&ctx, node->ptr, strlen(node->ptr) + 1);
		subp->args[i++] = HX_strdup(node->ptr);
	}

	SHA_Final(subp->checksum, &ctx);
	subp->args[i] = NULL;
	HXdeque_free(str_ptrs);
	HXdeque_push(dq, subp);
	return;
}
