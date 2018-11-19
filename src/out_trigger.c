/*
 * out_trigger.c		Trigger based on traffic pattern
 *
 * Copyright (c) 2018 Babak Farrokhi <babak@farrokhi.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <bmon/bmon.h>
#include <bmon/graph.h>
#include <bmon/conf.h>
#include <bmon/output.h>
#include <bmon/group.h>
#include <bmon/element.h>
#include <bmon/input.h>
#include <bmon/utils.h>
#include <bmon/attr.h>

#define RECENT_SIZE 3

static int c_quit_after_trigger = 0;
static long c_threshold_high = -1;
static long c_threshold_low = -1;
static unsigned long recent_l[RECENT_SIZE];
static unsigned long recent_count = 0;
static unsigned long recent_avg = 0;
static unsigned long triggered = 0;
static char *c_format;
static FILE *c_fd;

static char *get_token(struct element_group *g, struct element *e,
		       const char *token, char *buf, size_t len)
{
	char *name = strchr(token, ':');

	struct attr_def *def;
	struct attr *a;

	if (!name)
		quit("Invalid attribute field \"%s\"\n", token);

	name++;

	def = attr_def_lookup(name);
	if (!def)
		quit("Undefined attribute \"%s\"\n", name);

	if (!(a = attr_lookup(e, def->ad_id)))
		quit("Invalid attribute \"%s\"\n", name);

	if (!strncasecmp(token, "rxrate:", 7)) {
		snprintf(buf, len, "%.2f", a->a_rx_rate.r_rate);
		return buf;
	} else if (!strncasecmp(token, "txrate:", 7)) {
		snprintf(buf, len, "%.2f", a->a_tx_rate.r_rate);
		return buf;
	}

	quit("Unknown field \"%s\"\n", token);

	return NULL;
}

static void run_trigger()
{
	// TODO: Run the command
	if (++triggered >= c_quit_after_trigger)
		exit(0);
}

static void trigger_check()
{
	if (recent_count < RECENT_SIZE)
		return;

	if (c_threshold_high > 0 && recent_avg > c_threshold_high) {
		fprintf(c_fd, "TRIGGER: Passed high threshold: %li > %li\n", recent_avg, c_threshold_high);
		run_trigger();
		return;
	}
	if (c_threshold_low > 0 && recent_avg < c_threshold_low) {
		fprintf(c_fd, "TRIGGER: Droppped below threshold: %li < %li\n", recent_avg, c_threshold_low);
		run_trigger();
		return;
	}
}

static void trigger_process(struct element_group *g, struct element *e, void *arg)
{
	char buf[128];
	char *p;

	p = get_token(g, e, c_format, buf, sizeof(buf));

	if (p)
	{
		int i;
		unsigned long total = 0;

		recent_l[recent_count % RECENT_SIZE] = strtol(p, NULL, 0);
		for (i=0; i < RECENT_SIZE; i++)
		{
			fprintf(c_fd, "%li ", recent_l[i]);
			total += recent_l[i];
		}

		recent_avg = (unsigned long) total / RECENT_SIZE;
		fprintf(c_fd, " avg: %li\n", recent_avg);
		trigger_check();
		recent_count++;
	}
}

static void trigger_do(void)
{
	group_foreach_recursive(trigger_process, NULL);
	fflush(stdout);
}

static void print_help(void)
{
	printf(
	"trigger - Run actions based on traffic patterns\n" \
	"\n" \
	"  Monitors a given probe and triggers an action if the criteria is met.\n" \
	"  Criterias could be going above or dropping below a given threshold of traffic.\n" \
	"  Probes could be Bytes/sec or Packets/sec on TX or RX\n" \
	"\n" \
	"\n" \
	"  Author: Babak Farrokhi <babak@farrokhi.net>\n" \
	"\n" \
	"  Options:\n" \
	"    probe=ELEMENT     Element to monitor for threshold\n" \
	"    action=PROGRAM    Program or script to run when triggered\n" \
	"    below=THRESHOLD   Minimum acceptable level for given element (average in past three seconds)\n" \
	"    above=THRESHOLD   Maximum acceptable level for given element (average in past three seconds)\n" \
	"    quittriggers=NUM  Quit after NUM triggers\n" \
	"\n" \
	"  Probe Elements:\n" \
	"    rxrate:packets    RX packet rate\n" \
	"    txrate:packets    TX packet rate\n" \
	"    rxrate:bytes      RX traffic rate (bytes)\n" \
	"    txrate:bytes      TX traffic rate (bytes)\n" \
	"\n" \
	"  Examples:\n" \
	"    bmon -p eth0 -o 'trigger:probe=rxrate:packets;below=5000;quittriggers=3;action=/opt/bin/alert'\n" \
	"\n");
}

static void trigger_parse_opt(const char *type, const char *value)
{
	if (!strcasecmp(type, "above") && value)
		c_threshold_high = strtol(value, NULL, 0);
	else if (!strcasecmp(type, "below") && value)
		c_threshold_low = strtol(value, NULL, 0);
	else if (!strcasecmp(type, "quittriggers") && value)
		c_quit_after_trigger = strtol(value, NULL, 0);
	else if (!strcasecmp(type, "probe")) {
		if (c_format)
			free(c_format);
		c_format = strdup(value);
	}
	else if (!strcasecmp(type, "help")) {
		print_help();
		exit(0);
	}
}

static struct bmon_module trigger_ops = {
	.m_name		= "trigger",
	.m_do		= trigger_do,
	.m_parse_opt	= trigger_parse_opt,
};

static void __init ascii_init(void)
{
	c_fd = stdout;
	c_format = strdup("$(rxrate:packets)\\n");

	output_register(&trigger_ops);
}
