/*******************************************************************************

  Flow Library - Helpers for working on Flow API 
  Copyright(c) 2014 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Author: John Fastabend <john.r.fastabend@intel.com>

*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/attr.h>

#include <linux/if_ether.h>

#include <gvc.h>

#include "./include/if_flow.h"
#include "./include/flowlib.h"

#define MAX_TABLES 200
#define MAX_HDRS 200
#define MAX_FIELDS 200
#define MAX_ACTIONS 200
#define MAX_NODES 200

static char none[] = "<none>";
static char label[] = "label";
static char any[] = "<any>";
static char empty[] = "";
static char agopen_g[] = "g";
static char rankdir[] = "rankdir";
static char LR[] = "LR";
static char shape[] = "shape";
static char record[] = "record";

Agnode_t *graphviz_table_nodes[MAX_NODES];
Agnode_t *graphviz_header_nodes[MAX_NODES];

struct net_flow_tbl *tables[MAX_TABLES];
struct net_flow_hdr *headers[MAX_HDRS];	
struct net_flow_field *header_fields[MAX_HDRS][MAX_FIELDS];
struct net_flow_action *actions[MAX_ACTIONS];
struct net_flow_hdr_node *graph_nodes[MAX_NODES];

char *graph_names(int uid)
{
	return graph_nodes[uid] ? graph_nodes[uid]->name : none;
}

struct net_flow_hdr_node *get_graph_node(int uid)
{
	return graph_nodes[uid];
}

char *headers_names(int uid)
{
	return headers[uid] ? headers[uid]->name : none;
}

struct net_flow_hdr *get_headers(int uid)
{
	return headers[uid];
}

char *fields_names(int hid, int fid)
{
	return header_fields[hid][fid] ? header_fields[hid][fid]->name : none;
}

struct net_flow_field *get_fields(int huid, int uid)
{
	return header_fields[huid][uid];
}

char *table_names(int uid)
{
	return tables[uid] ? tables[uid]->name : none;
}

struct net_flow_tbl *get_tables(int uid)
{
	return tables[uid];
}

int get_table_id(char *name)
{
	int i;

	for (i = 0; i < MAX_TABLES; i++) {
		if (tables[i]) {
			tables[i]->name = strdup(name);
			if (!tables[i]->name)
				return -ENOMEM;
			return tables[i]->uid;
		}
	}

	return 0;
}

int gen_table_id(void)
{
	int i,j;

	for (i = 1; i < MAX_TABLES; i++) {
		for (j = 1; j < MAX_TABLES; j++) {
			if (tables[j])
				break;
		}

		if (j != (MAX_TABLES - 1))
			break;	
	}

	if (i == (MAX_TABLES - 1))
		return -EBUSY;

	return i;
}

char *action_names(int uid)
{
	return actions[uid]->name;
}

struct net_flow_action *get_actions(int uid)
{
	return actions[uid];
}

int find_table(char *name)
{
	int i;

	for (i = 0; i < MAX_TABLES; i++) {
		if (tables[i] && strcmp(table_names(i), name) == 0)
			return tables[i]->uid;
	}

	return -EINVAL;
}

int find_action(char *name)
{
	int i;

	for (i = 0; i < MAX_ACTIONS; i++) {
		if (actions[i] && strcmp(action_names(i), name) == 0) {
			return actions[i]->uid;
		}
	}
	return -EINVAL;
}

int find_header_node(char *name)
{
	int i;

	for (i = 0; i < MAX_NODES; i++) {
		if (graph_nodes[i] && strcmp(graph_names(i), name) == 0)
			return graph_nodes[i]->uid;
	}
	return -EINVAL;
}

int find_field(char *field, int hdr)
{
	struct net_flow_hdr *header;
	int i;

	header = get_headers(hdr);

	for (i = 0; i < MAX_FIELDS; i++) {
		if (header->fields[i].uid &&
		    strcmp(header->fields[i].name, field) == 0)
			return header->fields[i].uid;
	}
	return -EINVAL;
}

int find_match(char *header, char *field, int *hi, int *li)
{
	int i;

	*hi = *li = -1;

	for (i = 0; i < MAX_HDRS; i++) {
		if (headers[i] && strcmp(headers_names(i), header) == 0) {
			*hi = headers[i]->uid;
			break;
		}
	}

	for (i = 0; *hi >= 0 && i < MAX_FIELDS; i++) {
		if (header_fields[*hi][i] && strcmp(fields_names(*hi, i), field) == 0) {
			*li = header_fields[*hi][i]->uid;
			break;	
		}
	}

	if (*hi < 0 || *li < 0)
		return -EINVAL;

	return 0;
}

void flow_push_headers(struct net_flow_hdr **h)
{
	int i;

	for (i = 0; h[i]->uid; i++)
		headers[h[i]->uid] = h[i];	
}

void flow_push_actions(struct net_flow_action **a)
{
	int i;

	for (i = 0; a[i]->uid; i++)
		actions[a[i]->uid] = a[i];	
}

void flow_push_tables(struct net_flow_tbl *t)
{
	int i;

	for (i = 0; t[i].uid; i++)
		tables[t[i].uid] = &t[i];	
}

void flow_pop_tables(struct net_flow_tbl *t)
{
	int i;

	for (i = 0; t[i].uid; i++)
		free(tables[t[i].uid]);
}
void flow_push_header_fields(struct net_flow_hdr **h)
{
	int i, j;

	for (i = 0; h[i]->uid; i++) {
		struct net_flow_field *f = h[i]->fields;
		int uid = h[i]->uid;

		for (j = 0; j < h[i]->field_sz; j++)
			header_fields[uid][f[j].uid] = &f[j];
	}
}

void flow_push_graph_nodes(struct net_flow_hdr_node **n)
{
	int i;

	for (i = 0; n[i]->uid; i++)
		graph_nodes[n[i]->uid] = n[i];
}

/* Work with graphviz dot graphs */
static GVC_t *gvc;

void flow_init_graph()
{
	gvc = gvContext();
}

/* ll_addr_n2a is a iproute 2 library call hard coded here for now */
const char *ll_addr_n2a(unsigned char *addr, int alen, int type, char *buf, int blen)
{
	int i;
	int l = 0;

	for (i=0; i<alen; i++) {
		if (i==0) {
			snprintf(buf+l, blen, "%02x", addr[i]);
			blen -= 2;
			l += 2;
		} else {
			snprintf(buf+l, blen, ":%02x", addr[i]);
			blen -= 3;
			l += 3;
		}
	}
	return buf;
}

/* ll_addr_a2n is a iproute 2 library call hard coded here for now */
const int ll_addr_a2n(char *lladdr, int len, const char *arg)
{
	int i;

	for (i=0; i<len; i++) {
		int temp;
		char *cp = strchr(arg, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(arg, "%x", &temp) != 1)
			return -EINVAL;
		if (temp < 0 || temp > 255)
			return -EINVAL;
		lladdr[i] = (char)temp;
		if (!cp)
			break;
		arg = cp;
	}
	return i+1;
}

static void pfprintf(FILE *fp, int print, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (print)
		vfprintf(fp, format, args);

	va_end(args);
}

/* Top level parsing handled in applications */
#if 0
static struct nla_policy flow_get_tables_policy[NET_FLOW_MAX+1] = {
	[NET_FLOW_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_FLOW_TABLES]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]		= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS] 		= { .type = NLA_NESTED },
	[NET_FLOW_PARSE_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]		= { .type = NLA_NESTED },
};
#endif

struct nla_policy net_flow_table_policy[NET_FLOW_TABLE_ATTR_MAX + 1] = {
	[NET_FLOW_TABLE_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_FLOW_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_APPLY]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING, },
	[NET_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

struct nla_policy net_flow_action_arg_policy[NET_FLOW_ACTION_ARG_MAX + 1] = {
	[NET_FLOW_ACTION_ARG_NAME]	= {.type = NLA_STRING, },
	[NET_FLOW_ACTION_ARG_TYPE]	= {.type = NLA_U32 },
	[NET_FLOW_ACTION_ARG_VALUE]	= {.type = NLA_UNSPEC, },
};

static struct nla_policy flow_get_field_policy[NET_FLOW_FIELD_ATTR_MAX+1] = {
	[NET_FLOW_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_FLOW_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};

static struct nla_policy net_flow_field_policy[NET_FLOW_FIELD_REF_MAX + 1] = {
	[NET_FLOW_FIELD_REF_NEXT_NODE]  = { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_INSTANCE]   = { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_HEADER]	= { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_FIELD]	= { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_MASK_TYPE]	= { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_TYPE]	= { .type = NLA_U32,},
	[NET_FLOW_FIELD_REF_VALUE]	= { .type = NLA_UNSPEC,},
	[NET_FLOW_FIELD_REF_MASK]	= { .type = NLA_UNSPEC,},
};

static struct nla_policy flow_table_flow_policy[NET_FLOW_ATTR_MAX+1] = {
	[NET_FLOW_ATTR_TABLE]		= { .type = NLA_U32,},
	[NET_FLOW_ATTR_UID]		= { .type = NLA_U32,},
	[NET_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32,},
	[NET_FLOW_ATTR_MATCHES]		= { .type = NLA_NESTED,},
	[NET_FLOW_ATTR_ACTIONS]		= { .type = NLA_NESTED,},
};

static struct nla_policy flow_get_header_policy[NET_FLOW_FIELD_ATTR_MAX+1] = {
	[NET_FLOW_HEADER_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_FLOW_HEADER_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

static struct nla_policy flow_get_node_policy[NET_FLOW_TABLE_GRAPH_NODE_MAX + 1] = {
	[NET_FLOW_TABLE_GRAPH_NODE_UID]    = { .type = NLA_U32,},
	[NET_FLOW_TABLE_GRAPH_NODE_FLAGS]    = { .type = NLA_U32,},
	[NET_FLOW_TABLE_GRAPH_NODE_JUMP]   = { .type = NLA_NESTED,},
};

static struct nla_policy flow_get_hdr_node_policy[NET_FLOW_HEADER_NODE_MAX + 1] = {
	[NET_FLOW_HEADER_NODE_NAME] = { .type = NLA_STRING,},
	[NET_FLOW_HEADER_NODE_UID]  = { .type = NLA_U32,},
	[NET_FLOW_HEADER_NODE_HDRS] = { .type = NLA_NESTED,},
	[NET_FLOW_HEADER_NODE_JUMP] = { .type = NLA_NESTED,},
};

static void pp_field_ref(FILE *fp, int print, struct net_flow_field_ref *ref, bool first, bool nl, Agedge_t *e)
{
	char b1[64] = ""; /* arbitrary string field for mac */
	char fieldstr[1024];
	int fieldlen = 1024;//sizeof(*fieldstr);
	int inst = ref->instance;
	int hi = ref->header;
	int fi = ref->field;

	if (!hi)
		return;

	if (!ref->type) {
		if (!ref->header && !ref->field) {
			pfprintf(fp, print, "\t <any>");
			if (e)
				agsafeset(e, label, any, empty);
		} else if (!first) {
			pfprintf(fp, print, " %s", fi ? fields_names(hi, fi) : empty);
			if (e)
				agsafeset(e, label, fi ? fields_names(hi, fi) : empty, empty);
		} else {
			pfprintf(fp, print, "\n\t field: %s [%s",
				 graph_names(inst), fi ? fields_names(hi, fi) : empty);
			if (e)
				agsafeset(e, label, fi ? fields_names(hi, fi) : empty, empty);
		}

		switch (ref->mask_type) {
		case NET_FLOW_MASK_TYPE_EXACT:
			pfprintf(fp, print, " (exact)");
			break;
		case NET_FLOW_MASK_TYPE_LPM:
			pfprintf(fp, print, " (lpm)");
			break;
		default:
			break;
		}
	}

	switch (ref->type) {
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U8:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %02x (%02x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty, ref->v.u8.value_u8, ref->v.u8.mask_u8);

		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U16:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %04x (%04x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty, ref->v.u16.value_u16, ref->v.u16.mask_u16);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U32:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %08x (%08x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty, ref->v.u32.value_u32, ref->v.u32.mask_u32);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U64:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %s (%s)",
			 headers_names(hi), fi ? fields_names(hi, fi) : empty,
			 ll_addr_n2a((unsigned char *)&ref->v.u64.value_u64, ETH_ALEN, 0, b1, sizeof(b1)),
			 ll_addr_n2a((unsigned char *)&ref->v.u64.mask_u64, ETH_ALEN, 0, b1, sizeof(b1)));
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	default:
		break;
	}

	if (ref->type)
		pfprintf(fp, print, "%s", fieldstr);

	if (ref->type && nl)
		pfprintf(fp, print, "\n");
}

void pp_fields(FILE *fp, int print, struct net_flow_field_ref *ref)
{
	int i;
	bool first = true;

	for (i = 0; ref[i].header; i++) {
		if (i > 0  && (ref[i-1].header != ref[i].header)) {
			pfprintf(fp, print, "]");
			first = true;
		}

		pp_field_ref(fp, print, &ref[i], first, true, NULL);
		first = false;
	}
	if (i > 0 && !ref[i-1].type)
		pfprintf(fp, print, "]\n");
}

const char *flow_table_arg_type_str[__NET_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

void pp_action(FILE *fp, int print, struct net_flow_action *act)
{
	struct net_flow_action_arg *arg;
	int i;

	pfprintf(fp, print, "\t   %i: %s ( ", act->uid, act->name ? act->name : empty);

	if (!act->args)
		goto out;

	for (i = 0; act->args[i].type; i++) {
		arg = &act->args[i];

		pfprintf(fp, print, "%s %s ",
			 flow_table_arg_type_str[arg->type],
			 arg->name ? arg->name : empty);

		switch (arg->type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			pfprintf(fp, print, "%02x ", arg->v.value_u8);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			pfprintf(fp, print, "%" PRIu16 "", arg->v.value_u16);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			pfprintf(fp, print, "%" PRIu32 "", arg->v.value_u32);
		break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			pfprintf(fp, print, "%" PRIu64 "", arg->v.value_u64);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_NULL:
		default:
			break;
		}
	}
out:
	pfprintf(fp, print, " )\n");
}

void pp_actions(FILE *fp, int print, struct net_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		pp_action(fp, print, &actions[i]);
}

void pp_table(FILE *fp, int print, struct net_flow_tbl *table)
{
	int i;

	pfprintf(fp, print, "\n%s:%u src %u apply %u size %u\n",
		 table->name, table->uid, table->source, table->apply_action, table->size);

	pfprintf(fp, print, "  matches:");
	if (table->matches)
		pp_fields(fp, print, table->matches);

	pfprintf(fp, print, "  actions:\n");
	if (table->actions) {
		for (i = 0; table->actions[i]; i++) {
			struct net_flow_action *act = actions[table->actions[i]];

			if (!act) {
				fprintf(stderr, "unknown action uid %i\n", table->actions[i]);
				continue;
			}

			if (act->uid)
				pp_action(stdout, print, act);
		}
	}
}

void pp_header(FILE *fp, int print, struct net_flow_hdr *header)
{
	struct net_flow_field *f;
	int i = 0;

	pfprintf(fp, print, "  %s {\n\t", header->name);

	for (f = &header->fields[i];
	     f->uid;
	     f = &header->fields[++i]) {
		if (f->bitwidth >= 0)
			pfprintf(fp, print, " %s:%u ", f->name, f->bitwidth);
		else
			pfprintf(fp, print, " %s:* ", f->name);

		if (i && !(i % 5))
			pfprintf(fp, print, " \n\t");
	}

	if (i % 5)
		pfprintf(fp, print, "\n\t");
	pfprintf(fp, print, " }\n");
}

void pp_flow(FILE *fp, int print, struct net_flow_flow *flow)
{
	pfprintf(fp, print, "table : %u  ", flow->table_id);
	pfprintf(fp, print, "uid : %u  ", flow->uid);
	pfprintf(fp, print, "prio : %u\n", flow->priority);

	if (flow->matches)
		pp_fields(fp, print, flow->matches);	
	if (flow->actions)
		pp_actions(fp, print, flow->actions);	
}


void pp_flows(FILE *fp, int print, struct net_flow_flow *flows)
{
	int i;

	if (!print)
		return;

	for (i = 0; flows[i].uid; i++)
		pp_flow(fp, print, &flows[i]);
}

static void pp_jump_table(FILE *fp, int print,
			  struct net_flow_field_ref *jump)
{
	if (!print)
		return;

	pp_field_ref(fp, print, jump, 0, false, NULL);
	if (jump->next_node < 0)
		pfprintf(fp, print, " -> terminal\n");
	else {
		pfprintf(fp, print, " -> %s\n", table_names(jump->next_node));
	}

}

static int flow_compar_graph_nodes(const void *a, const void *b)
{
	const struct net_flow_tbl_node *g_a, *g_b;
	const struct net_flow_tbl *t_a, *t_b;

	g_a = a;
	g_b = b;

	t_a = get_tables(g_a->uid);
	t_b = get_tables(g_b->uid);

	if (t_a->source < t_b->source)
		return -1;
	else if (t_a->source == t_b->source)
		return 0;
	else if (t_a->source > t_b->source)
		return 1;

	return -EINVAL;
}

static void pp_tbl_node_flags(FILE *fp, int print, __u32 flags)
{
	if (!print)
		return;

	if (flags)
		pfprintf(fp, print, "( ");
	if (flags & NET_FLOW_TABLE_EGRESS_ROOT)
		pfprintf(fp, print, "EGRESS ");
	if (flags & NET_FLOW_TABLE_INGRESS_ROOT)
		pfprintf(fp, print, "INGRESS ");
	if (flags & NET_FLOW_TABLE_DYNAMIC)
		pfprintf(fp, print, "DYNAMIC ");
	if (flags)
		pfprintf(fp, print, ") ");
}
 
void pp_table_graph(FILE *fp, int print, struct net_flow_tbl_node *nodes)
{
	int i, j, src = -1;

	if (!print)
		return;

	for (i = 0; nodes[i].uid; i++)
		;

	qsort(nodes, i, sizeof(*nodes), flow_compar_graph_nodes);
	for (i = 0; nodes[i].uid; i++) {
		struct net_flow_tbl *t = get_tables(nodes[i].uid);

		if (src != t->source) {
			src = t->source;
			pfprintf(fp, print, "source: %u\n", src);
		}

		pfprintf(fp, print, "\t%s: ", table_names(nodes[i].uid));
		pp_tbl_node_flags(fp, print, nodes[i].flags);
		for (j = 0; nodes[i].jump[j].next_node; ++j)
			pp_jump_table(fp, print, &nodes[i].jump[j]);
	}
}

static void ppg_jump_table(struct net_flow_field_ref *jump,
			   Agraph_t *g, Agnode_t *n)
{
	//pp_field_ref(fp, print, &jump->field, 0, false);
	if (jump->next_node > 0)
		agedge(g, n, graphviz_table_nodes[jump->next_node], 0, 1);
}

void ppg_table_graph(FILE *fp, int print, struct net_flow_tbl_node *nodes)
{
	Agraph_t *s = NULL, *g = agopen(agopen_g, Agdirected, 0);
	char srcstr[80];
	__u32 src = 0;
	int i, j;

	agsafeset(g, rankdir, LR, empty);
	for (i = 0; nodes[i].uid; i++) {
		struct net_flow_tbl *t = get_tables(nodes[i].uid);
		Agnode_t *n;

		if (src != t->source) {
			src = t->source;
			sprintf(srcstr, "cluster-%u", src);
			s = agsubg(g, srcstr, 1);
			sprintf(srcstr, "source-%u", src);
			agsafeset(s, label, srcstr, empty);
		}

		n = agnode(s, table_names(nodes[i].uid), 1);

		agsafeset(n, shape, record, empty); /* use record boxes */
		graphviz_table_nodes[nodes[i].uid] = n;
	}

	qsort(nodes, i, sizeof(*nodes), flow_compar_graph_nodes);
	for (i = 0; nodes[i].uid; i++) {
		for (j = 0; nodes[i].jump[j].next_node; ++j)
			ppg_jump_table(&nodes[i].jump[j], s,
				       graphviz_table_nodes[nodes[i].uid]);
	}
	agwrite(g, fp);
}

void ppg_header_graph(FILE *fp, struct net_flow_hdr_node *nodes)
{
	Agraph_t *g = agopen(agopen_g, Agdirected, 0);
	Agedge_t *e;
	int i, j;

	for (i = 0; nodes[i].uid; i++) {
		graphviz_header_nodes[nodes[i].uid] = agnode(g, nodes[i].name, 1);
	}

#if 0
		for (j = 0; nodes[i].hdrs[j]; j++)
			pfprintf(fp, print, " %s ",
				 headers_names(nodes[i].hdrs[j]));
#endif

	for (i = 0; nodes[i].uid; i++) {
		for (j = 0; nodes[i].jump[j].next_node; ++j) {
			if (nodes[i].jump[j].next_node > 0) {
				e = agedge(g, graphviz_header_nodes[nodes[i].uid], graphviz_header_nodes[nodes[i].jump[j].next_node], 0, 1);
				pp_field_ref(fp, false, &nodes[i].jump[j], 0, false, e);
			}
		}
	}
	agwrite(g, fp);
}

void pp_header_graph(FILE *fp, int print, struct net_flow_hdr_node *nodes)
{
	int i, j;

	if (!print)
		return;

	for (i = 0; nodes[i].uid; i++) {
		pfprintf(fp, print, "%s-node: ", nodes[i].name);

		for (j = 0; nodes[i].hdrs[j]; j++)
			pfprintf(fp, print, " %s ",
				 headers_names(nodes[i].hdrs[j]));

		pfprintf(fp, print, "\n");	
		for (j = 0; nodes[i].jump[j].next_node; ++j) {
			pp_field_ref(fp, print, &nodes[i].jump[j], 0, false, NULL);
			if (nodes[i].jump[j].next_node < 0)
				pfprintf(fp, print, " -> terminal\n");
			else
				pfprintf(fp, print, " -> %s\n", graph_names(nodes[i].jump[j].next_node));
		}
		pfprintf(fp, print, "\n");
	}
}

int flow_get_field(FILE *fp, int print, struct nlattr *nla, struct net_flow_field_ref *field)
{
	struct nlattr *ref[NET_FLOW_FIELD_REF_MAX+1];
	int err;

	err = nla_parse_nested(ref, NET_FLOW_FIELD_REF_MAX,
			       nla, net_flow_field_policy);
	if (err)
		return err;

	if (ref[NET_FLOW_FIELD_REF_NEXT_NODE])
		field->next_node = nla_get_u32(ref[NET_FLOW_FIELD_REF_NEXT_NODE]);

	if (!ref[NET_FLOW_FIELD_REF_INSTANCE] ||
	    !ref[NET_FLOW_FIELD_REF_HEADER] ||
	    !ref[NET_FLOW_FIELD_REF_FIELD] ||
	    !ref[NET_FLOW_FIELD_REF_MASK_TYPE] ||
	    !ref[NET_FLOW_FIELD_REF_TYPE])
		return 0;

	field->instance = nla_get_u32(ref[NET_FLOW_FIELD_REF_INSTANCE]);
	field->header = nla_get_u32(ref[NET_FLOW_FIELD_REF_HEADER]);
	field->field = nla_get_u32(ref[NET_FLOW_FIELD_REF_FIELD]);
	field->mask_type = nla_get_u32(ref[NET_FLOW_FIELD_REF_MASK_TYPE]);
	field->type = nla_get_u32(ref[NET_FLOW_FIELD_REF_TYPE]);

	if (!ref[NET_FLOW_FIELD_REF_VALUE])
		goto out;

	switch (field->type) {
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U8:
		if (nla_len(ref[NET_FLOW_FIELD_REF_VALUE]) < sizeof(__u8)) {
			err = -EINVAL;
			break;
		}
		field->v.u8.value_u8 = nla_get_u8(ref[NET_FLOW_FIELD_REF_VALUE]);

		if (!ref[NET_FLOW_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_FLOW_FIELD_REF_MASK]) < sizeof(__u8)) {
			err = -EINVAL;
			break;
		}
		field->v.u8.mask_u8 = nla_get_u8(ref[NET_FLOW_FIELD_REF_MASK]);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U16:
		if (nla_len(ref[NET_FLOW_FIELD_REF_VALUE]) < sizeof(__u16)) {
			err = -EINVAL;
			break;
		}
		field->v.u16.value_u16 = nla_get_u16(ref[NET_FLOW_FIELD_REF_VALUE]);

		if (!ref[NET_FLOW_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_FLOW_FIELD_REF_MASK]) < sizeof(__u16)) {
			err = -EINVAL;
			break;
		}
		field->v.u16.mask_u16 = nla_get_u16(ref[NET_FLOW_FIELD_REF_MASK]);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U32:
		if (nla_len(ref[NET_FLOW_FIELD_REF_VALUE]) < sizeof(__u32)) {
			err = -EINVAL;
			break;
		}
		field->v.u32.value_u32 = nla_get_u32(ref[NET_FLOW_FIELD_REF_VALUE]);

		if (!ref[NET_FLOW_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_FLOW_FIELD_REF_MASK]) < sizeof(__u32)) {
			err = -EINVAL;
			break;
		}
		field->v.u32.mask_u32 = nla_get_u32(ref[NET_FLOW_FIELD_REF_MASK]);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U64:
		if (nla_len(ref[NET_FLOW_FIELD_REF_VALUE]) < sizeof(__u64)) {
			err = -EINVAL;
			break;
		}
		field->v.u64.value_u64 = nla_get_u64(ref[NET_FLOW_FIELD_REF_VALUE]);

		if (!ref[NET_FLOW_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_FLOW_FIELD_REF_MASK]) < sizeof(__u64)) {
			err = -EINVAL;
			break;
		}
		field->v.u64.mask_u64 = nla_get_u64(ref[NET_FLOW_FIELD_REF_MASK]);
		break;
	default:
		err = -EINVAL;
		break;
	}

out:
	pp_field_ref(fp, print, field, -1, true, NULL);

	return err;
}

static int flow_get_action_arg(struct net_flow_action_arg *arg, struct nlattr *nl)
{
	struct nlattr *tb[NET_FLOW_ACTION_ARG_MAX+1];
	int err;

	err = nla_parse_nested(tb, NET_FLOW_ACTION_ARG_MAX, nl, net_flow_action_arg_policy);
	if (err) {
		fprintf(stderr, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	if (!tb[NET_FLOW_ACTION_ARG_TYPE])
		return -EINVAL;	

	if (tb[NET_FLOW_ACTION_ARG_NAME]) {
		int max = nla_len(tb[NET_FLOW_ACTION_ARG_NAME]);

		if (max > NET_FLOW_MAX_NAME)
			max = NET_FLOW_MAX_NAME;

		arg->name = calloc(1, max);
		if (!arg->name)
			return -ENOMEM;

		nla_strlcpy(arg->name, tb[NET_FLOW_ACTION_ARG_NAME], max);
	} else {
		arg->name = "none";
	}

	arg->type = nla_get_u32(tb[NET_FLOW_ACTION_ARG_TYPE]);

	if (!tb[NET_FLOW_ACTION_ARG_VALUE])
		return 0;

	switch (arg->type) {
	case NET_FLOW_ACTION_ARG_TYPE_U8:
		if (nla_len(tb[NET_FLOW_ACTION_ARG_VALUE]) < sizeof(__u8))
			return -EINVAL;
		arg->v.value_u8 = nla_get_u8(tb[NET_FLOW_ACTION_ARG_VALUE]);
		break;
	case NET_FLOW_ACTION_ARG_TYPE_U16:
		if (nla_len(tb[NET_FLOW_ACTION_ARG_VALUE]) < sizeof(__u16))
			return -EINVAL;
		arg->v.value_u16 = nla_get_u16(tb[NET_FLOW_ACTION_ARG_VALUE]);
		break;
	case NET_FLOW_ACTION_ARG_TYPE_U32:
		if (nla_len(tb[NET_FLOW_ACTION_ARG_VALUE]) < sizeof(__u32))
			return -EINVAL;
		arg->v.value_u32 = nla_get_u32(tb[NET_FLOW_ACTION_ARG_VALUE]);
		break;
	case NET_FLOW_ACTION_ARG_TYPE_U64:
		if (nla_len(tb[NET_FLOW_ACTION_ARG_VALUE]) < sizeof(__u64))
			return -EINVAL;
		arg->v.value_u64 = nla_get_u64(tb[NET_FLOW_ACTION_ARG_VALUE]);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int flow_get_action(FILE *fp, int print, struct nlattr *nl, struct net_flow_action *a)
{
	int rem;
	struct nlattr *signature, *l;
	struct nlattr *action[NET_FLOW_ACTION_ATTR_MAX+1];
	struct net_flow_action *act;
	int err, uid, count = 0;
	char *name;

	err = nla_parse_nested(action, NET_FLOW_ACTION_ATTR_MAX, nl, net_flow_action_policy);
	if (err) {
		fprintf(stderr, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	uid = action[NET_FLOW_ACTION_ATTR_UID] ? nla_get_u32(action[NET_FLOW_ACTION_ATTR_UID]) : -1;
	if (uid < 0)
		return 0;

	act = actions[uid]; /* TBD review error paths */
	if (!act) {
		act = calloc(1, sizeof(struct net_flow_action));
		if (!act)
			return -ENOMEM;
	}

	if (action[NET_FLOW_ACTION_ATTR_NAME]) {
		act->uid = uid;
		name = nla_get_string(action[NET_FLOW_ACTION_ATTR_NAME]);
		act->name = strdup(name);
		if (!act->name)
			return -ENOMEM;
	} else if (act && act->uid) {
		name = act->name;
	} else {
		name = none;
	}


	if (!action[NET_FLOW_ACTION_ATTR_SIGNATURE])
		goto done;

	signature = action[NET_FLOW_ACTION_ATTR_SIGNATURE];
	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem))
		count++;

	if (count > 0) {
		act->args = calloc(count + 1, sizeof(struct net_flow_action_arg));
		if (!act->args)
			return -ENOMEM;
	}

	count = 0;

	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem)) {
		err = flow_get_action_arg(&act->args[count], l);
		if (err)
			return err;
		count++;
	}

done:
	if (a) {
		a->uid = act->uid;
		a->name = strdup(act->name);
		if (!a->name)
			return -ENOMEM;
		a->args = act->args;
	}
	actions[uid] = act;
	pp_action(fp, print, act);
	return 0;
}

int flow_get_matches(FILE *fp, int print, struct nlattr *nl, struct net_flow_field_ref **ref)
{
	struct net_flow_field_ref *r;
	struct nlattr *i;
	int rem, cnt;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	r = calloc(cnt + 1, sizeof(struct net_flow_field_ref));
	if (!r)
		return -ENOMEM;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem), cnt++)
		flow_get_field(fp, print, i, &r[cnt]);

	if (ref)
		*ref = r;
	return 0;
}

int flow_get_actions(FILE *fp, int print, struct nlattr *nl, struct net_flow_action **actions)
{
	struct net_flow_action *acts;
	int rem, j = 0;
	struct nlattr *i;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) 
		j++;

	acts = calloc(j + 1, sizeof(struct net_flow_action));
	if (!acts)
		return -ENOMEM; 

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++)
		flow_get_action(fp, print, i, &acts[j]);

	if (actions)
		*actions = acts;
	else
		free(acts);

	return 0;
}


int flow_get_table(FILE *fp, int print, struct nlattr *nl,
		   struct net_flow_tbl *t)
{
	struct nlattr *table[NET_FLOW_TABLE_ATTR_MAX+1];
	struct net_flow_field_ref *matches = NULL;
	__u32 uid, src, apply, size;
	int cnt, rem, err = 0;
	__u32 *actions = NULL;
	struct nlattr *i;
	char *name;

	err = nla_parse_nested(table, NET_FLOW_TABLE_ATTR_MAX, nl, net_flow_table_policy);
	if (err) {
		fprintf(stderr, "Warning parse error flow attribs, abort parse\n");
		return err;
	}

	name = table[NET_FLOW_TABLE_ATTR_NAME] ? nla_get_string(table[NET_FLOW_TABLE_ATTR_NAME]) : none,
	uid = table[NET_FLOW_TABLE_ATTR_UID] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_UID]) : 0;

	src = table[NET_FLOW_TABLE_ATTR_SOURCE] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_SOURCE]) : 0;
	apply = table[NET_FLOW_TABLE_ATTR_APPLY] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_APPLY]) : 0;
	size = table[NET_FLOW_TABLE_ATTR_SIZE] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_SIZE]) : 0;

	if (table[NET_FLOW_TABLE_ATTR_MATCHES])
		flow_get_matches(fp, false, table[NET_FLOW_TABLE_ATTR_MATCHES], &matches);

	if (table[NET_FLOW_TABLE_ATTR_ACTIONS]) {
		rem = nla_len(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem))
			cnt++;

		actions = calloc(cnt + 1, sizeof (__u32));
		if (!actions)
			goto out;

		rem = nla_len(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
			actions[cnt] = nla_get_u32(i);
		}
	}

	t->name = strdup(name);
	if (!t->name)
		goto out;
	t->uid = uid;
	t->source = src;
	t->apply_action = apply;
	t->size = size;

	t->matches = matches;
	t->actions = actions; 

	tables[uid] = t;
	pp_table(fp, print, t);
	return 0;
out:
	free(matches);
	return -ENOMEM;
}

int flow_get_tables(FILE *fp, int print, struct nlattr *nl,
		      struct net_flow_tbl **t)
{
	struct net_flow_tbl *tables;
	struct nlattr *i;
	int err, rem, cnt = 0;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	tables = calloc(cnt + 1, sizeof(struct net_flow_tbl));
	if (!tables)
		return -ENOMEM;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		err = flow_get_table(fp, print, i, &tables[cnt]);
		if (err)
			goto out;
	}

	if (print) /* TBD: move this into printer */
		pfprintf(fp, print, "\n");

	if (t)
		*t = tables;

	return 0;
out:
	free(tables);
	return err;
}

int flow_get_flows(FILE *fp, int print, struct nlattr *attr, struct net_flow_flow **flows)
{
	struct net_flow_field_ref *matches = NULL;
	struct net_flow_action *actions = NULL;
	struct net_flow_flow  *f;
	struct nlattr *i;
	int err, rem, count = 0;;

	rem = nla_len(attr);
	for (i = nla_data(attr);  nla_ok(i, rem); i = nla_next(i, &rem)) 
		count++;

	f = calloc(count + 1, sizeof(struct net_flow_flow));
	if (!f)
		return -EMSGSIZE;
	
	rem = nla_len(attr);
	for (count = 0, i = nla_data(attr);
	     nla_ok(i, rem); i = nla_next(i, &rem), count++) {
		struct nlattr *flow[NET_FLOW_ATTR_MAX+1];

		err = nla_parse_nested(flow, NET_FLOW_ATTR_MAX, i, flow_table_flow_policy);
		if (err) {
			fprintf(stderr, "Warning: get_flow parse error skipping input.\n");
			continue;
		}

		if (flow[NET_FLOW_ATTR_TABLE])
			f[count].table_id = nla_get_u32(flow[NET_FLOW_ATTR_TABLE]);

		if (flow[NET_FLOW_ATTR_UID])
			f[count].uid = nla_get_u32(flow[NET_FLOW_ATTR_UID]);

		if (flow[NET_FLOW_ATTR_PRIORITY])
			f[count].priority = nla_get_u32(flow[NET_FLOW_ATTR_PRIORITY]);

		if (flow[NET_FLOW_ATTR_MATCHES]) {
			err = flow_get_matches(fp, false,
					       flow[NET_FLOW_ATTR_MATCHES], &matches);
			if (err) {
				fprintf(stderr, "Warning get_flow matches parse error skipping input.\n");
				continue;
			}
		}

		if (flow[NET_FLOW_ATTR_ACTIONS]) {
			err = flow_get_actions(fp, false, flow[NET_FLOW_ATTR_ACTIONS], &actions);
			if (err) {
				fprintf(stderr, "Warning get_flow actions parse error skipping input.\n");
				continue;
			}
		}
		
		f[count].matches = matches;
		f[count].actions = actions;
	}

	pp_flows(fp, print, f);
	if (flows)
		*flows = f;
	else
		free(f);
	return 0;
}

int FLOW_GET_flow_errors(struct nlattr *nla)
{
	return nla_get_u32(nla);
}

int flow_get_table_field(FILE *UNUSED(fp), int UNUSED(print), struct nlattr *nl, struct net_flow_hdr *hdr)
{
	struct nlattr *i;
	struct nlattr *field[NET_FLOW_FIELD_ATTR_MAX+1];
	int rem, err, count = 0;

	/* TBD this couting stuff is a bit clumsy */
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	hdr->fields = calloc(count + 1, sizeof(struct net_flow_hdr));

	count = 0;
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct net_flow_field *f = &hdr->fields[count];	

		err = nla_parse_nested(field, NET_FLOW_FIELD_ATTR_MAX, i, flow_get_field_policy);
		if (err) {
			fprintf(stderr, "Warning field parse error\n");
			return -EINVAL;
		}

		f->uid = field[NET_FLOW_FIELD_ATTR_UID] ?
			 nla_get_u32(field[NET_FLOW_FIELD_ATTR_UID]) : 0;
		f->name = strdup((field[NET_FLOW_FIELD_ATTR_NAME] ? 
			  nla_get_string(field[NET_FLOW_FIELD_ATTR_NAME]) : none));
		f->bitwidth = field[NET_FLOW_FIELD_ATTR_BITWIDTH] ?
			      nla_get_u32(field[NET_FLOW_FIELD_ATTR_BITWIDTH]) : 0;
		header_fields[hdr->uid][f->uid] = f;
		count++;
	}

	return count;
}

int flow_get_headers(FILE *fp, int print, struct nlattr *nl, struct net_flow_hdr **hdrs)
{
	struct net_flow_hdr *h;
	struct nlattr *i;
	int rem, count = 0;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	h = calloc(count + 1, sizeof(struct net_flow_hdr));

	rem = nla_len(nl);
	count = 0;
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *hdr[NET_FLOW_HEADER_ATTR_MAX+1];
		struct net_flow_hdr *header;
		int err;

		err = nla_parse_nested(hdr, NET_FLOW_HEADER_ATTR_MAX, i, flow_get_header_policy);
		if (err) {
			fprintf(stderr, "Warning header parse error. aborting.\n");
			return -EINVAL;
		}

		header = calloc(1, sizeof(struct net_flow_hdr));
		if (!header) {
			fprintf(stderr, "Warning OOM in header parser. aborting.\n");
			return -ENOMEM;
		}

		header->uid = hdr[NET_FLOW_HEADER_ATTR_UID] ?
				nla_get_u32(hdr[NET_FLOW_HEADER_ATTR_UID]) : 0;
		header->name =
			strdup(hdr[NET_FLOW_HEADER_ATTR_NAME] ?
				nla_get_string(hdr[NET_FLOW_HEADER_ATTR_NAME]) : empty);
		flow_get_table_field(fp, print, hdr[NET_FLOW_HEADER_ATTR_FIELDS], header);
		headers[header->uid] = header;
		pp_header(fp, print, header);
		h[count] = *header;
		count++;
	}

	if (hdrs)
		*hdrs = h;
	else
		free(h);

	return 0;
}



static int flow_get_jump(FILE *fp, int print, struct nlattr *nl, struct net_flow_field_ref *ref)
{
	flow_get_field(fp, print, nl, ref);
	pp_jump_table(fp, print, ref);
	return 0;
}

static int flow_get_jump_table(FILE *fp, int print, struct nlattr *nl, struct net_flow_field_ref **ref)
{
	struct net_flow_field_ref *jump;
	struct nlattr *i;
	int rem, j;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	jump = calloc(j + 1, sizeof(struct net_flow_field_ref));
	if (!jump)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); j++, i = nla_next(i, &rem))
		flow_get_jump(fp, print, i, &jump[j]);

	if (ref)
		*ref = jump;
	else
		free(jump);
	return 0;
}

static int flow_get_header_refs(struct nlattr *nl, __u32 **ref)
{
	__u32 *headers;
	int rem, j;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	headers = calloc(j + 1, sizeof(int));
	if (!headers)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++)
		headers[j] = nla_get_u32(i);

	if (ref)
		*ref = headers;
	else
		free(headers);
	return 0;
}

int flow_get_hdrs_graph(FILE *fp, int print, struct nlattr *nl, struct net_flow_hdr_node **ref)
{
	struct net_flow_hdr_node *nodes;
	int rem, err, j;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	nodes = calloc(j + 1, sizeof(struct net_flow_hdr_node));
	if (!nodes)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) {
		struct nlattr *node[NET_FLOW_HEADER_NODE_MAX+1];

		err = nla_parse_nested(node, NET_FLOW_HEADER_NODE_MAX, i, flow_get_hdr_node_policy);
		if (err) {
			fprintf(stderr, "Warning header graph node parse error. aborting.\n");
			return -EINVAL;
		}

		if (node[NET_FLOW_HEADER_NODE_NAME]) {
			char *name;

			name = nla_get_string(node[NET_FLOW_HEADER_NODE_NAME]);
			nodes[j].name = strdup(name);
			if (!nodes[j].name)
				return -EINVAL;
		}

		if (!node[NET_FLOW_HEADER_NODE_UID]) {
			fprintf(stderr, "Warning, missing header node uid\n");
			return -EINVAL;
		}

		nodes[j].uid = nla_get_u32(node[NET_FLOW_HEADER_NODE_UID]);

		if (!node[NET_FLOW_HEADER_NODE_JUMP] ||
		    !node[NET_FLOW_HEADER_NODE_HDRS]) {
			fprintf(stderr, "Warning, missing header node hdrs and jump table\n");
			continue;
		}

		err = flow_get_header_refs(node[NET_FLOW_HEADER_NODE_HDRS],
					   &nodes[j].hdrs);
		if (err) {
			fprintf(stderr, "Warning header refs parse error. aborting.\n");
			return -EINVAL;
		}

		err = flow_get_jump_table(fp, false,
					  node[NET_FLOW_HEADER_NODE_JUMP],
					  &nodes[j].jump);
		if (err) {
			fprintf(stderr, "Warning header graph jump parse error. aborting.\n");
			return -EINVAL;
		}

		graph_nodes[nodes[j].uid] = &nodes[j];
	}	
	if (print == PRINT_GRAPHVIZ)
		ppg_header_graph(stdout, nodes);
	else if (print)
		pp_header_graph(stdout, print, nodes);
	if (ref)
		*ref = nodes;
	return 0;
}

int flow_get_tbl_graph(FILE *fp, int print, struct nlattr *nl, struct net_flow_tbl_node **ref)
{
	struct net_flow_tbl_node *nodes;
	int rem, err, j;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	nodes = calloc(j + 1, sizeof(struct net_flow_tbl_node));
	if (!nodes)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) {
		struct net_flow_tbl_node *n = &nodes[j];
		struct nlattr *node[NET_FLOW_TABLE_GRAPH_NODE_MAX+1];

		err = nla_parse_nested(node, NET_FLOW_TABLE_GRAPH_NODE_MAX, i, flow_get_node_policy);
		if (err) {
			fprintf(stderr, "Warning table graph node parse error. aborting.\n");
			return -EINVAL;
		}

		if (!node[NET_FLOW_TABLE_GRAPH_NODE_UID]) {
			fprintf(stderr, "Warning, missing graph node uid\n");
			return -EINVAL;
		}

		n->uid = nla_get_u32(node[NET_FLOW_TABLE_GRAPH_NODE_UID]);

		if (node[NET_FLOW_TABLE_GRAPH_NODE_FLAGS])
			n->flags = nla_get_u32(node[NET_FLOW_TABLE_GRAPH_NODE_FLAGS]);

		if (!node[NET_FLOW_TABLE_GRAPH_NODE_JUMP]) {
			fprintf(stderr, "Warning, missing graph node jump table\n");
			continue;
		}

		err = flow_get_jump_table(fp, false, node[NET_FLOW_TABLE_GRAPH_NODE_JUMP], &n->jump);
		if (err) {
			fprintf(stderr, "Warning table graph jump parse error. aborting.\n");
			return -EINVAL;
		}
	}	
	if (print == PRINT_GRAPHVIZ)
		ppg_table_graph(fp, print, nodes);
	else if (print)
		pp_table_graph(fp, print, nodes);
	if (ref)
		*ref = nodes;
	else
		free(nodes);
	return 0;
}

static int flow_put_action_args(struct nl_msg *nlbuf, struct net_flow_action_arg *args)
{
	struct net_flow_action_arg *this;
	struct nlattr *arg;
	int i, err, cnt = 0;

	for (this = &args[0]; this->type; this++)
		cnt++;

	for (i = 0; i < cnt; i++) {
		arg = nla_nest_start(nlbuf, NET_FLOW_ACTION_ARG);
		if (!arg)
			return -ENOMEM;

		if (nla_put_u32(nlbuf,
				NET_FLOW_ACTION_ARG_TYPE,
				args[i].type)) {
			nla_nest_cancel(nlbuf, arg);
			return -EMSGSIZE;
		}
		
		switch (args[i].type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			err = nla_put_u8(nlbuf,
					 NET_FLOW_ACTION_ARG_VALUE,
					 args[i].v.value_u8);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			err = nla_put_u16(nlbuf,
					  NET_FLOW_ACTION_ARG_VALUE,
					  args[i].v.value_u16);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			err = nla_put_u32(nlbuf,
					  NET_FLOW_ACTION_ARG_VALUE,
					  args[i].v.value_u32);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			err = nla_put_u64(nlbuf,
					  NET_FLOW_ACTION_ARG_VALUE,
					  args[i].v.value_u64);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_NULL:
		default:
			err = 0;
			break;
		}

		if (err) {
			nla_nest_cancel(nlbuf, arg);
			return -EMSGSIZE;
		}

		nla_nest_end(nlbuf, arg);
	}

	return 0;
}

int flow_put_action(struct nl_msg *nlbuf, struct net_flow_action *ref)
{
	struct nlattr *nest;
	int err;
	struct nlattr *action;

	action = nla_nest_start(nlbuf, NET_FLOW_ACTION);
	if (!action)
		return -EMSGSIZE;

	if (ref->name && nla_put_string(nlbuf, NET_FLOW_ACTION_ATTR_NAME, ref->name))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_FLOW_ACTION_ATTR_UID, ref->uid))
		return -EMSGSIZE;

	if (ref->args) {
		nest = nla_nest_start(nlbuf, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!nest)
			return -EMSGSIZE;

		err = flow_put_action_args(nlbuf, ref->args);
		if (err)
			return err;
		nla_nest_end(nlbuf, nest);
	}

	nla_nest_end(nlbuf, action);
	return 0;
}

int flow_put_actions(struct nl_msg *nlbuf, struct net_flow_action *ref)
{
	struct nlattr *actions;
	int i, err;

	actions = nla_nest_start(nlbuf, NET_FLOW_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (i = 0; ref[i].uid; i++) {
		err = flow_put_action(nlbuf, &ref[i]);
		if (err)
			return err;
	}
	nla_nest_end(nlbuf, actions);
	return 0;
}

static int flow_put_fields(struct nl_msg *nlbuf, struct net_flow_hdr *ref)
{
	struct nlattr *field;
	int count = ref->field_sz;
	struct net_flow_field *f;

	for (f = ref->fields; count; count--, f++) {
		field = nla_nest_start(nlbuf, NET_FLOW_FIELD);
		if (!field)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, NET_FLOW_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(nlbuf, NET_FLOW_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(nlbuf, NET_FLOW_FIELD_ATTR_BITWIDTH, f->bitwidth))
			return -EMSGSIZE;

		nla_nest_end(nlbuf, field);
	}

	return 0;
}

int flow_put_headers(struct nl_msg *nlbuf, struct net_flow_hdr **ref)
{
	struct nlattr *nest, *hdr, *fields;
	struct net_flow_hdr *this;
	int err, i;

	nest = nla_nest_start(nlbuf, NET_FLOW_HEADERS);
	if (!nest)
		return -EMSGSIZE;
		
	for (i = 0, this = ref[0]; this->uid; i++, this = ref[i]) {
		hdr = nla_nest_start(nlbuf, NET_FLOW_HEADER);
		if (!hdr)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, NET_FLOW_HEADER_ATTR_NAME, this->name) ||
		    nla_put_u32(nlbuf, NET_FLOW_HEADER_ATTR_UID, this->uid))
			return -EMSGSIZE;

		fields = nla_nest_start(nlbuf, NET_FLOW_HEADER_ATTR_FIELDS);
		if (!fields)
			return -EMSGSIZE;

		err = flow_put_fields(nlbuf, this);
		if (err)
			return err;

		nla_nest_end(nlbuf, fields);
		nla_nest_end(nlbuf, hdr);
	}
	nla_nest_end(nlbuf, nest);

	return 0;
}

int flow_put_field_ref(struct nl_msg *nlbuf, struct net_flow_field_ref *ref)
{
	if (nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_INSTANCE, ref->instance) ||
	    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_HEADER, ref->header) ||
	    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_FIELD, ref->field) ||
	    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_MASK_TYPE, ref->mask_type) ||
	    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_TYPE, ref->type))
		return -EMSGSIZE;

	if (ref->next_node &&
	    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_NEXT_NODE, ref->next_node))
		return -EMSGSIZE;

	if (!ref->type)
		return 0;

	switch (ref->type) {
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U8:
		if (nla_put_u8(nlbuf, NET_FLOW_FIELD_REF_VALUE, ref->v.u8.value_u8) ||
		    nla_put_u8(nlbuf, NET_FLOW_FIELD_REF_MASK, ref->v.u8.mask_u8))
			return -EMSGSIZE;
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U16:
		if (nla_put_u16(nlbuf, NET_FLOW_FIELD_REF_VALUE, ref->v.u16.value_u16) ||
		    nla_put_u16(nlbuf, NET_FLOW_FIELD_REF_MASK, ref->v.u16.mask_u16))
			return -EMSGSIZE;
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U32:
		if (nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_VALUE, ref->v.u32.value_u32) ||
		    nla_put_u32(nlbuf, NET_FLOW_FIELD_REF_MASK, ref->v.u32.mask_u32))
			return -EMSGSIZE;
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U64:
		if (nla_put_u64(nlbuf, NET_FLOW_FIELD_REF_VALUE, ref->v.u64.value_u64) ||
		    nla_put_u64(nlbuf, NET_FLOW_FIELD_REF_MASK, ref->v.u64.mask_u64))
			return -EMSGSIZE;
		break;
	default:
		break;
	}

	return 0;
}

int flow_put_matches(struct nl_msg *nlbuf, struct net_flow_field_ref *ref, int type)
{
	struct nlattr *matches, *field;
	int i;

	matches = nla_nest_start(nlbuf, type);
	if (!matches)
		return -EMSGSIZE;

	for (i = 0; ref[i].header; i++) {
		field = nla_nest_start(nlbuf, NET_FLOW_FIELD_REF);
		if (flow_put_field_ref(nlbuf, &ref[i]))
			return -EMSGSIZE;
		nla_nest_end(nlbuf, field);
	}
	nla_nest_end(nlbuf, matches);
	return 0;
}

int flow_put_flow_error(struct nl_msg *nlbuf, int err)
{
	return nla_put_u32(nlbuf, NET_FLOW_FLOWS_ERROR, err);
}

int flow_put_flow(struct nl_msg *nlbuf, struct net_flow_flow *ref)
{
	int err;
	struct nlattr *flow, *actions;

	flow = nla_nest_start(nlbuf, NET_FLOW_FLOW);
	if (!flow)
		return -EMSGSIZE;

	nla_put_u32(nlbuf, NET_FLOW_ATTR_TABLE, ref->table_id);
	nla_put_u32(nlbuf, NET_FLOW_ATTR_UID, ref->uid);
	nla_put_u32(nlbuf, NET_FLOW_ATTR_PRIORITY, ref->priority);

	if (ref->matches) {
		err = flow_put_matches(nlbuf, ref->matches, NET_FLOW_ATTR_MATCHES);
		if (err)
			return err;
	}

	if (ref->actions) {
		int i;

		actions = nla_nest_start(nlbuf, NET_FLOW_ATTR_ACTIONS);
		if (!actions)
			return -EMSGSIZE;
		
		for (i = 0; ref->actions[i].uid; i++) {
			err = flow_put_action(nlbuf, &ref->actions[i]);
			if (err)
				return err;
		}
		nla_nest_end(nlbuf, actions);
	}

	nla_nest_end(nlbuf, flow);
	return 0;
}

int flow_put_flows(struct nl_msg *nlbuf, struct net_flow_flow *ref)
{
	struct nlattr *flows;
	int err, i = 0;

	flows = nla_nest_start(nlbuf, NET_FLOW_FLOWS);
	if (!flows)
		return -EMSGSIZE;
	for (i = 0; ref[i].uid; i++) {
		err = flow_put_flow(nlbuf, &ref[i]);
		if (err) {
			fprintf(stderr, "Warning put flow error aborting\n");
			return err;
		}
	}

	nla_nest_end(nlbuf, flows);

	return 0;
}


int flow_put_table(struct nl_msg *nlbuf, struct net_flow_tbl *ref)
{
	struct nlattr *actions;
	__u32 *aref;
	int err;

	if (nla_put_string(nlbuf, NET_FLOW_TABLE_ATTR_NAME, ref->name) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_SOURCE, ref->source) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_APPLY, ref->apply_action) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_SIZE, ref->size))
		return -EMSGSIZE;

	if (ref->matches) {
		err = flow_put_matches(nlbuf, ref->matches, NET_FLOW_TABLE_ATTR_MATCHES);
		if (err)
			return err;
	}

	if (ref->actions) {
		actions = nla_nest_start(nlbuf, NET_FLOW_TABLE_ATTR_ACTIONS);
		if (!actions)
			return -EMSGSIZE;

		for (aref = ref->actions; *aref; aref++) {
			if (nla_put_u32(nlbuf, NET_FLOW_ACTION_ATTR_UID, *aref))
				return -EMSGSIZE;
		}
		nla_nest_end(nlbuf, actions);
	}
	return 0;
}

int flow_put_tables(struct nl_msg *nlbuf, struct net_flow_tbl *ref)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(nlbuf, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; ref[i].uid > 0; i++) {
		t = nla_nest_start(nlbuf, NET_FLOW_TABLE);
		err = flow_put_table(nlbuf, &ref[i]);
		if (err)
			return err;
		nla_nest_end(nlbuf, t);
	}
	nla_nest_end(nlbuf, nest);
	return 0;
}

int flow_put_table_graph(struct nl_msg *nlbuf, struct net_flow_tbl_node **ref)
{
	struct nlattr *nodes, *node, *jump;
	int i = 0, j = 0;

	nodes = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; ref[i]->uid; i++) {
		node = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH_NODE);
		if (!node)
			return -EMSGSIZE;

		if (nla_put_u32(nlbuf, NET_FLOW_TABLE_GRAPH_NODE_UID, ref[i]->uid) ||
		    nla_put_u32(nlbuf, NET_FLOW_TABLE_GRAPH_NODE_FLAGS, ref[i]->flags))
			return -EMSGSIZE;

		jump = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH_NODE_JUMP);
		if (!jump)
			return -EMSGSIZE;

		for (j = 0; ref[i]->jump[j].next_node; j++)
			nla_put(nlbuf, NET_FLOW_JUMP_TABLE_ENTRY, sizeof(struct net_flow_field_ref), &ref[i]->jump[j]);

		nla_nest_end(nlbuf, jump);
		nla_nest_end(nlbuf, node);
	}

	nla_nest_end(nlbuf, nodes);
	return 0;
}

static int net_flow_put_header_node(struct nl_msg *nlbuf,
				    struct net_flow_hdr_node *node)
{
	struct nlattr *hdrs, *jumps;
	int i, err;

	if (nla_put_string(nlbuf, NET_FLOW_HEADER_NODE_NAME, node->name) ||
	    nla_put_u32(nlbuf, NET_FLOW_HEADER_NODE_UID, node->uid))
		return -EMSGSIZE;

	/* Insert the set of headers that get extracted at this node */
	hdrs = nla_nest_start(nlbuf, NET_FLOW_HEADER_NODE_HDRS);
	if (!hdrs)
		return -EMSGSIZE;
	for (i = 0; node->hdrs[i]; i++) {
		if (nla_put_u32(nlbuf, NET_FLOW_HEADER_NODE_HDRS_VALUE,
				node->hdrs[i])) {
			nla_nest_cancel(nlbuf, hdrs);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(nlbuf, hdrs);

	/* Then give the jump table to find next header node in graph */
	jumps = nla_nest_start(nlbuf, NET_FLOW_HEADER_NODE_JUMP);
	if (!jumps)
		return -EMSGSIZE;	

	for (i = 0; node->jump[i].next_node; i++) {
		err = nla_put(nlbuf, NET_FLOW_JUMP_TABLE_ENTRY,
			      sizeof(struct net_flow_field_ref),
			      &node->jump[i]);
		if (err) {
			nla_nest_cancel(nlbuf, jumps);	
			return -EMSGSIZE;
		}
	}
	nla_nest_end(nlbuf, jumps);

	return 0;
}

int flow_put_header_graph(struct nl_msg *nlbuf,
			  struct net_flow_hdr_node **g)
{
	struct nlattr *nodes, *node;
	int err, i;

	nodes = nla_nest_start(nlbuf, NET_FLOW_HEADER_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; g[i]->uid; i++) {
		node = nla_nest_start(nlbuf, NET_FLOW_HEADER_GRAPH_NODE);
		if (!node)
			return -EMSGSIZE;

		err = net_flow_put_header_node(nlbuf, g[i]);
		if (err)
			return -EMSGSIZE;

		nla_nest_end(nlbuf, node);
	}

	nla_nest_end(nlbuf, nodes);
	return 0;
}
