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

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>

#include <linux/if_flow.h>
#include <linux/if_ether.h>

#include <linux/if_flow.h>

#define MAX_TABLES 100
#define MAX_HDRS 100
#define MAX_FIELDS 100
#define MAX_ACTIONS 100

struct net_flow_table *tables[MAX_TABLES];
struct net_flow_header *headers[MAX_HDRS];	
struct net_flow_field *header_fields[MAX_HDRS][MAX_FIELDS];
struct net_flow_action *actions[MAX_ACTIONS];

char *headers_names(int uid)
{
	return headers[uid] ? headers[uid]->name : "<none>";
}

struct net_flow_header *get_headers(int uid)
{
	return headers[uid];
}

static char *fields_names(int hid, int fid)
{
	return header_fields[hid][fid] ? header_fields[hid][fid]->name : "<none>";
}

struct net_flow_field *get_fields(int huid, int uid)
{
	return header_fields[huid][uid];
}

char *table_names(int uid)
{
	return tables[uid] ? tables[uid]->name : "<none>";
}

struct net_flow_table *get_tables(int uid)
{
	return tables[uid];
}

char *action_names(int uid)
{
	return actions[uid]->name;
}

struct net_flow_action *get_actions(int uid)
{
	return actions[uid];
}

int find_action(char *name)
{
	int i;

	for (i = 0; i < MAX_ACTIONS; i++) {
		if (actions[i] && strcmp(action_names(i), name) == 0) {
			return i;
		}
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

	return -EINVAL;
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

static void pfprintf(FILE *fp, bool p, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (p)
		vfprintf(fp, format, args);

	va_end(args);
}

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

struct nla_policy net_flow_table_policy[NET_FLOW_TABLE_ATTR_MAX + 1] = {
	[NET_FLOW_TABLE_ATTR_NAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ-1 },
	[NET_FLOW_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_ATTR_FLOWS]	= { .type = NLA_NESTED },
};

struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING, },
	[NET_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

static struct nla_policy flow_get_field_policy[NET_FLOW_FIELD_ATTR_MAX+1] = {
	[NET_FLOW_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_FLOW_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
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
	[NET_FLOW_TABLE_GRAPH_NODE_JUMP]   = { .type = NLA_NESTED,},
};

static struct nla_policy flow_get_jump_policy[NET_FLOW_JUMP_TABLE_MAX+1] = {
	[NET_FLOW_JUMP_TABLE_NODE]	= { .type = NLA_U32, },
	[NET_FLOW_JUMP_TABLE_FIELD_REF] = { .minlen = sizeof(struct net_flow_field_ref)},
};

static void pp_field_ref(FILE *fp, bool p, struct net_flow_field_ref *ref, int last)
{
	char b1[16] = ""; /* arbitrary string field for mac */
	int hi = ref->header;
	int fi = ref->field;

	if (!ref->type) {
		if (!ref->header && !ref->field)
			pfprintf(stdout, p, " <any>");
		else if (last == hi)
			pfprintf(stdout, p, " %s", fields_names(hi, fi));
		else if (last < 0)
			pfprintf(stdout, p, "\t field: %s [%s", headers_names(hi), fields_names(hi, fi));
		else
			pfprintf(stdout, p, "]\n\t field: %s [%s", headers_names(hi), fields_names(hi, fi));
	}

	switch (ref->type) {
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U8:
		pfprintf(stdout, p, "\t %s.%s = %02x (%02x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u8, ref->mask_u8);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U16:
		pfprintf(stdout, p, "\t %s.%s = %04x (%04x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u16, ref->mask_u16);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U32:
		pfprintf(stdout, p, "\t %s.%s = %08x (%08x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u32, ref->mask_u32);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U64:
		pfprintf(stdout, p, "\t %s.%s = %s (%016x)\n",
			 headers_names(hi), fields_names(hi, fi),
			 ll_addr_n2a((unsigned char *)&ref->value_u64, ETH_ALEN, 0, b1, sizeof(b1)),
			 ref->value_u64, ref->mask_u64);
		break;
	default:
		break;
	}
}

void pp_fields(FILE *fp, bool print, struct net_flow_field_ref *ref)
{
	bool brace = false;
	int i, last;

	for (i = 0; ref[i].header; i++) {
		pp_field_ref(fp, print, &ref[i], last);
		last = ref[i].header;
		brace = true;
	}

	if (brace)
		pfprintf(fp, print, "]\n");
}

const char *flow_table_arg_type_str[__NET_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

void pp_action(FILE *fp, bool p, struct net_flow_action *act)
{
	struct net_flow_action_arg *arg;
	int i;

	pfprintf(fp, p, "\t   %i: %s ( ", act->uid, act->name);

	if (!act->args)
		goto out;

	for (i = 0; act->args[i].type; i++) {
		arg = &act->args[i];

		pfprintf(fp, p, "%s %s ",
			 flow_table_arg_type_str[arg->type],
			 arg->name ? arg->name : "");

		switch (arg->type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			pfprintf(fp, p, "%02x ", arg->value_u8);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			pfprintf(fp, p, "%i ", arg->value_u16);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			pfprintf(fp, p, "%i ", arg->value_u32);
		break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			pfprintf(fp, p, "%llu ", arg->value_u64);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_NULL:
		default:
			break;
		}
	}
out:
	pfprintf(fp, p, " )\n");
}

void pp_actions(FILE *fp, bool p, struct net_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		pp_action(fp, p, &actions[i]);
}

void pp_table(FILE *fp, int p, struct net_flow_table *table)
{
	int i, last = -1;
	bool brace = false;

	pfprintf(fp, p, "\n%s:%i src %i size %i\n",
		 table->name, table->uid, table->source, table->size);

	pfprintf(fp, p, "  matches:\n");
	if (table->matches)
		pp_fields(fp, p, table->matches);

	pfprintf(fp, p, "  actions:\n");
	if (table->actions)
	
	for (i = 0; table->actions[i]; i++) {
		struct net_flow_action *act = actions[table->actions[i]];

		if (act->uid)
			pp_action(stdout, p, act);
	}

}

void pp_header(FILE *fp, bool p, struct net_flow_header *header)
{
	struct net_flow_field *f;
	int i = 0;

	pfprintf(fp, p, "  %s {\n\t", header->name);

	for (f = &header->fields[i];
	     f->uid;
	     f = &header->fields[++i]) {
		if (f->bitwidth >= 0)
			pfprintf(fp, p, " %s:%i ", f->name, f->bitwidth);
		else
			pfprintf(fp, p, " %s:* ", f->name);

		if (i && !(i % 5))
			pfprintf(fp, p, " \n\t");
	}

	if (i % 5)
		pfprintf(fp, p, "\n\t");
	pfprintf(fp, p, " }\n");
}

void pp_flow(FILE *fp, bool print, struct net_flow_flow *flow)
{
	pfprintf(fp, true, "table : %i  ", flow->table_id);
	pfprintf(fp, true, "uid : %i  ", flow->uid);
	pfprintf(fp, true, "prio : %i\n", flow->priority);

	if (flow->matches)
		pp_fields(fp, print, flow->matches);	
	if (flow->actions)
		pp_actions(fp, print, flow->actions);	
}


void pp_flows(FILE *fp, bool print, struct net_flow_flow *flows)
{
	int i;

	if (!print)
		return;

	for (i = 0; flows[i].uid; i++)
		pp_flow(fp, print, &flows[i]);
}

static void pp_jump_table(FILE *fp, bool print, struct net_flow_jump_table *jump)
{
	if (!print)
		return;

	pp_field_ref(fp, print, &jump->field, 0);
	if (jump->node < 0)
		pfprintf(fp, print, " -> terminal\n");
	else
		pfprintf(fp, print, " -> %s\n", table_names(jump->node));

}

static int flow_compar_graph_nodes(const void *a, const void *b)
{
	const struct net_flow_table_graph_node *g_a, *g_b;
	const struct net_flow_table *t_a, *t_b;

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
}

void pp_table_graph(FILE *fp, bool print, struct net_flow_table_graph_node *nodes)
{
	struct net_flow_table_graph_node *sorted;
	int i, j, src = -1;

	if (!print)
		return;

	for (i = 0; nodes[i].uid; i++)
		;

	qsort(nodes, i, sizeof(*nodes), flow_compar_graph_nodes);

	for (i = 0; nodes[i].uid; i++) {
		struct net_flow_table *t = get_tables(nodes[i].uid);

		if (src != t->source) {
			src = t->source;
			pfprintf(fp, print, "source: %i\n", src);
		}

		pfprintf(fp, print, "\t%s: ", table_names(nodes[i].uid));
		for (j = 0; nodes[i].jump[j].node; ++j)
			pp_jump_table(fp, print, &nodes[i].jump[j]);
	}
}

int flow_get_field(FILE *fp, bool p, struct nlattr *nl, struct net_flow_field_ref *ref)
{
	*ref = *(struct net_flow_field_ref*) nla_data(nl);
	pp_field_ref(fp, p, ref, -1);
	return 0;
}

int flow_get_action(FILE *fp, bool p, struct nlattr *nl, struct net_flow_action **a)
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
		strncpy(act->name, name, IFNAMSIZ - 1);
	} else if (act && act->uid) {
		name = act->name;
	} else {
		name = "<none>";
	}

	if (!action[NET_FLOW_ACTION_ATTR_SIGNATURE])
		goto done;

	signature = action[NET_FLOW_ACTION_ATTR_SIGNATURE];
	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem))
		count++;
	
	if (act->args) /* replace args with new values */
		free(act->args);

	if (count > 0) {
		act->args = calloc(count + 1, sizeof(struct net_flow_action_arg));
		if (!act->args)
			return -ENOMEM;
	}

	count = 0;

	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem)) {
		/* TBD verify attr type */
		act->args[count] = *(struct net_flow_action_arg *)nla_data(l);
		count++;
	}

done:
	actions[uid] = act;
	if (a)
		*a = act;
	pp_action(fp, p, act);
	return 0;
}

int flow_get_matches(FILE *fp, bool print, struct nlattr *nl, struct net_flow_field_ref **ref)
{
	struct net_flow_field_ref *r;
	struct nlattr *i;
	int err, rem, cnt;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	r = calloc(cnt + 1, sizeof(struct net_flow_field_ref));
	if (!r)
		return -ENOMEM;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		err = flow_get_field(fp, print, i, &r[cnt]);
		if (err)
			goto out;
	}


	*ref = r;
	return 0;
out:
	free(r);
	return err;
}

int flow_get_actions(FILE *fp, bool print, struct nlattr *nl, struct net_flow_action **actions)
{
	struct net_flow_action **acts;
	int err, rem, j = 0;
	struct nlattr *i;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) 
		j++;

	acts = calloc(j + 1, sizeof(struct net_flow_action *));
	if (!acts)
		return -ENOMEM; 

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) 
		flow_get_action(fp, print, i, &acts[j]);

	if (actions)
		actions = &acts[0];
	else
		free(acts);

	return 0;
}


int flow_get_table(FILE *fp, bool print, struct nlattr *nl,
		   struct net_flow_table *t)
{
	struct nlattr *table[NET_FLOW_TABLE_ATTR_MAX+1];
	struct nlattr *i;
	char *name;
	int uid, src, size, cnt, rem, err = 0;
	struct net_flow_field_ref *matches;
	net_flow_action_ref *actions;

	err = nla_parse_nested(table, NET_FLOW_TABLE_ATTR_MAX, nl, net_flow_table_policy);
	if (err) {
		fprintf(stderr, "Warning parse error flow attribs, abort parse\n");
		return err;
	}

	name = table[NET_FLOW_TABLE_ATTR_NAME] ? nla_get_string(table[NET_FLOW_TABLE_ATTR_NAME]) : "<none>",
	uid = table[NET_FLOW_TABLE_ATTR_UID] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_UID]) : 0;

	src = table[NET_FLOW_TABLE_ATTR_SOURCE] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_SOURCE]) : 0,
	size = table[NET_FLOW_TABLE_ATTR_SIZE] ? nla_get_u32(table[NET_FLOW_TABLE_ATTR_SIZE]) : 0;

	if (table[NET_FLOW_TABLE_ATTR_MATCHES])
		flow_get_matches(fp, print, table[NET_FLOW_TABLE_ATTR_MATCHES], &matches);

	if (table[NET_FLOW_TABLE_ATTR_ACTIONS]) {
		rem = nla_len(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem))
			cnt++;

		actions = calloc(cnt + 1, sizeof (struct net_flow_field_ref));
		if (!actions)
			goto out;

		rem = nla_len(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_FLOW_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
			actions[cnt] = nla_get_u32(i);
		}
	}

	strncpy(t->name, name, IFNAMSIZ - 1);
	t->uid = uid;
	t->source = src;
	t->size = size;

	t->matches = matches;
	t->actions = actions; 
	t->flows = NULL;

	tables[uid] = t;
	pp_table(fp, print, t);
	return 0;
out:
	free(matches);
	return -ENOMEM;
}

int flow_get_tables(FILE *fp, bool print, struct nlattr *nl,
		      struct net_flow_table **t)
{
	struct net_flow_table *tables;
	struct nlattr *i;
	int err, rem, cnt;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	tables = calloc(cnt, sizeof(struct net_flow_table));
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

int flow_get_flows(FILE *fp, bool print, struct nlattr *attr, struct net_flow_flow **flows)
{
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
	struct net_flow_flow  *f;
	struct nlattr *i;
	int err, rem, count = 0;;

	rem = nla_len(attr);
	for (i = nla_data(attr);  nla_ok(i, rem); i = nla_next(i, &rem)) 
		count++;

	f = calloc(count + 1, sizeof(struct net_flow_flow));

	
	rem = nla_len(attr);
	for (count = 0, i = nla_data(attr);
	     nla_ok(i, rem); i = nla_next(i, &rem), count++) {
		struct nlattr *flow[NET_FLOW_ATTR_MAX+1];

		err = nla_parse_nested(flow, NET_FLOW_ATTR_MAX, i, flow_table_flow_policy);

		if (flow[NET_FLOW_ATTR_TABLE])
			f[count].table_id = nla_get_u32(flow[NET_FLOW_ATTR_TABLE]);

		if (flow[NET_FLOW_ATTR_UID])
			f[count].uid = nla_get_u32(flow[NET_FLOW_ATTR_UID]);

		if (flow[NET_FLOW_ATTR_PRIORITY])
			f[count].priority = nla_get_u32(flow[NET_FLOW_ATTR_PRIORITY]);

		if (flow[NET_FLOW_ATTR_MATCHES])
			err = flow_get_matches(false, false,
					    flow[NET_FLOW_ATTR_MATCHES], &matches);

		if (flow[NET_FLOW_ATTR_ACTIONS])
			flow_get_actions(fp, print, flow[NET_FLOW_ATTR_ACTIONS], &actions);
		
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

int flow_get_table_field(FILE *fp, bool p, struct nlattr *nl, struct net_flow_header *hdr)
{
	struct nlattr *i;
	struct nlattr *field[NET_FLOW_FIELD_ATTR_MAX+1];
	int rem, err, count = 0;

	/* TBD this couting stuff is a bit clumsy */
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	hdr->fields = calloc(count + 1, sizeof(struct net_flow_header));

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
		strncpy(f->name, (field[NET_FLOW_FIELD_ATTR_NAME] ? 
			  nla_get_string(field[NET_FLOW_FIELD_ATTR_NAME]) : "<none>"), IFNAMSIZ - 1);
		f->bitwidth = field[NET_FLOW_FIELD_ATTR_BITWIDTH] ?
			      nla_get_u32(field[NET_FLOW_FIELD_ATTR_BITWIDTH]) : 0;
		header_fields[hdr->uid][f->uid] = f;
		count++;
	}

	return count;
}

int flow_get_headers(FILE *fp, bool p, struct nlattr *nl)
{
	struct nlattr *i;
	int rem;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *hdr[NET_FLOW_HEADER_ATTR_MAX+1];
		struct net_flow_header *header;
		struct nlattr *fields, *j;
		int uid, err;

		err = nla_parse_nested(hdr, NET_FLOW_HEADER_ATTR_MAX, i, flow_get_header_policy);
		if (err) {
			fprintf(stderr, "Warning header parse error. aborting.\n");
			return -EINVAL;
		}

		header = calloc(1, sizeof(struct net_flow_header));
		if (!header) {
			fprintf(stderr, "Warning OOM in header parser. aborting.\n");
			return -ENOMEM;
		}

		header->uid = hdr[NET_FLOW_HEADER_ATTR_UID] ?
				nla_get_u32(hdr[NET_FLOW_HEADER_ATTR_UID]) : 0;
		strncpy(header->name,
			strdup(hdr[NET_FLOW_HEADER_ATTR_NAME] ?
				nla_get_string(hdr[NET_FLOW_HEADER_ATTR_NAME]) : ""), IFNAMSIZ - 1);

		flow_get_table_field(fp, p, hdr[NET_FLOW_HEADER_ATTR_FIELDS], header);
		headers[header->uid] = header;
		pp_header(fp, p, header);
	}
	return 0;
}

static int flow_get_jump_table(FILE *fp, bool p, struct nlattr *nl, struct net_flow_jump_table **ref)
{
	struct net_flow_jump_table *jump;
	struct nlattr *i;
	int rem, err, j;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	jump = calloc(j + 1, sizeof(struct net_flow_jump_table));
	if (!jump)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); j++, i = nla_next(i, &rem)) {
		struct nlattr *jtb[NET_FLOW_JUMP_TABLE_MAX];
		struct nlattr *nla = i;
		int node;

		err = nla_parse_nested(jtb, NET_FLOW_JUMP_TABLE_MAX, nla, flow_get_jump_policy);
		if (err) {
			fprintf(stderr, "Warning parsing jump tabled failed\n");
			continue;
		}

		if (!jtb[NET_FLOW_JUMP_TABLE_NODE]) {
			fprintf(stderr, "Warning no jump table node!\n");
			continue;
		}

		if (!jtb[NET_FLOW_JUMP_TABLE_FIELD_REF]) {
			fprintf(stderr, "Warning no jump table field!\n");
			continue;
		}

		jump[j].node = nla_get_u32(jtb[NET_FLOW_JUMP_TABLE_NODE]);
		flow_get_field(stdout, p, jtb[NET_FLOW_JUMP_TABLE_FIELD_REF], &jump[j].field);
	}

	if (ref)
		*ref = jump;
	else
		free(jump);
	return 0;
}

int flow_get_tbl_graph(FILE *fp, bool p, struct nlattr *nl, struct net_flow_table_graph_node **ref)
{
	struct net_flow_table_graph_node *nodes;
	int rem, err, uid, j;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	nodes = calloc(j + 1, sizeof(struct net_flow_parser_node));
	if (!nodes)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) {
		struct net_flow_table_graph_node *n = &nodes[j];
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
	pp_table_graph(stdout, p, nodes);
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

	for (this = &args[0]; strlen(this->name) > 0; this++)
		cnt++;

	for (i = 0; i < cnt; i++) {
		err = nla_put(nlbuf, NET_FLOW_ACTION_ARG, sizeof(args[i]), &args[i]);
		if (err)
			return -EMSGSIZE;
	}

	return 0;
}

int flow_put_action(struct nl_msg *nlbuf, struct net_flow_action *ref)
{
	struct net_flow_action_arg *this;
	struct nlattr *nest;
	int err;

	if (nla_put_string(nlbuf, NET_FLOW_ACTION_ATTR_NAME, ref->name) ||
	    nla_put_u32(nlbuf, NET_FLOW_ACTION_ATTR_UID, ref->uid))
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

	return 0;
}

int flow_put_actions(struct nl_msg *nlbuf, struct net_flow_actions *ref)
{
	struct net_flow_action **a;
	struct net_flow_action *this;
	struct nlattr *actions;
	int err;

	actions = nla_nest_start(nlbuf, NET_FLOW_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (a = ref->actions, this = *a; strlen(this->name) > 0; a++, this = *a) {
		struct nlattr *action = nla_nest_start(nlbuf, NET_FLOW_ACTION);

		if (!action)
			return -EMSGSIZE;

		err = flow_put_action(nlbuf, this);
		if (err)
			return -EMSGSIZE;
		nla_nest_end(nlbuf, action);
	}
	nla_nest_end(nlbuf, actions);

	return 0;
}

static int flow_put_fields(struct nl_msg *nlbuf, struct net_flow_header *ref)
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

int flow_put_headers(struct nl_msg *nlbuf, struct net_flow_headers *ref)
{
	struct nlattr *nest, *hdr, *fields;
	struct net_flow_header *this, **h;
	int err;

	nest = nla_nest_start(nlbuf, NET_FLOW_HEADERS);
	if (!nest)
		return -EMSGSIZE;
		
	for (h = ref->net_flow_headers, this = *h; strlen(this->name) > 0; h++, this = *h) {
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

int flow_put_flows(struct nl_msg *nlbuf, struct net_flow_flow *ref)
{
	struct nlattr *flows, *matches, *field;
	struct nlattr *actions = NULL;
	int err, j, i = 0;

	flows = nla_nest_start(nlbuf, NET_FLOW_FLOW);
	if (!flows)
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_FLOW_ATTR_TABLE, ref->table_id) ||
	    nla_put_u32(nlbuf, NET_FLOW_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, NET_FLOW_ATTR_PRIORITY, ref->priority))
		return -EMSGSIZE;

#if 0
	matches = nla_nest_start(nlbuf, NET_FLOW_FLOW_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (j = 0; j < mcnt; j++) {
		struct net_flow_field_ref *f = &ref->matches[j];

		if (!f->header)
			continue;

		field = nla_nest_start(nlbuf, NET_FLOW_FIELD_REF);
		if (!field || flow_put_field_ref(nlbuf, f))
			return -EMSGSIZE;
		nla_nest_end(nlbuf, field);
	}
	nla_nest_end(nlbuf, matches);

	actions = nla_nest_start(nlbuf, NET_FLOW_FLOW_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (i = 0; i < acnt; i++) {
		err = flow_put_action(nlbuf, &ref->actions[i], args);
		if (err)
			return -EMSGSIZE;
	}

	nla_nest_end(nlbuf, actions);
#endif
	nla_nest_end(nlbuf, flows);
	return 0;
}

int flow_put_field_ref(struct nl_msg *nlbuf, struct net_flow_field_ref *ref)
{
	return nla_put(nlbuf, NET_FLOW_FIELD_REF, sizeof(*ref), ref);
}

int flow_put_table(struct nl_msg *nlbuf, struct net_flow_table *ref)
{
	struct nlattr *matches, *flow, *actions;
	struct net_flow_field_ref *m;
	net_flow_action_ref *aref;
	int err;

	flow = NULL; /* must null to get unwind correct */

	if (nla_put_string(nlbuf, NET_FLOW_TABLE_ATTR_NAME, ref->name) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_SOURCE, ref->source) ||
	    nla_put_u32(nlbuf, NET_FLOW_TABLE_ATTR_SIZE, ref->size))
		return -EMSGSIZE;

	matches = nla_nest_start(nlbuf, NET_FLOW_TABLE_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (m = ref->matches; m->header || m->field; m++) {
		err = flow_put_field_ref(nlbuf, m);
		if (err)
			return -EMSGSIZE;
	}
	nla_nest_end(nlbuf, matches);

	actions = nla_nest_start(nlbuf, NET_FLOW_TABLE_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (aref = ref->actions; *aref; aref++) {
		if (nla_put_u32(nlbuf, NET_FLOW_ACTION_ATTR_UID, *aref))
			return -EMSGSIZE;
	}
	nla_nest_end(nlbuf, actions);
	return 0;
}

int flow_put_tables(struct nl_msg *nlbuf, struct net_flow_tables *ref)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(nlbuf, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; i < ref->table_sz; i++) {
		t = nla_nest_start(nlbuf, NET_FLOW_TABLE);
		err = flow_put_table(nlbuf, &ref->tables[i]);
		if (err)
			return err;
		nla_nest_end(nlbuf, t);
	}
	nla_nest_end(nlbuf, nest);
	return 0;
}

int flow_put_table_graph(struct nl_msg *nlbuf, struct net_flow_table_graph_nodes *ref)
{
	struct nlattr *nodes, *node, *jump, *jump_node;
	struct net_flow_table_graph_node *n;
	int err, i = 0, j = 0;

	nodes = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (n = ref->nodes[i], i = 0; n->uid; n = ref->nodes[++i]) {
		struct net_flow_jump_table *jnode;

		node = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH_NODE);
		if (!node)
			return -EMSGSIZE;

		if (nla_put_u32(nlbuf, NET_FLOW_TABLE_GRAPH_NODE_UID, n->uid))
			return -EMSGSIZE;

		jump = nla_nest_start(nlbuf, NET_FLOW_TABLE_GRAPH_NODE_JUMP);
		if (!jump)
			return -EMSGSIZE;

		for (j = 0, jnode = &n->jump[j];
		     jnode->node; jnode = &n->jump[++j]) {
			jump_node = nla_nest_start(nlbuf, NET_FLOW_JUMP_TABLE_ENTRY);
			if (!jump_node)
				return -EMSGSIZE;

			if (nla_put_u32(nlbuf, NET_FLOW_JUMP_TABLE_NODE, jnode->node)) {
				fprintf(stderr, "table graph node failed. aborting\n");
				return -EMSGSIZE;
			}

			err = nla_put(nlbuf, NET_FLOW_JUMP_TABLE_FIELD_REF, sizeof(jnode->field), &jnode->field);
			if (err) {
				fprintf(stderr, "table graph field ref failed. aborting\n");
				return -EMSGSIZE;
			}
			nla_nest_end(nlbuf, jump_node);
		}

		nla_nest_end(nlbuf, jump);
		nla_nest_end(nlbuf, node);
	}

	nla_nest_end(nlbuf, nodes);
	return 0;
}
