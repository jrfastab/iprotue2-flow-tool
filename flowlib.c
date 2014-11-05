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

struct hw_flow_table *tables[MAX_TABLES];
struct hw_flow_header *headers[MAX_HDRS];		/* Hack to get this working need a real datastructure */
struct hw_flow_field *header_fields[MAX_HDRS][MAX_FIELDS]; /* Hack to get this working need a real datastructure */
struct hw_flow_action *actions[MAX_ACTIONS];

char *headers_names(int uid)
{
	return headers[uid]->name;
}

struct hw_flow_header *get_headers(int uid)
{
	return headers[uid];
}

static char *fields_names(int hid, int fid)
{
	return header_fields[hid][fid]->name;
}

struct hw_flow_field *get_fields(int huid, int uid)
{
	return header_fields[huid][uid];
}

char *table_names(int uid)
{
	return tables[uid]->name;
}

struct hw_flow_table *get_tables(int uid)
{
	return tables[uid];
}

char *action_names(int uid)
{
	return actions[uid]->name;
}

struct hw_flow_action *get_actions(int uid)
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

static struct nla_policy flow_get_tables_policy[FLOW_TABLE_MAX+1] = {
	[FLOW_TABLE_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[FLOW_TABLE_IDENTIFIER]		= { .type = NLA_U32 },
	[FLOW_TABLE_TABLES]		= { .type = NLA_NESTED },
	[FLOW_TABLE_HEADERS]		= { .type = NLA_NESTED },
	[FLOW_TABLE_ACTIONS] 		= { .type = NLA_NESTED },
	[FLOW_TABLE_PARSE_GRAPH] 	= { .type = NLA_NESTED },
	[FLOW_TABLE_TABLE_GRAPH] 	= { .type = NLA_NESTED },
	[FLOW_TABLE_FLOWS]		= { .type = NLA_NESTED },
};

struct nla_policy hw_flow_table_policy[HW_FLOW_TABLE_ATTR_MAX + 1] = {
	[HW_FLOW_TABLE_ATTR_NAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ-1 },
	[HW_FLOW_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[HW_FLOW_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
	[HW_FLOW_TABLE_ATTR_FLOWS]	= { .type = NLA_NESTED },
};

struct nla_policy hw_flow_field_ref_policy[HW_FLOW_FIELD_REF_ATTR_MAX + 1] = {
	[HW_FLOW_FIELD_REF_ATTR_HEADER] = { .type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_FIELD] = { .type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_TYPE] = {.type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_VALUE] = {.type = NLA_UNSPEC, },
	[HW_FLOW_FIELD_REF_ATTR_MASK] = {.type = NLA_UNSPEC, },
};

struct nla_policy hw_flow_action_policy[HW_FLOW_ACTION_ATTR_MAX + 1] = {
	[HW_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING, },
	[HW_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[HW_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};
struct nla_policy hw_flow_action_arg_policy[HW_FLOW_ACTION_ARG_TYPE_MAX + 1] = {
	[HW_FLOW_ACTION_ARG_NAME] = {.type = NLA_STRING, .maxlen = IFNAMSIZ-1 },
	[HW_FLOW_ACTION_ARG_TYPE] = {.type = NLA_U32 },
	[HW_FLOW_ACTION_ARG_VALUE] = {.type = NLA_UNSPEC, },
};

static struct nla_policy flow_get_field_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};

static struct nla_policy flow_table_flow_policy[HW_FLOW_FLOW_ATTR_MAX+1] = {
	[HW_FLOW_FLOW_ATTR_TABLE]	= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_UID]		= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED,},
	[HW_FLOW_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED,},
};

static struct nla_policy flow_get_header_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_HEADER_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_HEADER_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

static void pp_field_ref(FILE *fp, bool p, struct hw_flow_field_ref *ref, int last)
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
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U8:
		pfprintf(stdout, p, "\t %s.%s = %02x (%02x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u8, ref->mask_u8);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		pfprintf(stdout, p, "\t %s.%s = %04x (%04x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u16, ref->mask_u16);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		pfprintf(stdout, p, "\t %s.%s = %08x (%08x)\n",
			headers_names(hi), fields_names(hi, fi), ref->value_u32, ref->mask_u32);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		pfprintf(stdout, p, "\t %s.%s = %s (%016x)\n",
			 headers_names(hi), fields_names(hi, fi),
			 ll_addr_n2a((unsigned char *)&ref->value_u64, ETH_ALEN, 0, b1, sizeof(b1)),
			 ref->value_u64, ref->mask_u64);
		break;
	default:
		break;
	}
}

void pp_fields(FILE *fp, bool print, struct hw_flow_field_ref *ref)
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

const char *flow_table_arg_type_str[__HW_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

void pp_action(FILE *fp, bool p, struct hw_flow_action *act)
{
	struct hw_flow_action_arg *arg;
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
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			pfprintf(fp, p, "%02x ", arg->value_u8);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			pfprintf(fp, p, "%i ", arg->value_u16);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			pfprintf(fp, p, "%i ", arg->value_u32);
		break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			pfprintf(fp, p, "%llu ", arg->value_u64);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_NULL:
		default:
			break;
		}
	}
out:
	pfprintf(fp, p, " )\n");
}

void pp_actions(FILE *fp, bool p, struct hw_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		pp_action(fp, p, &actions[i]);
}

void pp_table(FILE *fp, int p, struct hw_flow_table *table)
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
		struct hw_flow_action *act = actions[table->actions[i]];

		if (act->uid)
			pp_action(stdout, p, act);
	}

}

void pp_header(FILE *fp, bool p, struct hw_flow_header *header)
{
	struct hw_flow_field *f;
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

void pp_flow(FILE *fp, bool print, struct hw_flow_flow *flow)
{
	pfprintf(fp, true, "table : %i  ", flow->table_id);
	pfprintf(fp, true, "uid : %i  ", flow->uid);
	pfprintf(fp, true, "prio : %i\n", flow->priority);

	if (flow->matches)
		pp_fields(fp, print, flow->matches);	
	if (flow->actions)
		pp_actions(fp, print, flow->actions);	
}


void pp_flows(FILE *fp, bool print, struct hw_flow_flow *flows)
{
	int i;

	if (!print)
		return;

	for (i = 0; flows[i].uid; i++)
		pp_flow(fp, print, &flows[i]);
}

int nl_to_hw_flow_field_ref(FILE *fp, bool p,
			    struct nlattr *nl,
			    struct hw_flow_field_ref *ref)
{
	struct nlattr *match[HW_FLOW_FIELD_REF_ATTR_MAX+1];
	int hi, fi, type, last = ref->header;
	char b1[64];
	int err;

	err = nla_parse_nested(match, HW_FLOW_FIELD_REF_ATTR_MAX, nl, hw_flow_field_ref_policy);
	if (err) {
		fprintf(stderr, "Warning field_ref parse error. aborting.\n");
		return -EINVAL;
	}

	hi = match[HW_FLOW_FIELD_REF_ATTR_HEADER] ?
		nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_HEADER]) : 0;
	fi = match[HW_FLOW_FIELD_REF_ATTR_FIELD] ?
		nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_FIELD]) : 0;
	type = match[HW_FLOW_FIELD_REF_ATTR_TYPE] ?
		nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_TYPE]) : 0;
#if 0
	else if ... (* use unique ids if no strings *)
#endif

	ref->header	= hi;
	ref->field	= fi;
	ref->type	= type; 

	if (!match[HW_FLOW_FIELD_REF_ATTR_VALUE] ||
	    !match[HW_FLOW_FIELD_REF_ATTR_MASK])
		return 0;

	switch (type) {
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U8:
		ref->value_u8 = nla_get_u8(match[HW_FLOW_FIELD_REF_ATTR_VALUE]);
		ref->mask_u8 = nla_get_u8(match[HW_FLOW_FIELD_REF_ATTR_MASK]);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		ref->value_u16 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u16(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u16 = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u16(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		ref->value_u32 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u32   = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		ref->value_u64 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u64(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u64   = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u64(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		break;
	break;
		default:
		type = 0;
	}

	pp_field_ref(fp, p, ref, last);
	return 0;
}

int nl_to_sw_action(FILE *fp, bool p, struct nlattr *nl, struct hw_flow_action **a)
{
	int rem;
	struct nlattr *signature, *l;
	struct nlattr *action[HW_FLOW_ACTION_ATTR_MAX+1];
	struct hw_flow_action *act;
	int err, uid, count = 0;
	char *name;

	err = nla_parse_nested(action, HW_FLOW_ACTION_ATTR_MAX, nl, hw_flow_action_policy);
	if (err) {
		fprintf(stderr, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	uid = action[HW_FLOW_ACTION_ATTR_UID] ? nla_get_u32(action[HW_FLOW_ACTION_ATTR_UID]) : -1;
	if (uid < 0)
		return 0;

	act = actions[uid]; /* TBD review error paths */
	if (!act) {
		act = calloc(1, sizeof(struct hw_flow_action));
		if (!act)
			return -ENOMEM;
	}

	if (action[HW_FLOW_ACTION_ATTR_NAME]) {
		act->uid = uid;
		name = nla_get_string(action[HW_FLOW_ACTION_ATTR_NAME]);
		strncpy(act->name, name, IFNAMSIZ - 1);
	} else if (act && act->uid) {
		name = act->name;
	} else {
		name = "<none>";
	}

	if (!action[HW_FLOW_ACTION_ATTR_SIGNATURE])
		goto done;

	signature = action[HW_FLOW_ACTION_ATTR_SIGNATURE];
	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem))
		count++;
	
	if (act->args) /* replace args with new values */
		free(act->args);

	if (count > 0) {
		act->args = calloc(count + 1, sizeof(struct hw_flow_action_arg));
		if (!act->args)
			return -ENOMEM;
	}

	count = 0;

	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem)) {
		struct nlattr *arg[HW_FLOW_ACTION_ARG_TYPE_MAX+1];
		const char *argname;
		__u64 vu64;
		__u32 vu32;
		__u16 vu16;
		__u8 vu8;
		int t;

		err = nla_parse_nested(arg, HW_FLOW_ACTION_ARG_TYPE_MAX, l, hw_flow_action_arg_policy);
		if (err) {
			fprintf(stdout, "Warning parse error parsing action arguments\n");
			return -EINVAL;
		}

		argname = arg[HW_FLOW_ACTION_ARG_NAME] ?
			  nla_get_string(arg[HW_FLOW_ACTION_ARG_NAME]) : "";
		t = arg[HW_FLOW_ACTION_ARG_TYPE] ? nla_get_u32(arg[HW_FLOW_ACTION_ARG_TYPE]) : 0;

		strncpy(act->args[count].name, argname, IFNAMSIZ);
		act->args[count].type = t;

		switch (t) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			vu8 = nla_get_u8(arg[HW_FLOW_ACTION_ARG_VALUE]);
			act->args[count].value_u8 = vu8;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			vu16 = nla_get_u16(arg[HW_FLOW_ACTION_ARG_VALUE]);
			act->args[count].value_u16 = vu16;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			vu32 = nla_get_u32(arg[HW_FLOW_ACTION_ARG_VALUE]);
			act->args[count].value_u32 = vu32;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			vu64 = nla_get_u64(arg[HW_FLOW_ACTION_ARG_VALUE]);
			act->args[count].value_u64 = vu64;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_NULL:
		default:
			break;
		}

		count++;
	}

done:
	actions[uid] = act;
	if (a)
		*a = act;
	pp_action(fp, p, act);
	return 0;
}

int nl_to_matches(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_field_ref **ref)
{
	struct hw_flow_field_ref *r;
	struct nlattr *i;
	int err, rem, cnt;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	r = calloc(cnt + 1, sizeof(struct hw_flow_field_ref));
	if (!r)
		return -ENOMEM;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		err = nl_to_hw_flow_field_ref(fp, print, i, &r[cnt]);
		if (err)
			goto out;
	}


	*ref = r;
	return 0;
out:
	free(r);
	return err;
}

int nl_to_actions(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_action **actions)
{
	struct hw_flow_action **acts;
	int err, rem, j = 0;
	struct nlattr *i;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) 
		j++;

	acts = calloc(j + 1, sizeof(struct hw_flow_action *));
	if (!acts)
		return -ENOMEM; 

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) 
		nl_to_sw_action(fp, print, i, &acts[j]);

	if (actions)
		actions = &acts[0];
	else
		free(acts);

	return 0;
}


int nl_to_flow_table(FILE *fp, bool print, struct nlattr *nl,
		     struct hw_flow_table *t)
{
	struct nlattr *table[HW_FLOW_TABLE_ATTR_MAX+1];
	struct nlattr *i;
	char *name;
	int uid, src, size, cnt, rem, err = 0;
	struct hw_flow_field_ref *matches;
	hw_flow_action_ref *actions;

	err = nla_parse_nested(table, HW_FLOW_TABLE_ATTR_MAX, nl, hw_flow_table_policy);
	if (err) {
		fprintf(stderr, "Warning parse error flow attribs, abort parse\n");
		return err;
	}

	name = table[HW_FLOW_TABLE_ATTR_NAME] ? nla_get_string(table[HW_FLOW_TABLE_ATTR_NAME]) : "<none>",
	uid = table[HW_FLOW_TABLE_ATTR_UID] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_UID]) : 0;

	src = table[HW_FLOW_TABLE_ATTR_SOURCE] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_SOURCE]) : 0,
	size = table[HW_FLOW_TABLE_ATTR_SIZE] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_SIZE]) : 0;

	if (table[HW_FLOW_TABLE_ATTR_MATCHES])
		nl_to_matches(fp, print, table[HW_FLOW_TABLE_ATTR_MATCHES], &matches);

	if (table[HW_FLOW_TABLE_ATTR_ACTIONS]) {
		rem = nla_len(table[HW_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[HW_FLOW_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem))
			cnt++;

		actions = calloc(cnt + 1, sizeof (struct hw_flow_field_ref));
		if (!actions)
			goto out;

		rem = nla_len(table[HW_FLOW_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[HW_FLOW_TABLE_ATTR_ACTIONS]);
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

int nl_to_flow_tables(FILE *fp, bool print, struct nlattr *nl,
		      struct hw_flow_table **t)
{
	struct hw_flow_table *tables;
	struct nlattr *i;
	int err, rem, cnt;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	tables = calloc(cnt, sizeof(struct hw_flow_table));
	if (!tables)
		return -ENOMEM;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		err = nl_to_flow_table(fp, print, i, &tables[cnt]);
		if (err)
			goto out;
	}

	if (print) /* TBD: move this into printer */
		pfprintf(fp, print, "\n");

	if (t)
		*t = tables;
	else
		free(tables);

	return 0;
out:
	free(tables);
	return err;
}

int nl_to_flows(FILE *fp, bool print, struct nlattr *attr, struct hw_flow_flow **flows)
{
	struct hw_flow_field_ref *matches;
	struct hw_flow_action *actions;
	struct hw_flow_flow  *f;
	struct nlattr *i;
	int err, rem, count = 0;;

	rem = nla_len(attr);
	for (i = nla_data(attr);  nla_ok(i, rem); i = nla_next(i, &rem)) 
		count++;

	f = calloc(count + 1, sizeof(struct hw_flow_flow));

	
	rem = nla_len(attr);
	for (count = 0, i = nla_data(attr);
	     nla_ok(i, rem); i = nla_next(i, &rem), count++) {
		struct nlattr *flow[HW_FLOW_FLOW_ATTR_MAX+1];

		err = nla_parse_nested(flow, HW_FLOW_FLOW_ATTR_MAX, i, flow_table_flow_policy);

		if (flow[HW_FLOW_FLOW_ATTR_TABLE])
			f[count].table_id = nla_get_u32(flow[HW_FLOW_FLOW_ATTR_TABLE]);

		if (flow[HW_FLOW_FLOW_ATTR_UID])
			f[count].uid = nla_get_u32(flow[HW_FLOW_FLOW_ATTR_UID]);

		if (flow[HW_FLOW_FLOW_ATTR_PRIORITY])
			f[count].priority = nla_get_u32(flow[HW_FLOW_FLOW_ATTR_PRIORITY]);

		if (flow[HW_FLOW_FLOW_ATTR_MATCHES])
			err = nl_to_matches(false, false,
					    flow[HW_FLOW_FLOW_ATTR_MATCHES], &matches);

		if (flow[HW_FLOW_FLOW_ATTR_ACTIONS])
			nl_to_actions(fp, print, flow[HW_FLOW_FLOW_ATTR_ACTIONS], &actions);
		
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

int nl_to_flow_table_field(FILE *fp, bool p, struct nlattr *nl, struct hw_flow_header *hdr)
{
	struct nlattr *i;
	struct nlattr *field[HW_FLOW_FIELD_ATTR_MAX+1];
	int rem, err, count = 0;

	/* TBD this couting stuff is a bit clumsy */
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	hdr->fields = calloc(count + 1, sizeof(struct hw_flow_header));

	count = 0;
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct hw_flow_field *f = &hdr->fields[count];	

		err = nla_parse_nested(field, HW_FLOW_FIELD_ATTR_MAX, i, flow_get_field_policy);
		if (err) {
			fprintf(stderr, "Warning field parse error\n");
			return -EINVAL;
		}

		f->uid = field[HW_FLOW_FIELD_ATTR_UID] ?
			 nla_get_u32(field[HW_FLOW_FIELD_ATTR_UID]) : 0;
		strncpy(f->name, (field[HW_FLOW_FIELD_ATTR_NAME] ? 
			  nla_get_string(field[HW_FLOW_FIELD_ATTR_NAME]) : "<none>"), IFNAMSIZ - 1);
		f->bitwidth = field[HW_FLOW_FIELD_ATTR_BITWIDTH] ?
			      nla_get_u32(field[HW_FLOW_FIELD_ATTR_BITWIDTH]) : 0;
		header_fields[hdr->uid][f->uid] = f;
		count++;
	}

	return count;
}

int nl_to_hw_headers(FILE *fp, bool p, struct nlattr *nl)
{
	struct nlattr *i;
	int rem;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *hdr[HW_FLOW_HEADER_ATTR_MAX+1];
		struct hw_flow_header *header;
		struct nlattr *fields, *j;
		int uid, err;

		err = nla_parse_nested(hdr, HW_FLOW_HEADER_ATTR_MAX, i, flow_get_header_policy);
		if (err) {
			fprintf(stderr, "Warning header parse error. aborting.\n");
			return -EINVAL;
		}

		header = calloc(1, sizeof(struct hw_flow_header));
		if (!header) {
			fprintf(stderr, "Warning OOM in header parser. aborting.\n");
			return -ENOMEM;
		}

		header->uid = hdr[HW_FLOW_HEADER_ATTR_UID] ?
				nla_get_u32(hdr[HW_FLOW_HEADER_ATTR_UID]) : 0;
		strncpy(header->name,
			strdup(hdr[HW_FLOW_HEADER_ATTR_NAME] ?
				nla_get_string(hdr[HW_FLOW_HEADER_ATTR_NAME]) : ""), IFNAMSIZ - 1);

		nl_to_flow_table_field(fp, p, hdr[HW_FLOW_HEADER_ATTR_FIELDS], header);
		headers[header->uid] = header;
		pp_header(fp, p, header);
	}
	return 0;
}

static int flow_put_action_args(struct nl_msg *nlbuf, struct hw_flow_action_arg *args, int argcnt)
{
	struct nlattr *arg;
	int i;

	for (i = 0; i < argcnt; i++) {
		struct hw_flow_action_arg *this = &args[i];

		arg = nla_nest_start(nlbuf, HW_FLOW_ACTION_ARG);
		if (!arg)
			return -EMSGSIZE;

		if (this->type == HW_FLOW_ACTION_ARG_TYPE_NULL)
			goto next_arg;

		if (this->name &&
		    nla_put_string(nlbuf, HW_FLOW_ACTION_ARG_NAME, this->name))
			return -EMSGSIZE;

		if (nla_put_u32(nlbuf, HW_FLOW_ACTION_ARG_TYPE, this->type))
			return -EMSGSIZE;

		switch (this->type) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			if (nla_put_u8(nlbuf,
				       HW_FLOW_ACTION_ARG_VALUE, this->value_u8))
				return -EMSGSIZE;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			if (nla_put_u16(nlbuf,
					HW_FLOW_ACTION_ARG_VALUE, this->value_u16))
				return -EMSGSIZE;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			if (nla_put_u32(nlbuf,
					HW_FLOW_ACTION_ARG_VALUE, this->value_u32))
				return -EMSGSIZE;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			if (nla_put_u64(nlbuf,
					HW_FLOW_ACTION_ARG_VALUE, this->value_u64))
				return -EMSGSIZE;
			break;
		default:
			break;
		}
next_arg:
		nla_nest_end(nlbuf, arg);
	}

	return 0;
}

static int flow_put_action(struct nl_msg *nlbuf, struct hw_flow_action *ref)
{
	struct hw_flow_action_arg *this;
	struct nlattr *nest;
	int err, args = 0;

	if (nla_put_string(nlbuf, HW_FLOW_ACTION_ATTR_NAME, ref->name) ||
	    nla_put_u32(nlbuf, HW_FLOW_ACTION_ATTR_UID, ref->uid))
		return -EMSGSIZE;

	for (this = &ref->args[0]; strlen(this->name) > 0; this++)
		args++;

	if (args) {
		nest = nla_nest_start(nlbuf, HW_FLOW_ACTION_ATTR_SIGNATURE);
		if (!nest)
			return -EMSGSIZE;

		err = flow_put_action_args(nlbuf, ref->args, args);
		if (err)
			return err;
		nla_nest_end(nlbuf, nest);
	}

	return 0;
}

int flow_put_actions(struct nl_msg *nlbuf, struct hw_flow_actions *ref)
{
	struct hw_flow_action **a;
	struct hw_flow_action *this;
	struct nlattr *actions;
	int err;

	actions = nla_nest_start(nlbuf, FLOW_TABLE_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (a = ref->actions, this = *a; strlen(this->name) > 0; a++, this = *a) {
		struct nlattr *action = nla_nest_start(nlbuf, HW_FLOW_ACTION);

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

static int flow_put_fields(struct nl_msg *nlbuf, struct hw_flow_header *ref)
{
	struct nlattr *field;
	int count = ref->field_sz;
	struct hw_flow_field *f;

	for (f = ref->fields; count; count--, f++) {
		field = nla_nest_start(nlbuf, HW_FLOW_FIELD);
		if (!field)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, HW_FLOW_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(nlbuf, HW_FLOW_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(nlbuf, HW_FLOW_FIELD_ATTR_BITWIDTH, f->bitwidth))
			return -EMSGSIZE;

		nla_nest_end(nlbuf, field);
	}

	return 0;
}

int flow_put_headers(struct nl_msg *nlbuf, struct hw_flow_headers *ref)
{
	struct nlattr *nest, *hdr, *fields;
	struct hw_flow_header *this, **h;
	int err;

	nest = nla_nest_start(nlbuf, FLOW_TABLE_HEADERS);
	if (!nest)
		return -EMSGSIZE;
		
	for (h = ref->hw_flow_headers, this = *h; strlen(this->name) > 0; h++, this = *h) {
		hdr = nla_nest_start(nlbuf, HW_FLOW_HEADER);
		if (!hdr)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, HW_FLOW_HEADER_ATTR_NAME, this->name) ||
		    nla_put_u32(nlbuf, HW_FLOW_HEADER_ATTR_UID, this->uid))
			return -EMSGSIZE;

		fields = nla_nest_start(nlbuf, HW_FLOW_HEADER_ATTR_FIELDS);
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

int flow_put_flows(struct nl_msg *nlbuf, struct hw_flow_flow *ref)
{
	struct nlattr *flows, *matches, *field;
	struct nlattr *actions = NULL;
	int err, j, i = 0;

	flows = nla_nest_start(nlbuf, HW_FLOW_FLOW);
	if (!flows)
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, HW_FLOW_FLOW_ATTR_TABLE, ref->table_id) ||
	    nla_put_u32(nlbuf, HW_FLOW_FLOW_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, HW_FLOW_FLOW_ATTR_PRIORITY, ref->priority))
		return -EMSGSIZE;

#if 0
	matches = nla_nest_start(nlbuf, HW_FLOW_FLOW_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (j = 0; j < mcnt; j++) {
		struct hw_flow_field_ref *f = &ref->matches[j];

		if (!f->header)
			continue;

		field = nla_nest_start(nlbuf, HW_FLOW_FIELD_REF);
		if (!field || flow_put_field_ref(nlbuf, f))
			return -EMSGSIZE;
		nla_nest_end(nlbuf, field);
	}
	nla_nest_end(nlbuf, matches);

	actions = nla_nest_start(nlbuf, HW_FLOW_FLOW_ATTR_ACTIONS);
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

static int flow_put_field_ref(struct nl_msg *nlbuf, struct hw_flow_field_ref *ref)
{
	if (nla_put_u32(nlbuf, HW_FLOW_FIELD_REF_ATTR_HEADER, ref->header) ||
	    nla_put_u32(nlbuf, HW_FLOW_FIELD_REF_ATTR_FIELD, ref->field)   ||
	    nla_put_u32(nlbuf, HW_FLOW_FIELD_REF_ATTR_TYPE, ref->type))
		return -EMSGSIZE;

	switch (ref->type) {
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U8:
		if (nla_put_u8(nlbuf,
			       HW_FLOW_FIELD_REF_ATTR_VALUE, ref->value_u8) ||
		    nla_put_u8(nlbuf,
			       HW_FLOW_FIELD_REF_ATTR_MASK, ref->mask_u8))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		if (nla_put_u16(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_VALUE, ref->value_u16) ||
		    nla_put_u16(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_MASK, ref->mask_u16))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		if (nla_put_u32(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_VALUE, ref->value_u32) ||
		    nla_put_u32(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_MASK, ref->mask_u32))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		if (nla_put_u64(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_VALUE, ref->value_u64) ||
		    nla_put_u64(nlbuf,
				HW_FLOW_FIELD_REF_ATTR_MASK, ref->mask_u64))
			return -EMSGSIZE;
		break;
	default:
		break;
	}

	return 0;
}

int flow_put_table(struct nl_msg *nlbuf, struct hw_flow_table *ref)
{
	struct nlattr *matches, *flow, *actions;
	struct hw_flow_field_ref *m;
	hw_flow_action_ref *aref;
	int err;

	flow = NULL; /* must null to get unwind correct */

	if (nla_put_string(nlbuf, HW_FLOW_TABLE_ATTR_NAME, ref->name) ||
	    nla_put_u32(nlbuf, HW_FLOW_TABLE_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, HW_FLOW_TABLE_ATTR_SOURCE, ref->source) ||
	    nla_put_u32(nlbuf, HW_FLOW_TABLE_ATTR_SIZE, ref->size))
		return -EMSGSIZE;

	matches = nla_nest_start(nlbuf, HW_FLOW_TABLE_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (m = ref->matches; m->header || m->field; m++) {
		struct nlattr *match = nla_nest_start(nlbuf, HW_FLOW_FIELD_REF);

		if (!match)
			return -EMSGSIZE;

		err = flow_put_field_ref(nlbuf, m);
		if (err)
			return -EMSGSIZE;
		nla_nest_end(nlbuf, match);
	}
	nla_nest_end(nlbuf, matches);

	actions = nla_nest_start(nlbuf, HW_FLOW_TABLE_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (aref = ref->actions; *aref; aref++) {
		if (nla_put_u32(nlbuf, HW_FLOW_ACTION_ATTR_UID, *aref))
			return -EMSGSIZE;
	}
	nla_nest_end(nlbuf, actions);
	return 0;
}

int flow_put_tables(struct nl_msg *nlbuf, struct hw_flow_tables *ref)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(nlbuf, FLOW_TABLE_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; i < ref->table_sz; i++) {
		t = nla_nest_start(nlbuf, HW_FLOW_TABLE);
		err = flow_put_table(nlbuf, &ref->tables[i]);
		if (err)
			return err;
		nla_nest_end(nlbuf, t);
	}
	nla_nest_end(nlbuf, nest);
	return 0;
}
