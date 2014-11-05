/*******************************************************************************

  Flow Agent
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
#include <unistd.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>

#include <linux/if_flow.h>
#include <linux/if_ether.h>

#include "flowlib.h"

static struct nl_sock *nsd;

struct flow_msg {
	void *msg;
	struct nl_msg *nlbuf;
	int refcnt;
	LIST_ENTRY(flow_msg) ack_list_element;
	int seq;
	void (*ack_cb)(struct flow_msg *amsg, struct flow_msg *msg, int err);
};

LIST_HEAD(ack_list, flow_msg);

struct ack_list ack_list_head = {NULL};

int seq = 0;

static void pfprintf(FILE *fp, bool p, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (p)
		vfprintf(fp, format, args);

	va_end(args);
}

struct flow_msg *alloc_flow_msg(uint32_t type, uint32_t pid, uint16_t flags, size_t size, int family)
{
	struct flow_msg *msg;
	static uint32_t seq = 0;

	msg = (struct flow_msg *) malloc(sizeof(struct flow_msg));
	if (!msg)
		return NULL;

	msg->nlbuf = nlmsg_alloc();
	msg->msg = genlmsg_put(msg->nlbuf, 0, seq, family, size, flags, type, 1);
	msg->ack_cb = NULL;
	msg->seq = seq++;

	if (pid) {
		struct nl_msg *nl_msg = msg->nlbuf;
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
			.nl_pid = pid,
			.nl_groups = 0,
		};

		nlmsg_set_dst(nl_msg, &nladdr);
	}
	return msg;
}

void set_ack_cb(struct flow_msg *msg,
		void (*cb)(struct flow_msg *, struct flow_msg *, int))
{
	if (msg->ack_cb)
		return;

	msg->ack_cb = cb;
	msg->refcnt++;
	LIST_INSERT_HEAD(&ack_list_head, msg, ack_list_element);
}

void handle_flow_table_get_tables(struct flow_msg *amsg, struct flow_msg *msg, int err)
{
	if (err) {
		fprintf(stderr, "Netlink request error: %s\n", strerror(err));
		return;
	}
	printf("got reply what is it?\n");
}

struct flow_msg *wrap_netlink_msg(struct nlmsghdr *buf)
{
	struct flow_msg *msg;

	msg = (struct flow_msg *) malloc(sizeof(struct flow_msg));
	if (msg) {
		msg->refcnt = 1;
		msg->msg = buf;
		msg->nlbuf = NULL;
	}

	return msg;
}

int free_flow_msg(struct flow_msg *msg)
{
	int refcnt;

	msg->refcnt--;

	refcnt = msg->refcnt;

	if (!refcnt) {
		if (msg->nlbuf)
			nlmsg_free(msg->nlbuf);
		else
			free(msg->msg);
		free(msg);
	}

	return refcnt;
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

struct nl_cache *link_cache;

static int flow_table_cmd_to_type(FILE *fp, bool p, int valid, struct nlattr *tb[])
{
	int ifindex, type;
	char iface[IFNAMSIZ];

	if (!tb[FLOW_TABLE_IDENTIFIER_TYPE]) {
		fprintf(stderr, "Warning: received get_tables without identifier type!\n");
		return -EINVAL;
	}
	if (!tb[FLOW_TABLE_IDENTIFIER]) {
		fprintf(stderr, "Warning: received get_tables without identifier!\n");
		return -EINVAL;
	}

	if (!tb[valid]){
		fprintf(stderr, "Warning recevied cmd without valid attribute expected %i\n", valid);
		return -EINVAL;
	}

	type = nla_get_u32(tb[FLOW_TABLE_IDENTIFIER_TYPE]);

	switch (type) {
	case FLOW_TABLE_IDENTIFIER_IFINDEX:
		ifindex = nla_get_u32(tb[FLOW_TABLE_IDENTIFIER]);
		rtnl_link_i2name(link_cache, ifindex, iface, IFNAMSIZ);
		pfprintf(fp, p, "%s (%i):\n", iface, ifindex);
		break;
	default:
		fprintf(stderr, "Unknown table identifier, abort\n");
		return -EINVAL;
	}

	return 0;
}

static void flow_table_cmd_get_tables(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, FLOW_TABLE_TABLES, tb))
		return;

	if (tb[FLOW_TABLE_TABLES])
		flow_get_tables(stdout, verbose, tb[FLOW_TABLE_TABLES], NULL);
}

static struct nla_policy flow_get_field_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};

static struct nla_policy flow_get_header_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_HEADER_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_HEADER_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

static void flow_table_cmd_get_headers(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, FLOW_TABLE_HEADERS, tb))
		return;

	if (tb[FLOW_TABLE_HEADERS])
		flow_get_headers(stdout, verbose, tb[FLOW_TABLE_HEADERS]);
}

static struct nla_policy flow_get_jump_policy[HW_FLOW_JUMP_TABLE_MAX+1] = {
	[HW_FLOW_JUMP_TABLE_NODE]  = { .type = NLA_U32, },
	[HW_FLOW_JUMP_TABLE_FIELD] = { .type = NLA_NESTED, },
};

static int flow_table_tbl_graph_jump(FILE *fp, bool p, struct nlattr *nl)
{
	struct nlattr *i;
	int rem, err;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct hw_flow_field_ref ref = {.header = -1, };
		struct nlattr *jump[HW_FLOW_JUMP_TABLE_MAX];
		int node;

		err = nla_parse_nested(jump, HW_FLOW_JUMP_TABLE_MAX, i, flow_get_jump_policy);
		if (err) {
			fprintf(stderr, "Warning parsing jump tabled failed\n");
			continue;
		}

		if (!jump[HW_FLOW_JUMP_TABLE_NODE])
			fprintf(stderr, "Warning no jump table node!\n");

		if (!jump[HW_FLOW_JUMP_TABLE_FIELD])
			fprintf(stderr, "Warning no jump table field!\n");

		node = nla_get_u32(jump[HW_FLOW_JUMP_TABLE_NODE]);
		if (node < 0)
			pfprintf(fp, p, "\n\t terminating node", node);
		else
			pfprintf(fp, p, "\n\t to node %i when", node);

		flow_get_field(stdout, p, jump[HW_FLOW_JUMP_TABLE_FIELD], &ref);
	}
}

static struct nla_policy flow_get_node_policy[HW_TABLE_GRAPH_NODE_MAX + 1] = {
	[HW_TABLE_GRAPH_NODE_UID]    = { .type = NLA_U32,},
	[HW_TABLE_GRAPH_NODE_JUMP]   = { .type = NLA_NESTED,},
};

static void flow_table_tbl_graph_parse(FILE *fp, bool p, struct nlattr *nl)
{
	struct nlattr *i;
	int rem, err, uid;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *node[HW_TABLE_GRAPH_NODE_MAX+1];

		err = nla_parse_nested(node, HW_TABLE_GRAPH_NODE_MAX, i, flow_get_node_policy);
		if (err) {
			fprintf(stderr, "Warning table graph node parse error. aborting.\n");
			return;
		}

		if (!node[HW_TABLE_GRAPH_NODE_UID]) {
			fprintf(stderr, "Warning, missing graph node uid\n");
			continue;
		}

		uid = nla_get_u32(node[HW_TABLE_GRAPH_NODE_UID]);
		pfprintf(fp, p, "table %s ", table_names(uid));

		if (!node[HW_TABLE_GRAPH_NODE_JUMP]) {
			fprintf(stderr, "Warning, missing graph node jump table\n");
			continue;
		}

		err = flow_table_tbl_graph_jump(fp, p, node[HW_TABLE_GRAPH_NODE_JUMP]);
		if (err) {
			fprintf(stderr, "Warning table graph jump parse error. aborting.\n");
			return;
		}
		pfprintf(fp, p, "\n");
	}	
}

static void flow_table_cmd_get_actions(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, FLOW_TABLE_ACTIONS, tb))
		return;

	if (tb[FLOW_TABLE_ACTIONS])
		flow_get_actions(stdout, verbose, tb[FLOW_TABLE_ACTIONS], NULL);
}

static void flow_table_cmd_get_parse_graph(struct flow_msg *msg, int verbose)
{
	pfprintf(stdout, verbose, "Parse graph operation not supported\n");
}

static void flow_table_cmd_get_table_graph(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, FLOW_TABLE_TABLE_GRAPH, tb))
		return;

	if (tb[FLOW_TABLE_TABLE_GRAPH])
		flow_table_tbl_graph_parse(stdout, verbose, tb[FLOW_TABLE_TABLE_GRAPH]);
}

static
struct nla_policy flow_table_flows_policy[FLOW_TABLE_FLOWS_MAX + 1] = {
	[FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
	[FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
	[FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
	[FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

static
struct nla_policy flow_table_flow_policy[HW_FLOW_FLOW_ATTR_MAX+1] = {
	[HW_FLOW_FLOW_ATTR_TABLE]	= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_UID]		= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32,},
	[HW_FLOW_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED,},
	[HW_FLOW_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED,},
};

static void flow_table_cmd_get_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, FLOW_TABLE_FLOWS, tb))
		return;

	if (tb[FLOW_TABLE_FLOWS])
		flow_get_flows(stdout, verbose, tb[FLOW_TABLE_FLOWS], NULL);
}

static void flow_table_cmd_set_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];
	int err;

	fprintf(stdout, "received set flow reply\n");

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}
}

struct flow_msg *recv_flow_msg(int *err)
{
	static unsigned char *buf;
	struct flow_msg *msg;
	struct genlmsghdr *glm;
	struct sockaddr_nl nla;
	int type;
	int rc;

	*err = 0;

	do {
		rc = nl_recv(nsd, &nla, &buf, NULL);
		if (rc < 0) {	
			switch (errno) {
			case EINTR:
				/*
				 * Take a pass throught the state loop
				 */
				return NULL;
				break;
			default:
				perror("Receive operation failed:");
				return NULL;
				break;
			}
		}
	} while (rc == 0);

	msg = wrap_netlink_msg((struct nlmsghdr *)buf);

	type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct flow_msg *am;
		struct nlmsgerr *errm = nlmsg_data(msg->msg);

		LIST_FOREACH(am, &ack_list_head, ack_list_element) {
			if (am->seq == errm->msg.nlmsg_seq)
				break;
		}
	
		if (am) {	
			LIST_REMOVE(am, ack_list_element);
			am->ack_cb(msg, am, errm->error);
			free_flow_msg(am);
		}

		free_flow_msg(msg);
		return NULL;
	}

	glm = nlmsg_data(msg->msg);
	type = glm->cmd;
	
	if (type != FLOW_TABLE_CMD_GET_TABLES &&
	    type != FLOW_TABLE_CMD_GET_HEADERS &&
	    type != FLOW_TABLE_CMD_GET_ACTIONS &&
	    type != FLOW_TABLE_CMD_GET_FLOWS &&
	    type != FLOW_TABLE_CMD_GET_TABLE_GRAPH) {
		printf("Received message of unknown type %d\n", 
			type);
		free_flow_msg(msg);
		return NULL;
	}

	return msg;	
}

static void(*type_cb[FLOW_TABLE_MAX+1])(struct flow_msg *, int err) = {
	flow_table_cmd_get_tables,
	flow_table_cmd_get_headers,
	flow_table_cmd_get_actions,
	flow_table_cmd_get_parse_graph,
	flow_table_cmd_get_table_graph,
	flow_table_cmd_get_flows,
	flow_table_cmd_set_flows,
};

void process_rx_message(int verbose)
{
	struct flow_msg *msg;
	int err;
	int type;
	sigset_t bs;

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = recv_flow_msg(&err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct genlmsghdr *glh = nlmsg_data(nlh);
		type = glh->cmd;
		type_cb[type](msg, verbose);
	}
	return;
}

void flow_usage()
{
	fprintf(stdout, "flow <dev> [get_tables | get_headers | get_actions | get_flows <table> | get_graph]\n");
	fprintf(stdout, "           [set_flow ]\n");
}


void set_flow_usage()
{
	printf("flow dev set_flow prio <num> fh <num> table <id>  match <name> action <name arguments>\n");
}

#define NEXT_ARG() do { argv++; if (--argc <= 0) break; } while(0)

int flow_set_send(bool verbose, int pid, int family, int ifindex, int argc, char **argv)
{
	struct nlattr *deprecated_flows, *flows, *flow;
	struct flow_msg *msg;
	int c, i, digit_optind = 0;
	int cmd = FLOW_TABLE_CMD_SET_FLOWS;
	int table, prio, uid, err = 0;
	int hdr_uid, field_uid;
	char *endptr;
	struct hw_flow_field_ref *m = NULL;
	struct hw_flow_action *a = NULL;
	struct hw_flow_action_arg *args;
	struct hw_flow_header *h;
	struct hw_flow_field *f;
	unsigned long int match_value;
	struct nlattr *field, *matches, *actions, *action, *signatures, *signature;

	table = prio = uid = 0;

	opterr = 0;
	while (argc > 0) {
		if (strcmp(*argv, "match") == 0) {
			char *strings, *hdr, *field;

			NEXT_ARG();
			strings = *argv;

			hdr = strtok(strings, ".");
			field = strtok(NULL, ".");

			find_match(hdr, field, &hdr_uid, &field_uid);
			h = get_headers(hdr_uid);
			f = get_fields(hdr_uid, field_uid);

			NEXT_ARG();
			match_value = strtoul(*argv, &endptr, 0);
			/* TBD mask support */
		} else if (strcmp(*argv, "action") == 0) {
			NEXT_ARG();

			i = find_action(*argv);
			if (i < 0) {
				printf("Unknown action\n");
				set_flow_usage();
				exit(-1);
			}

			a = get_actions(i);
			args = a->args;
			for (i = 0; a->args && a->args[i].type; i++) {
				struct hw_flow_action_arg *arg = &a->args[i];

				NEXT_ARG();
				switch (arg->type) {
				case HW_FLOW_ACTION_ARG_TYPE_U8:
					arg->value_u8 = 0;
					break;
				case HW_FLOW_ACTION_ARG_TYPE_U16:
					arg->value_u16 = 0;
					break;
				case HW_FLOW_ACTION_ARG_TYPE_U32:
					arg->value_u32 = atoi(*argv); 
					break;
				case HW_FLOW_ACTION_ARG_TYPE_U64:
					arg->value_u64 = strtol(*argv, &endptr, 10);
					break;
				}
			}
		} else if (strcmp(*argv, "prio") == -1) {
			NEXT_ARG();
			prio = atoi(*argv);
		} else if (strcmp(*argv, "handle") == 0) {
			NEXT_ARG();
			uid = atoi(*argv);
		} else if (strcmp(*argv, "table") == 0) {
			NEXT_ARG();
			table = atoi(*argv);
		}
		argc--; argv++;
	}

	if (err) {
		printf("Invalid argument\n");
		set_flow_usage();
		exit(-1);
	}

	if (!table) {
		fprintf(stderr, "Table ID requried\n");	
		set_flow_usage();
		exit(-1);
	}

	if (!prio)
		prio = 1;

	if (!uid)
		uid = 10;	

	if (!a) {
		fprintf(stderr, "Missing action list\n");
		set_flow_usage();
		exit(-1);
	}

	printf("prio %i uid %i table %i\n", prio, uid, table);
	printf("  match: %s.%s %lu\n", h->name, f->name, match_value);
	printf("  action: %s ", a->name);
	for (i = 0; a->args && a->args[i].type; i++) {
		struct hw_flow_action_arg *arg = &a->args[i];

		switch (arg->type) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			arg->value_u8 = 0;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			arg->value_u16 = 0;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			printf("%s %i ", arg->name, arg->value_u32);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			printf("%s %lu ", arg->name, arg->value_u64);
			break;
		}
	}
	printf("\n");

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER_TYPE, FLOW_TABLE_IDENTIFIER_IFINDEX);
	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER, ifindex);

	/* Add flows */ /* TBD error checking */
	flows = nla_nest_start(msg->nlbuf, FLOW_TABLE_FLOWS);
	deprecated_flows = nla_nest_start(msg->nlbuf, FLOW_TABLE_FLOWS_FLOWS);
	
	flow = nla_nest_start(msg->nlbuf, HW_FLOW_FLOW);

	nla_put_u32(msg->nlbuf, HW_FLOW_FLOW_ATTR_TABLE, table);
	nla_put_u32(msg->nlbuf, HW_FLOW_FLOW_ATTR_UID, uid);
	nla_put_u32(msg->nlbuf, HW_FLOW_FLOW_ATTR_PRIORITY, prio);

	matches = nla_nest_start(msg->nlbuf, HW_FLOW_FLOW_ATTR_MATCHES);
	field = nla_nest_start(msg->nlbuf, HW_FLOW_FIELD_REF);
	
	nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_HEADER, h->uid);
	nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_FIELD, f->uid);

	if (f->bitwidth <= 8) {
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_TYPE, HW_FLOW_FIELD_REF_ATTR_TYPE_U8);
		nla_put_u8(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_VALUE, match_value);
		nla_put_u8(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_MASK, -1);
	} else if (f->bitwidth <= 16) {
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_TYPE, HW_FLOW_FIELD_REF_ATTR_TYPE_U16);
		nla_put_u16(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_VALUE, match_value);
		nla_put_u16(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_MASK, -1);
	} else if (f->bitwidth <= 32) {
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_TYPE, HW_FLOW_FIELD_REF_ATTR_TYPE_U32);
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_VALUE, match_value);
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_MASK, -1);
	} else if (f->bitwidth <= 64) {
		nla_put_u32(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_TYPE, HW_FLOW_FIELD_REF_ATTR_TYPE_U64);
		nla_put_u64(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_VALUE, match_value);
		nla_put_u64(msg->nlbuf, HW_FLOW_FIELD_REF_ATTR_MASK, -1);
	} else {
		printf("Warning greater than 64 bitwidth fields are not supported\n");
		return -EINVAL;
	}

	nla_nest_end(msg->nlbuf, field);
	nla_nest_end(msg->nlbuf, matches);

	actions = nla_nest_start(msg->nlbuf, HW_FLOW_FLOW_ATTR_ACTIONS);
	action = nla_nest_start(msg->nlbuf, HW_FLOW_ACTION);

	nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ATTR_UID, a->uid);
	signatures = nla_nest_start(msg->nlbuf, HW_FLOW_ACTION_ATTR_SIGNATURE);

	for (i = 0; a->args && a->args[i].type; i++) {
		struct hw_flow_action_arg *arg = &a->args[i];

		signature = nla_nest_start(msg->nlbuf, HW_FLOW_ACTION_ARG);

		nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ARG_TYPE, arg->type);
		switch (arg->type) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ARG_VALUE, arg->value_u8);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ARG_VALUE, arg->value_u16);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ARG_VALUE, arg->value_u32);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			nla_put_u32(msg->nlbuf, HW_FLOW_ACTION_ARG_VALUE, arg->value_u64);
			break;
		default:
			break;
		}
		nla_nest_end(msg->nlbuf, signature);
	}
	nla_nest_end(msg->nlbuf, signatures);

	nla_nest_end(msg->nlbuf, action);
	nla_nest_end(msg->nlbuf, actions);

	nla_nest_end(msg->nlbuf, flow);
	nla_nest_end(msg->nlbuf, deprecated_flows);
	nla_nest_end(msg->nlbuf, flows);

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

int flow_send_recv(bool verbose, int pid, int family, int ifindex, int cmd, int tableid)
{
	struct flow_msg *msg;

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER_TYPE, FLOW_TABLE_IDENTIFIER_IFINDEX);
	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER, ifindex);

	if (cmd == FLOW_TABLE_CMD_GET_FLOWS) {
		struct nlattr *f = nla_nest_start(msg->nlbuf, FLOW_TABLE_FLOWS);

		if (!f) {
			fprintf(stderr, "Error: get_flows attributes failed\n");
			return -ENOMSG;
		}

		nla_put_u32(msg->nlbuf, FLOW_TABLE_FLOWS_TABLE, tableid);
		nla_nest_end(msg->nlbuf, f);
	}

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

int main(int argc, char **argv)
{
	int cmd = FLOW_TABLE_CMD_GET_TABLES;
	int family, err, ifindex, pid = 0;
	bool resolve_names = true;
	struct nl_sock *fd;
	int tableid = 0;
	int opt;
	int args = 2;

	if (argc < 2) {
		flow_usage();
		return 0;
	}

	while ((opt = getopt(argc, argv, "p:h")) != -1) {
		switch (opt) {
		case 'h':
			flow_usage();
			exit(-1);
		case 'p':
			pid = atoi(optarg);
			args+=2;
			break;
		}
	}

	if (argc > 2) {
		if (strcmp(argv[args], "get_tables") == 0) {
			cmd = FLOW_TABLE_CMD_GET_TABLES;
		} else if (strcmp(argv[args], "get_headers") == 0) {
			resolve_names = false;
			cmd = FLOW_TABLE_CMD_GET_HEADERS;
		} else if (strcmp(argv[args], "get_actions") == 0) {
			resolve_names = false;
			cmd = FLOW_TABLE_CMD_GET_ACTIONS;
		} else if (strcmp(argv[args], "get_graph") == 0) {
			cmd = FLOW_TABLE_CMD_GET_TABLE_GRAPH;
		} else if (strcmp(argv[args], "get_flows") == 0) {
			cmd = FLOW_TABLE_CMD_GET_FLOWS;
			if (argc < 4) {
				flow_usage();
				return -1;
			}
			tableid = atoi(argv[args+1]);
		} else if (strcmp(argv[args], "set_flow") == 0) {
			cmd = FLOW_TABLE_CMD_SET_FLOWS;
		} else {
			flow_usage();	
			return 0;
		}
	}

	/* Build cache to translate netdev's to names */
	fd = nl_socket_alloc();
	if ((err = nl_connect(fd, NETLINK_ROUTE)) < 0) {
		nl_perror(err, "Unable to connect socket\n");
		return err;
	}

	if ((err = rtnl_link_alloc_cache(fd, AF_UNSPEC, &link_cache)) < 0) {
		nl_perror(err, "Unable to allocate cache\n");
		return err;
	}
	if (!(ifindex = rtnl_link_name2i(link_cache, argv[args-1]))) {
		fprintf(stderr, "Unable to lookup %s\n", argv[args-1]);
		flow_usage();
		return -1;
	}

	nl_close(fd);
	nl_socket_free(fd);
	
	/* Get the family */
	fd = nl_socket_alloc();
	genl_connect(fd);

	family = genl_ctrl_resolve(fd, FLOW_TABLE_GENL_NAME);
	if (family < 0) {
		printf("Can not resolve family FLOW_TABLE\n");
		goto out;
	}
	nl_close(fd);
	nl_socket_free(fd);

	if (resolve_names) {
		err = flow_send_recv(false, pid, family, ifindex, FLOW_TABLE_CMD_GET_HEADERS, 0);
		if (err)
			goto out;
		err = flow_send_recv(false, pid, family, ifindex, FLOW_TABLE_CMD_GET_ACTIONS, 0);
		if (err)
			goto out;
		err = flow_send_recv(false, pid, family, ifindex, FLOW_TABLE_CMD_GET_TABLES, 0);
		if (err)
			goto out;
	}

	switch (cmd) {
	case FLOW_TABLE_CMD_SET_FLOWS:
		flow_set_send(true, pid, family, ifindex, argc, argv);
		break;
	default:
		flow_send_recv(true, pid, family, ifindex, cmd, tableid);
		break;
	}
out:
	nl_close(fd);
	nl_socket_free(fd);	
	return 0;
}
