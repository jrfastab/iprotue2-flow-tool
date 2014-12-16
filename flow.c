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
#include <inttypes.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>

#include <linux/if_ether.h>

#include "include/if_flow.h"
#include "include/flowlib.h"

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

static struct nla_policy flow_get_tables_policy[NET_FLOW_MAX+1] = {
	[NET_FLOW_IDENTIFIER_TYPE] = { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]	= { .type = NLA_U32 },
	[NET_FLOW_TABLES]	= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]	= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS] 	= { .type = NLA_NESTED },
	[NET_FLOW_HEADER_GRAPH]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH]	= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]	= { .type = NLA_NESTED },
};

struct nl_cache *link_cache;

static int flow_table_cmd_to_type(FILE *fp, bool p, int valid, struct nlattr *tb[])
{
	int ifindex, type;
	char iface[NET_FLOW_NAMSIZ];

	if (!tb[NET_FLOW_IDENTIFIER_TYPE]) {
		fprintf(stderr, "Warning: received flow msg without identifier type!\n");
		return -EINVAL;
	}
	if (!tb[NET_FLOW_IDENTIFIER]) {
		fprintf(stderr, "Warning: received flow msg without identifier!\n");
		return -EINVAL;
	}

	if (valid > 0 && !tb[valid]){
		fprintf(stderr, "Warning received cmd without valid attribute expected %i\n", valid);
		return -ENOMSG;
	}

	if (nla_len(tb[NET_FLOW_IDENTIFIER_TYPE]) < sizeof(type)) {
		fprintf(stderr, "Warning invalid identifier type len\n");
		return -EINVAL;
	}
	type = nla_get_u32(tb[NET_FLOW_IDENTIFIER_TYPE]);

	switch (type) {
	case NET_FLOW_IDENTIFIER_IFINDEX:
		ifindex = nla_get_u32(tb[NET_FLOW_IDENTIFIER]);
		rtnl_link_i2name(link_cache, ifindex, iface, NET_FLOW_NAMSIZ);
		pfprintf(fp, p, "%s (%i):\n", iface, ifindex);
		break;
	default:
		fprintf(stderr, "Unknown interface identifier type %i, abort\n", type);
		return -EINVAL;
	}

	return 0;
}

static void flow_table_cmd_get_tables(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, NET_FLOW_TABLES, tb))
		return;

	if (tb[NET_FLOW_TABLES])
		flow_get_tables(stdout, verbose, tb[NET_FLOW_TABLES], NULL);
}

static void flow_table_cmd_get_headers(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, NET_FLOW_HEADERS, tb))
		return;

	if (tb[NET_FLOW_HEADERS])
		flow_get_headers(stdout, verbose, tb[NET_FLOW_HEADERS], NULL);
}

static void flow_table_cmd_get_actions(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, NET_FLOW_ACTIONS, tb))
		return;

	if (tb[NET_FLOW_ACTIONS])
		flow_get_actions(stdout, verbose, tb[NET_FLOW_ACTIONS], NULL);
}

static void flow_table_cmd_get_headers_graph(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, NET_FLOW_HEADER_GRAPH, tb))
		return;

	if (tb[NET_FLOW_HEADER_GRAPH])
		flow_get_hdrs_graph(stdout, verbose, tb[NET_FLOW_HEADER_GRAPH], NULL);
}

static void flow_table_cmd_get_table_graph(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(stdout, false, NET_FLOW_TABLE_GRAPH, tb))
		return;

	if (tb[NET_FLOW_TABLE_GRAPH])
		flow_get_tbl_graph(stdout, verbose, tb[NET_FLOW_TABLE_GRAPH], NULL);
}

/* TBD support flow ranges */
#if 0
static
struct nla_policy flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1] = {
	[NET_FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};
#endif

static void flow_table_cmd_get_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get flows msg\n");
		return;
	}

	err = flow_table_cmd_to_type(stdout, false, 0, tb);
	if (err == -ENOMSG) {
		fprintf(stdout, "Table empty\n");
		return;
	} else if (err) {
		fprintf(stderr, "Warning recevied cmd without valid attribute expected %i\n", NET_FLOW_FLOWS);
		return;
	}

	if (tb[NET_FLOW_FLOWS])
		flow_get_flows(stdout, verbose, tb[NET_FLOW_FLOWS], NULL);
}

void handle_flow_set_error(struct flow_msg *amsg, struct flow_msg *msg, int err)
{
	if (err)
		fprintf(stderr, "Error, set flow aborted: %s\n", strerror(err));

	return;
}

static void flow_table_cmd_set_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse set flows msg\n");
		return;
	}

	err = flow_table_cmd_to_type(stdout, false, -1, tb);
	if (err)
		return;

	if (tb[NET_FLOW_FLOWS]) {
		fprintf(stderr, "Failed to set:\n");
		flow_get_flows(stdout, verbose, tb[NET_FLOW_FLOWS], NULL);
	} else {
		fprintf(stderr, "Completed sucessfully\n");
	}
}

static void flow_table_cmd_del_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse del flows msg\n");
		return;
	}

	fprintf(stderr, "delete flow cmd not supported\n");
}

static void flow_table_cmd_update_flows(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse update tables msg\n");
		return;
	}
	fprintf(stderr, "update flow cmd not supported\n");
}

static void flow_table_cmd_create_table(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse create table msg\n");
		return;
	}
}

static void flow_table_cmd_destroy_table(struct flow_msg *msg, int verbose)
{
	struct nlmsghdr *nlh = msg->msg;
	struct nlattr *tb[NET_FLOW_MAX+1];
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse destroy table msg\n");
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
	
	if (type < 0 || type > NET_FLOW_CMD_MAX) {
		fprintf(stderr, "Received message of unknown type %d\n", type);
		free_flow_msg(msg);
		return NULL;
	}

	return msg;	
}

static void(*type_cb[NET_FLOW_CMD_MAX+1])(struct flow_msg *, int verbose) = {
	flow_table_cmd_get_tables,
	flow_table_cmd_get_headers,
	flow_table_cmd_get_actions,
	flow_table_cmd_get_headers_graph,
	flow_table_cmd_get_table_graph,
	flow_table_cmd_get_flows,
	flow_table_cmd_set_flows,
	flow_table_cmd_del_flows,
	flow_table_cmd_update_flows,
	flow_table_cmd_create_table,
	flow_table_cmd_destroy_table,
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
	fprintf(stdout, "flow [-p pid] [-f family] [-i dev]\n");
	fprintf(stdout, "           [get_tables | get_headers | get_actions | get_flows <table> | get_graph | set_flow | del_flow | create | destroy]\n");
}

void set_flow_usage()
{
	printf("flow dev set_flow prio <num> handle <num> table <id>  match <name> action <name arguments>\n");
}

#define NEXT_ARG() do { argv++; if (--argc <= 0) break; } while(0)

int get_match_arg(int argc, char **argv, bool need_value, bool need_mask_type,
		  struct net_flow_field_ref *match)
{
	char *strings, *instance, *s_fld;
	struct net_flow_hdr_node *hdr_node;
	struct net_flow_field *field;
	int advance = 0, err = 0;

	NEXT_ARG();
	strings = *argv;
	advance++;

	/* We use the instance name followed by the field in that instance
	 * to setup a flow rule. The instance name must be used to avoid
	 * ambiguity when a packet parser can support multiple stacked
	 * headers or tunnels and other such packets with multiples of the
	 * same header. This means here we have to unwind the string name
	 * from the user into a correct header_node and field nodes.
	 */
	instance = strtok(strings, ".");
	if (!instance)
		return -EINVAL;

	s_fld = strtok(NULL, ".");
	if (!s_fld)
		return -EINVAL;

	match->instance = find_header_node(instance);
	if (match->instance < 0)
		return -EINVAL;

	hdr_node = get_graph_node(match->instance);	
	if (!hdr_node) /* with an abundance of caution */
		return -EINVAL;

	/* For now only support parsing single header per node. Its not
	 * very clera what it means to support multiple header types or
	 * how we would infere the correct one. It might be best to
	 * codify the single header _only_ case. Also we require that
	 * hdrs be a valid pointer. Being overly cautious we check for
	 * it though.
	 */ 

	if (!hdr_node->hdrs)
		return -EINVAL;

	match->header = hdr_node->hdrs[0];
	match->field = find_field(s_fld, match->header);
	if (match->field < 0)
		return -EINVAL;

	field = get_fields(match->header, match->field);
	if (!field)
		return -EINVAL;

	if (need_mask_type) {
		advance++;
		NEXT_ARG();
		if (strcmp(*argv, "lpm") == 0)
			match->mask_type = NET_FLOW_MASK_TYPE_LPM;
		else if (strcmp(*argv, "exact") == 0)
			match->mask_type = NET_FLOW_MASK_TYPE_EXACT;
		else
			return -EINVAL;
	}

	if (!need_value)
		return advance;

	NEXT_ARG();
	if (field->bitwidth <= 8) {
		match->type = NET_FLOW_FIELD_REF_ATTR_TYPE_U8;
		err = sscanf(*argv, "0x%02x", &match->value_u8);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu8 "", &match->value_u8);
	} else if (field->bitwidth <= 16) {
		match->type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16;
		err = sscanf(*argv, "0x%04x" SCNu16 "", &match->value_u16);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu16 "", &match->value_u16);
	} else if (field->bitwidth <= 32) {
		match->type = NET_FLOW_FIELD_REF_ATTR_TYPE_U32;
		err = sscanf(*argv, "0x%08x" SCNu32 "", &match->value_u32);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu32 "", &match->value_u32);
	} else if (field->bitwidth <= 64) {
		errno = 0;
		match->type = NET_FLOW_FIELD_REF_ATTR_TYPE_U64;
		err = sscanf(*argv, "0x%016x" SCNu64 "", &match->value_u64);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu64 "", &match->value_u64);
	}
	advance++;

	if (err != 1)
		return err;

	NEXT_ARG(); /* need a mask if its not an exact match */
	switch (match->type) {
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U8:
		err = sscanf(*argv, "0x%02x", &match->mask_u8);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu8 "", &match->mask_u8);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U16:
		err = sscanf(*argv, "0x%04x", &match->mask_u16);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu16 "", &match->mask_u16);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U32:
		err = sscanf(*argv, "0x%08x", &match->mask_u32);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu32 "", &match->mask_u32);
		break;
	case NET_FLOW_FIELD_REF_ATTR_TYPE_U64:
		errno = 0;
		
		err = ll_addr_a2n((char *)&match->mask_u64, ETH_ALEN, *argv);
		if (err < ETH_ALEN)
			err = sscanf(*argv, "0x%016x", &match->mask_u64);
		if (err != 1)
			err = sscanf(*argv, "%" SCNu64 "", &match->mask_u64);
	}

	if (err != 1)
		return err;

	advance++;
	return advance;
}

int get_action_arg(int argc, char **argv, bool need_args,
		   struct net_flow_action *action)
{
	struct net_flow_action *a;
	int i, reqs_args = 0;
	int err, advance = 0;
	char *endptr;

	NEXT_ARG();
	advance++;

	i = find_action(*argv);
	if (i < 0) {
		fprintf(stderr, "Warning unknown action\n");
		return -EINVAL;
	}

	a = get_actions(i);
	for (i = 0; a->args && a->args[i].type; i++)
		reqs_args++;

	strncpy(action->name, a->name, NET_FLOW_NAMSIZ - 1);
	action->uid = a->uid;
	if (!reqs_args || !need_args)
		goto done;

	action->args = calloc(reqs_args + 1, sizeof(struct net_flow_action_arg));

	for (i = 0; i <= reqs_args; i++) {
		strncpy(action->args[i].name, a->args[i].name, NET_FLOW_NAMSIZ);
		action->args[i].type = a->args[i].type;

		if (a->args[i].type) {
			NEXT_ARG();
			advance++;
		}

		switch (a->args[i].type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			err = sscanf(*argv, "0x%02x", &action->args[i].value_u8);
			if (err != 1)
				err = sscanf(*argv, "%" PRIu8 "", &action->args[i].value_u8);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			err = sscanf(*argv, "0x%04x", &action->args[i].value_u16);
			if (err != 1)
				err = sscanf(*argv, "%" PRIu16 "", &action->args[i].value_u16);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			err = sscanf(*argv, "0x%08x", &action->args[i].value_u32);
			if (err != 1)
				err = sscanf(*argv, "%" PRIu32 "", &action->args[i].value_u32);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			errno = 0;
			action->args[i].value_u64 = strtol(*argv, &endptr, 10);
			if (errno)
				err = -EINVAL;
			else
				err = 1;
			break;
		case NET_FLOW_ACTION_ARG_TYPE_NULL:
			break;
		}

		if (err != 1)
			return -EINVAL;
	}

done:
	return advance;
}

#define MAX_MATCHES	10
#define MAX_ACTIONS	10

static void set_table_usage()
{
	fprintf(stdout, "\nflow dev create source <id> name <name> [id <id>] size <size> [match ...] [action ...]\n");
	fprintf(stdout, "     match : [header_instance].[field] [mask_type]\n");
	fprintf(stdout, "     mask_type : lpm|exact\n");
	fprintf(stdout, "     action : action_name\n");
}

static void del_table_usage()
{
	fprintf(stdout, "flow dev destroy source <id> [name <name> | id <id>]\n");
}

int flow_destroy_tbl_send(int verbose, int pid, int family, int ifindex, int argc, char **argv)
{
	int cmd = NET_FLOW_TABLE_CMD_DESTROY_TABLE;
	struct net_flow_table table = {.name = "", .uid = 0};
	struct nlattr *nest, *nest1;
	struct flow_msg *msg;
	int err = 0;

	while (argc > 0) {
		if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			strncpy(table.name, *argv, NET_FLOW_NAMSIZ - 1);
			table.uid = get_table_id(table.name);	
		} else if (strcmp(*argv, "source") == 0) {
			NEXT_ARG();
			table.source = atoi(*argv);
		} else if (strcmp(*argv, "id") == 0) {
			NEXT_ARG();
			table.uid = atoi(*argv);	
		}
		argc--; argv++;
	}

	if (err) {
		printf("Invalid argument\n");
		del_table_usage();
		exit(-1);
	}

	if (!table.uid) {
		if (strncmp(table.name, "", NET_FLOW_NAMSIZ))
			fprintf(stderr, "Unknown table name %s\n", table.name);
		else
			fprintf(stderr, "Unknown table id %i\n", table.uid);

		del_table_usage();
		exit(-1);
	}

	if (!table.source) {
		fprintf(stderr, "Missing table <source> specifier.\n");
		del_table_usage();
		exit(-1);
	}

	pp_table(stdout, true, &table);

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		return -EMSGSIZE;
	}

	nest = nla_nest_start(msg->nlbuf, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;
	nest1 = nla_nest_start(msg->nlbuf, NET_FLOW_TABLE);
	flow_put_table(msg->nlbuf, &table);
	nla_nest_end(msg->nlbuf, nest1);
	nla_nest_end(msg->nlbuf, nest);

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;

}

int flow_create_tbl_send(int verbose, int pid, int family, int ifindex, int argc, char **argv)
{
	struct nlattr *nest, *nest1;
	struct net_flow_field_ref matches[MAX_MATCHES];
	int acts[MAX_ACTIONS];
	int match_count = 0, action_count = 0;
	struct flow_msg *msg;
	int err = 0, advance = 0;
	int cmd = NET_FLOW_TABLE_CMD_CREATE_TABLE;
	struct net_flow_table table;

	memset(&table, 0, sizeof(table));
	memset(matches, 0, sizeof(struct net_flow_field_ref) * MAX_ACTIONS);
	memset(acts, 0, sizeof(int) * MAX_ACTIONS);
	table.matches = &matches[0];
	table.actions = &acts[0];

	opterr = 0;
	while (argc > 0) {
		if (strcmp(*argv, "match") == 0) {
			advance = get_match_arg(argc, argv, false, true, &matches[match_count]);
			if (advance < 0)
				break;
			match_count++;
			for (; advance; advance--)
				NEXT_ARG();
		} else if (strcmp(*argv, "action") == 0) {
			struct net_flow_action a;

			advance = get_action_arg(argc, argv, false, &a);
			if (advance < 0)
				break;
			acts[action_count] = a.uid;
			action_count++;
			for (; advance; advance--)
				NEXT_ARG();
		} else if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			strncpy(table.name, *argv, NET_FLOW_NAMSIZ - 1);
		} else if (strcmp(*argv, "source") == 0) {
			NEXT_ARG();
			table.source = atoi(*argv);
		} else if (strcmp(*argv, "id") == 0) {
			NEXT_ARG();
			table.uid = atoi(*argv);	
		} else if (strcmp(*argv, "size") == 0) {
			NEXT_ARG();
			table.size = atoi(*argv);
		}
		argc--; argv++;
	}

	if (err) {
		printf("Invalid argument\n");
		set_table_usage();
		exit(-1);
	}

	if (!table.uid) {
		table.uid = gen_table_id();
		if (table.uid < 0) {
			fprintf(stderr, "Could not generate unique table id! Too many tables\n");
			exit(-1);
		}
	}

	if (!table.size) {
		fprintf(stderr, "Missing table <size> specifier.\n");
		set_table_usage();
		exit(-1);
	}

	if (!table.source) {
		fprintf(stderr, "Missing table <source> specifier.\n");
		set_table_usage();
		exit(-1);
	}

	if (!table.matches[0].header) {
		fprintf(stderr, "Table has NULL <match> specifier. Aborting this doesn't appear useful\n");
		set_table_usage();
		exit(-1);
	}

	if (!table.matches[0].mask_type) {
		fprintf(stderr, "Table has missing mask_type specifier. Valid entries (lpm, exact). Aborting.\n");
		set_table_usage();
		exit(-1);
	}

	if (!table.actions[0]) {
		fprintf(stderr, "Table has NULL <action> specifier. Aborting this doesn't appear useful\n");
		set_table_usage();
		exit(-1);
	}

	if (strncmp(table.name, "", NET_FLOW_NAMSIZ) == 0) {
		fprintf(stderr, "Table has NULL <name> specifier. Please name table\n");
		set_table_usage();
		exit(-1);
	}

	pp_table(stdout, true, &table);

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		return -EMSGSIZE;
	}

	nest = nla_nest_start(msg->nlbuf, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;
	nest1 = nla_nest_start(msg->nlbuf, NET_FLOW_TABLE);
	flow_put_table(msg->nlbuf, &table);
	nla_nest_end(msg->nlbuf, nest1);
	nla_nest_end(msg->nlbuf, nest);

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

void del_flow_usage()
{
	printf("flow dev del_flow handle <num> table <id>\n");
}

int flow_del_send(int verbose, int pid, int family, int ifindex, int argc, char **argv)
{
	struct net_flow_flow flow = {0};
	struct flow_msg *msg;
	struct nlattr *flows;
	int cmd = NET_FLOW_TABLE_CMD_DEL_FLOWS;

	while (argc > 0) {
		if (strcmp(*argv, "prio") == 0) {
			NEXT_ARG();
			flow.priority = atoi(*argv);
		} else if (strcmp(*argv, "handle") == 0) {
			NEXT_ARG();
			flow.uid = atoi(*argv);
		} else if (strcmp(*argv, "table") == 0) {
			NEXT_ARG();
			flow.table_id = atoi(*argv);
		}
		argc--; argv++;
	}

	if (!flow.table_id) {
		fprintf(stderr, "Table ID requried\n");	
		del_flow_usage();
		exit(-1);
	}

	if (!flow.uid) {
		fprintf(stderr, "Flow ID requried\n");	
		del_flow_usage();
		exit(-1);
	}

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		return -EMSGSIZE;
	}

	flows = nla_nest_start(msg->nlbuf, NET_FLOW_FLOWS);
	if (!flows)
		return -EMSGSIZE;
	flow_put_flow(msg->nlbuf, &flow);
	nla_nest_end(msg->nlbuf, flows);

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

int flow_set_send(int verbose, int pid, int family, int ifindex, int argc, char **argv)
{
	struct net_flow_field_ref matches[MAX_MATCHES];
	struct net_flow_action acts[MAX_ACTIONS];
	int match_count = 0, action_count = 0;
	struct flow_msg *msg;
	int advance = 0;
	int cmd = NET_FLOW_TABLE_CMD_SET_FLOWS;
	int err = 0;
	struct net_flow_flow flow;
	struct nlattr *flows;

	memset(&flow, 0, sizeof(flow));
	memset(matches, 0, sizeof(struct net_flow_field_ref) * MAX_ACTIONS);
	memset(acts, 0, sizeof(struct net_flow_action) * MAX_ACTIONS);
	flow.matches = &matches[0];
	flow.actions = &acts[0];

	opterr = 0;
	while (argc > 0) {
		if (strcmp(*argv, "match") == 0) {
			advance = get_match_arg(argc, argv, true, false, &matches[match_count]);
			if (advance < 0)
				break;
			match_count++;
			for (; advance; advance--)
				NEXT_ARG();
		} else if (strcmp(*argv, "action") == 0) {
			advance = get_action_arg(argc, argv, true, &acts[action_count]);
			if (advance < 0)
				break;
			action_count++;
			for (; advance; advance--)
				NEXT_ARG();
		} else if (strcmp(*argv, "prio") == 0) {
			NEXT_ARG();
			flow.priority = atoi(*argv);
		} else if (strcmp(*argv, "handle") == 0) {
			NEXT_ARG();
			flow.uid = atoi(*argv);
		} else if (strcmp(*argv, "table") == 0) {
			NEXT_ARG();
			flow.table_id = atoi(*argv);
		}
		argc--; argv++;
	}

	if (err) {
		printf("Invalid argument\n");
		set_flow_usage();
		exit(-1);
	}

	if (!flow.table_id) {
		fprintf(stderr, "Table ID requried\n");	
		set_flow_usage();
		exit(-1);
	}

	if (!flow.priority)
		flow.priority = 1;

	if (!flow.uid)
		flow.uid = 10;	

	pp_flow(stdout, true, &flow);

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		return -EMSGSIZE;
	}

	err = flow_put_flow_error(msg->nlbuf, NET_FLOW_FLOWS_ERROR_CONT_LOG);
	if (err)
		return err;

	flows = nla_nest_start(msg->nlbuf, NET_FLOW_FLOWS);
	if (!flows)
		return -EMSGSIZE;
	flow_put_flow(msg->nlbuf, &flow);
	nla_nest_end(msg->nlbuf, flows);

	set_ack_cb(msg, handle_flow_set_error);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

int flow_send_recv(int verbose, int pid, int family, int ifindex, int cmd, int tableid)
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

	nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(msg->nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	if (cmd == NET_FLOW_TABLE_CMD_GET_FLOWS) {
		struct nlattr *f = nla_nest_start(msg->nlbuf, NET_FLOW_FLOWS);

		if (!f) {
			fprintf(stderr, "Error: get_flows attributes failed\n");
			return -ENOMSG;
		}

		nla_put_u32(msg->nlbuf, NET_FLOW_TABLE_FLOWS_TABLE, tableid);
		nla_nest_end(msg->nlbuf, f);
	}

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send_auto(nsd, msg->nlbuf);
	process_rx_message(verbose);

	return 0;
}

int main(int argc, char **argv)
{
	int cmd = NET_FLOW_TABLE_CMD_GET_TABLES;
	int family = -1, err, ifindex = 0, pid = 0;
	int tableid = 0, verbose = 1;
	bool resolve_names = true;
	struct nl_sock *fd;
	int opt;
	int args = 1;
	char *ifname = NULL;
	char *tablestr = NULL;
	char *endptr;

	if (argc < 2) {
		flow_usage();
		return 0;
	}

	while ((opt = getopt(argc, argv, "i:p:f:hsg")) != -1) {
		switch (opt) {
		case 'h':
			flow_usage();
			exit(-1);
		case 'p':
			pid = atoi(optarg);
			args+=2;
			break;
		case 'f':
			family = atoi(optarg);
			args+=2;
			break;
		case 'i':
			ifname = optarg;
			args+=2;
			break;
		case 'g':
			verbose = PRINT_GRAPHVIZ;
			args++;
			break;
		case 's':
			verbose = 0;
			args++;
			break;
		}
	}

	if (argc > 2) {
		if (strcmp(argv[args], "get_tables") == 0) {
			cmd = NET_FLOW_TABLE_CMD_GET_TABLES;
		} else if (strcmp(argv[args], "get_headers") == 0) {
			resolve_names = false;
			cmd = NET_FLOW_TABLE_CMD_GET_HEADERS;
		} else if (strcmp(argv[args], "get_header_graph") == 0) {
			cmd = NET_FLOW_TABLE_CMD_GET_HDR_GRAPH;
		} else if (strcmp(argv[args], "get_actions") == 0) {
			resolve_names = false;
			cmd = NET_FLOW_TABLE_CMD_GET_ACTIONS;
		} else if (strcmp(argv[args], "get_graph") == 0) {
			cmd = NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH;
		} else if (strcmp(argv[args], "get_flows") == 0) {
			cmd = NET_FLOW_TABLE_CMD_GET_FLOWS;
			if (args + 1 >= argc) {
				flow_usage();
				return -1;
			}
			tableid = strtol(argv[args+1], &endptr, 0);
			if (tableid <= 0)
				tablestr = argv[args+1];
		} else if (strcmp(argv[args], "set_flow") == 0) {
			cmd = NET_FLOW_TABLE_CMD_SET_FLOWS;
		} else if (strcmp(argv[args], "del_flow") == 0) {
			cmd = NET_FLOW_TABLE_CMD_DEL_FLOWS;
		} else if (strcmp(argv[args], "create") == 0) {
			cmd = NET_FLOW_TABLE_CMD_CREATE_TABLE;
		} else if (strcmp(argv[args], "destroy") == 0) {
			cmd = NET_FLOW_TABLE_CMD_DESTROY_TABLE;
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

	if (ifname) {
		if (!(ifindex = rtnl_link_name2i(link_cache, ifname))) {
			fprintf(stderr, "Unable to lookup %s\n", ifname);
			flow_usage();
			return -1;
		}
	}

	nl_close(fd);
	nl_socket_free(fd);
	
	/* Get the family */
	if (family < 0) {
		fd = nl_socket_alloc();
		genl_connect(fd);

		family = genl_ctrl_resolve(fd, NET_FLOW_GENL_NAME);
		if (family < 0) {
			printf("Can not resolve family FLOW_TABLE\n");
			goto out;
		}
		nl_close(fd);
		nl_socket_free(fd);
	}

	if (resolve_names) {
		err = flow_send_recv(0, pid, family, ifindex, NET_FLOW_TABLE_CMD_GET_HEADERS, 0);
		if (err)
			goto out;
		err = flow_send_recv(0, pid, family, ifindex, NET_FLOW_TABLE_CMD_GET_ACTIONS, 0);
		if (err)
			goto out;
		err = flow_send_recv(0, pid, family, ifindex, NET_FLOW_TABLE_CMD_GET_TABLES, 0);
		if (err)
			goto out;
		err = flow_send_recv(0, pid, family, ifindex, NET_FLOW_TABLE_CMD_GET_HDR_GRAPH, 0);
		if (err)
			goto out;
	}

	switch (cmd) {
	case NET_FLOW_TABLE_CMD_SET_FLOWS:
		flow_set_send(verbose, pid, family, ifindex, argc, argv);
		break;
	case NET_FLOW_TABLE_CMD_DEL_FLOWS:
		flow_del_send(verbose, pid, family, ifindex, argc, argv);
		break;
	case NET_FLOW_TABLE_CMD_CREATE_TABLE:
		flow_create_tbl_send(verbose, pid, family, ifindex, argc, argv);
		break;
	case NET_FLOW_TABLE_CMD_DESTROY_TABLE:
		flow_destroy_tbl_send(verbose, pid, family, ifindex, argc, argv);
		break;
	case NET_FLOW_TABLE_CMD_GET_FLOWS:
		if (tableid <= 0) {
			tableid = find_table(tablestr);	
			if (tableid < 0)
			exit (-1);
		}
		flow_send_recv(verbose, pid, family, ifindex, cmd, tableid);
		break;
	default:
		flow_send_recv(verbose, pid, family, ifindex, cmd, tableid);
		break;
	}
out:
	nl_close(fd);
	nl_socket_free(fd);	
	return 0;
}
