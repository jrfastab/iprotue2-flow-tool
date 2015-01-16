/*******************************************************************************

  Flowd - Test program for flow API 
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
#include <libnl3/netlink/cli/utils.h>

#include <unistd.h>

#include "../include/if_flow.h"
#include "../include/flowlib.h"
#include "models/better_pipeline.h" /* Pipeline model */

#define FLOWD_MOCK_SUPPORT 1

#ifdef FLOWD_MOCK_SUPPORT
/* Allocate a software cache of the flow tables so we can
 * get and set flow entries in software only mode.
 */
#define MAX_MOCK_TABLES	50
struct net_flow_flow *flowd_mock_tables[MAX_MOCK_TABLES + 1];
#endif

/* Used as a hook for software cache of flow tables */
struct net_flow_tbl my_dyn_table_list[MAX_MOCK_TABLES];

/* The family id can be learned either via a kernel query or by
 * specifying the id on the command line.
 */
int family = -1;
struct nl_sock *nsd;

static struct nl_msg *flow_alloc_msg(struct nlmsghdr *nlh, uint32_t type, uint16_t flags, size_t size)
{
	int seq = nlh->nlmsg_seq;
	int pid = nlh->nlmsg_pid;
	struct nl_msg *nlbuf;
	struct nl_sock *fd;
	void *hdr;

	/* Get the family */
	fd = nl_socket_alloc();
	genl_connect(fd);

	if (family < 0) {
		family = genl_ctrl_resolve(fd, NET_FLOW_GENL_NAME);
		if (family < 0) {
			fprintf(stderr, "Can not resolve family NET_FLOW_TABLE\n");
			return NULL;
		}
	}

	nl_close(fd);
	nl_socket_free(fd);

	nlbuf = nlmsg_alloc();
	if (!nlbuf)
		return NULL;

	hdr = genlmsg_put(nlbuf, 0, seq, family, size, flags, type, 1);
	if (!hdr) {
		nlmsg_free(nlbuf);
		return NULL;
	}

	if (pid) {
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
			.nl_pid = nlh->nlmsg_pid,
			.nl_groups = 0,
		};

		nlmsg_set_dst(nlbuf, &nladdr);
	}

	return nlbuf;
}

static struct nla_policy flow_get_tables_policy[NET_FLOW_MAX+1] = {
	[NET_FLOW_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_FLOW_TABLES]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]		= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS] 		= { .type = NLA_NESTED },
	[NET_FLOW_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH] 		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]		= { .type = NLA_NESTED },
};

static int flow_cmd_get_tables(struct nlmsghdr *nlh)
{
	struct nlattr *nest, *t, *tb[NET_FLOW_MAX+1];
	int i, err, ifindex = 0;
	struct nl_msg *nlbuf;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_TABLES, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);
	
	nest = nla_nest_start(nlbuf, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;
	for (i = 0; i < MAX_MOCK_TABLES; i++) {
		if (my_dyn_table_list[i].uid < 1)
			continue;

		t = nla_nest_start(nlbuf, NET_FLOW_TABLE);
		err = flow_put_table(nlbuf, &my_dyn_table_list[i]);
		if (err)
			return err;
		nla_nest_end(nlbuf, t);
	}
	nla_nest_end(nlbuf, nest);
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_get_headers(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_FLOW_MAX+1];
	struct nl_msg *nlbuf;
	int err, ifindex = 0;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_HEADERS, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	err = flow_put_headers(nlbuf, my_header_list);
	if (err) {
		fprintf(stderr, "Warning failed to pack headers.\n");
		return err;
	}
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_get_actions(struct nlmsghdr *nlh)
{
	struct nlattr *actions, *tb[NET_FLOW_MAX+1];
	struct nl_msg *nlbuf;
	int i, err, ifindex = 0;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_ACTIONS, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	actions = nla_nest_start(nlbuf, NET_FLOW_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (i = 0; my_action_list[i]->uid; i++) {
		err = flow_put_action(nlbuf, my_action_list[i]);
		if (err)
			return err;
	}
	nla_nest_end(nlbuf, actions);
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_get_header_graph(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_FLOW_MAX+1];
	struct nl_msg *nlbuf;
	int err, ifindex = 0;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_HDR_GRAPH, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	flow_put_header_graph(nlbuf, my_hdr_nodes);
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_get_table_graph(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_FLOW_MAX+1];
	struct nl_msg *nlbuf;
	int err, ifindex = 0;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	flow_put_table_graph(nlbuf, my_tbl_nodes);
	return nl_send_auto(nsd, nlbuf);
}

static struct nla_policy flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1] = {
	[NET_FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

static int flow_cmd_get_flows(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_FLOW_MAX+1];
	int table = 0, min = 0, max = 0;
	int err, ifindex = 0;
	struct nl_msg *nlbuf;
#ifdef FLOWD_MOCK_SUPPORT
	struct net_flow_flow *flows;
	struct nlattr *nest;
	int i;
#endif

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_GET_FLOWS, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX);
	nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex);

	err = nla_parse_nested(tb, NET_FLOW_TABLE_FLOWS_MAX, tb[NET_FLOW_FLOWS], flow_table_flows_policy);
	if (err)
		return err;

	if (tb[NET_FLOW_TABLE_FLOWS_TABLE]) /* If missing get all tables */
		table = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_TABLE]);
	if (tb[NET_FLOW_TABLE_FLOWS_MINPRIO]) /* If missing use min = 0 */ /* TBD: prio -> should be uid */
		min = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_MINPRIO]);
	if (tb[NET_FLOW_TABLE_FLOWS_MAXPRIO]) /* If missing use max = table_sz */
		max = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_MAXPRIO]);

	//fprintf(stdout, "%s: table %i min %i max %i\n", __func__, table, min, max);

#ifdef FLOWD_MOCK_SUPPORT
	if (table > MAX_MOCK_TABLES - 1 || table < 1 || !flowd_mock_tables[table])
		return -EINVAL;

	if (!max)
		max = my_dyn_table_list[table].size;

	if (min > my_dyn_table_list[table].size ||
	    max > my_dyn_table_list[table].size || min > max)
		return -EINVAL;

	nest = nla_nest_start(nlbuf, NET_FLOW_FLOWS);
	if (!nest)
		return -EMSGSIZE;

	flows = flowd_mock_tables[table];
	for (i = min; i < max; i++) {
		if (flows[i].uid)
			flow_put_flow(nlbuf, &flows[i]);
	}
	nla_nest_end(nlbuf, nest);
#endif /* FLOWD_MOCK_SUPPORT */
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_resolve_flows(struct net_flow_flow *flow, int cmd,
				  int error_method,
				  struct nl_msg *nlbuf)
{
	int i, err = 0;

	for (i = 0; flow[i].uid; i++) {
		struct net_flow_flow *flows;
		int table = flow[i].table_id;

		if (!flowd_mock_tables[table]) {
			fprintf(stderr, "Warning, invalid flow table %i\n", table);
			err = -EINVAL;
			goto skip_add;
		}

		if (!my_dyn_table_list[table].uid) {
			fprintf(stderr, "Warning, invalid dynamic table %i\n", table);
			err = -EINVAL;
			goto skip_add;
		}

		if (flow[i].uid > my_dyn_table_list[table].size) {
			fprintf(stderr, "Warning, table overrun\n");
			err = -ENOMEM;
			goto skip_add;
		}
		flows = flowd_mock_tables[table];

		if (!flow[i].matches || !flow[i].actions) {
			fprintf(stderr, "Warning, programming NOP missing %s\n",
				flow[i].matches ? "matches" : "actions");
			err = -EINVAL;
			goto skip_add;
		}

		switch (cmd) {
		case NET_FLOW_TABLE_CMD_SET_FLOWS:
			flows[flow[i].uid] = flow[i];
			break;
		case NET_FLOW_TABLE_CMD_DEL_FLOWS:
			flows[flow[i].uid].uid = 0;
			break;
		default:
			return -EINVAL;
		}
skip_add:
		if (err) {
			switch (error_method) {
			case NET_FLOW_FLOWS_ERROR_ABORT:
				return err;
			case NET_FLOW_FLOWS_ERROR_CONTINUE:
				err = 0;
				break;
			case NET_FLOW_FLOWS_ERROR_ABORT_LOG:
				flow_put_flow(nlbuf, &flow[i]);
				goto done;
			case NET_FLOW_FLOWS_ERROR_CONT_LOG:
				err = 0;
				flow_put_flow(nlbuf, &flow[i]);
				break;
			default:
				return err;
			}
		}
	}

done:
	return err;
}

static int flow_cmd_flows(struct nlmsghdr *nlh)
{
	int error_method = NET_FLOW_FLOWS_ERROR_ABORT;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[NET_FLOW_MAX+1];
	struct net_flow_flow *flow;
	int err, ifindex = 0;
	struct nl_msg *nlbuf;

	if (glh->cmd > NET_FLOW_CMD_MAX)
		return -EOPNOTSUPP;


	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_SET_FLOWS, NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	if (nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex))
		return -EMSGSIZE;

	if (tb[NET_FLOW_FLOWS_ERROR])
		error_method = nla_get_u32(tb[NET_FLOW_FLOWS_ERROR]);

	/* Generates a null terminated list of flows for processing */
	err = flow_get_flows(stdout, true, tb[NET_FLOW_FLOWS], &flow);
	if (err) {
		fprintf(stderr, "Warning received an invlid set_flow operation\n");
		return err;
	} 

	err = flow_cmd_resolve_flows(flow, glh->cmd, error_method, nlbuf);
	if (err)
		return err;

	if (error_method < NET_FLOW_FLOWS_ERROR_CONTINUE + 1) {
		printf("%s: return err %i\n", __func__, err);
		return err;
	}
	return nl_send_auto(nsd, nlbuf);
}

static int flow_cmd_update_flows(struct nlmsghdr *nlh)
{
	return -EOPNOTSUPP;
}

static bool flow_is_dynamic_table(int uid)
{
	int i;

	for (i = 0; my_tbl_nodes[i]->uid; i++) {
		if (my_tbl_nodes[i]->uid == uid &&
		    my_tbl_nodes[i]->flags & NET_FLOW_TABLE_DYNAMIC)
			return true;
	}

	return false;
}

static int flow_cmd_table(struct nlmsghdr *nlh)
{
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[NET_FLOW_MAX+1];
	struct net_flow_tbl *tables;
	int i, err, ifindex = 0;
	struct nl_msg *nlbuf;

	nlbuf = flow_alloc_msg(nlh, NET_FLOW_TABLE_CMD_CREATE_TABLE,
			       NLM_F_REQUEST|NLM_F_ACK, 0);

	err = genlmsg_parse(nlh, 0, tb, NET_FLOW_MAX, flow_get_tables_policy);
	if (err) {
		fprintf(stderr, "Warnings genlmsg_parse failed\n");
		return -EINVAL; /* TBD need to reply with ERROR */
	}

	if (nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(nlbuf, NET_FLOW_IDENTIFIER, ifindex))
		return -EMSGSIZE;

	if (!tb[NET_FLOW_TABLES])
		return -EINVAL;

	/* Generates a null terminated list of flows for processing */
	err = flow_get_tables(stdout, false, tb[NET_FLOW_TABLES], &tables);
	if (err)
		return err;

	/*
		(* valid fields *)
		table->uid (* unique id of the table to create *)
		table->source (* where to place it *)
		table->size   (* how many rule entries *)
		table->matches (* null terminated matches it needs to support *)
		table->actions (* num terminated list of action ids *) 

	*/

	for (i = 0; tables[i].uid; i++) {
		pp_table(stdout, true, &tables[i]);

		switch (glh->cmd) {
		case NET_FLOW_TABLE_CMD_DESTROY_TABLE:
			fprintf(stdout, "destroy table\n");

			if (my_dyn_table_list[tables[i].uid].uid < 1)
				return -EINVAL;

			if (tables[i].uid > MAX_MOCK_TABLES - 1)
				return -EINVAL;

			my_dyn_table_list[tables[i].uid].uid = 0;
			free(flowd_mock_tables[tables[i].uid]);
			flowd_mock_tables[tables[i].uid] = NULL;

			break;
		case NET_FLOW_TABLE_CMD_CREATE_TABLE:
			if (tables[i].uid > MAX_MOCK_TABLES - 1) {
				fprintf(stderr, "create table request greater than max tables abort!\n");
				return -EINVAL;
			}

			if (flowd_mock_tables[tables[i].uid]) {
				fprintf(stderr, "create table request exists in mock tables abort!\n");
				return -EEXIST;
			}

			if (my_dyn_table_list[tables[i].uid].uid) {
				fprintf(stderr, "create table request exists in dyn tables abort!\n");
				return -EEXIST;
			}

			if (flow_is_dynamic_table(tables[i].source) == false) {
				fprintf(stderr, "create table requests require dynamic bit\n");
				return -EINVAL;
			}

			/* In ENOMEM case leave my_dyn_table_list allocated
			 * anticipating a retry from agent.
			 */
			flowd_mock_tables[tables[i].uid] = calloc(1 + tables[i].size, sizeof(struct net_flow_flow));
			if (!flowd_mock_tables[tables[i].uid]) {
				fprintf(stderr, "Flow table allocation failed!\n");
				return -ENOMEM;
			}

			my_dyn_table_list[tables[i].uid] = tables[i];
			break;
		default:
			fprintf(stdout, "table cmd error\n");
			break;
		}
	}

	if (glh->cmd == NET_FLOW_TABLE_CMD_CREATE_TABLE)
		flow_push_tables(tables);
	else
		flow_pop_tables(tables);
	return nl_send_auto(nsd, nlbuf);
}

static int(*type_cb[NET_FLOW_CMD_MAX+1])(struct nlmsghdr *nlh) = {
	flow_cmd_get_tables,
	flow_cmd_get_headers,
	flow_cmd_get_actions,
	flow_cmd_get_header_graph,
	flow_cmd_get_table_graph,
	flow_cmd_get_flows,
	flow_cmd_flows,
	flow_cmd_flows,
	flow_cmd_update_flows,
	flow_cmd_table,
	flow_cmd_table,
};

int rx_process(struct nlmsghdr *nlh, size_t len)
{
	struct genlmsghdr *glh = nlmsg_data(nlh);
	int type;

	if (nlh->nlmsg_type == NLMSG_ERROR)
		return -EINVAL;	

	if (glh->cmd > NET_FLOW_CMD_MAX)
		return -EOPNOTSUPP;

	type = glh->cmd;
	return type_cb[type](nlh);
}

void flowd_usage(void)
{
	fprintf(stdout, "flowd [-f family_id] [-h]\n");
}

int main(int argc, char **argv)
{
	struct sockaddr_nl dest_addr;
	int rcv_size = 2048;
	unsigned char *buf;
	int rc, err, opt;
#ifdef FLOWD_MOCK_SUPPORT
	int i;
#endif

	while ((opt = getopt(argc, argv, "f:h")) != -1) {
		switch (opt) {
		case 'h':
			flowd_usage();
			exit(-1);
		case 'f':
			family = atoi(optarg);
			break;
		default:
			flowd_usage();
			exit(-1);
		}
	}

#ifdef FLOWD_MOCK_SUPPORT
	for (i = 0; my_table_list[i]->uid; i++)
		flowd_mock_tables[i] = calloc(1 + my_table_list[i]->size, sizeof(struct net_flow_flow));
#endif

	for (i = 0; my_table_list[i]->uid; i++)
		my_dyn_table_list[my_table_list[i]->uid] = *my_table_list[i];

	/* Need to populate headers, tables, and actions for string lookup */
	flow_push_headers(my_header_list);
	flow_push_actions(my_action_list);
	flow_push_tables(my_dyn_table_list);
	flow_push_header_fields(my_header_list);
	flow_push_graph_nodes(my_hdr_nodes);

	nsd = nl_socket_alloc();
	nl_socket_set_local_port(nsd, getpid());
	nl_connect(nsd, NETLINK_GENERIC);

	while (1) {
		printf("Waiting for message\n");
		rc = nl_recv(nsd, &dest_addr, &buf, NULL);
		if(rc < 0) {
			printf("%s:receive error on netlink socket:%d\n", __func__,
				    errno);
			exit(-1);
		}
		//printf("%s:recvfrom received %d bytes from pid %d\n", __func__, rc, dest_addr.nl_pid);

		err = rx_process((struct nlmsghdr *)buf, rc);
		if (err < 0)
			fprintf(stderr, "%s: Warning: parsing error\n", __func__);
		memset(buf, 0, rcv_size);
	}
}
