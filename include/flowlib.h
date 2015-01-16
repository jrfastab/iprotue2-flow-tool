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

#define PRINT_GRAPHVIZ 2

int flow_get_field(FILE *fp, int print, struct nlattr *nl, struct net_flow_field_ref *ref);
int flow_get_matches(FILE *fp, int print, struct nlattr *nl, struct net_flow_field_ref **ref);
int flow_get_action(FILE *fp, int p, struct nlattr *nl, struct net_flow_action *a);
int flow_get_actions(FILE  *fp, int print, struct nlattr *nl, struct net_flow_action **actions);
int flow_get_headers(FILE *fp, int print, struct nlattr *nl, struct net_flow_hdr **headers);
int flow_get_flows(FILE *fp, int print, struct nlattr *attr, struct net_flow_flow **f);
int flow_get_table(FILE *fp, int print, struct nlattr *nl, struct net_flow_tbl *t);
int flow_get_tables(FILE *fp, int print, struct nlattr *nl, struct net_flow_tbl **t);
int flow_get_table_field(FILE *fp, int print, struct nlattr *nl, struct net_flow_hdr *hdr);
int flow_get_tbl_graph(FILE *fp, int p, struct nlattr *nl, struct net_flow_tbl_node **ref);
int flow_get_hdrs_graph(FILE *fp, int p, struct nlattr *nl, struct net_flow_hdr_node **ref);

int flow_get_flow_errors(FILE *fp, int print, struct nlattr *nl);

int flow_put_field_ref(struct nl_msg *nlbuf, struct net_flow_field_ref *ref);
int flow_put_matches(struct nl_msg *nlbuf, struct net_flow_field_ref *ref, int type);
int flow_put_action(struct nl_msg *nlbuf, struct net_flow_action *ref);
int flow_put_actions(struct nl_msg *nlbuf, struct net_flow_action *actions);
int flow_put_headers(struct nl_msg *nlbuf, struct net_flow_hdr **header);
int flow_put_flows(struct nl_msg *nlbuf, struct net_flow_flow *flow);
int flow_put_flow(struct nl_msg *nlbuf, struct net_flow_flow *ref);
int flow_put_flow_error(struct nl_msg *nlbuf, int err);
int flow_put_table(struct nl_msg *nlbuf, struct net_flow_tbl *t);
int flow_put_tables(struct nl_msg *nlbuf, struct net_flow_tbl *t);
int flow_put_table_graph(struct nl_msg *nlbuf, struct net_flow_tbl_node **ref);
int flow_put_header_graph(struct nl_msg *nlbuf, struct net_flow_hdr_node **g);

void flow_push_headers(struct net_flow_hdr **h);
void flow_push_actions(struct net_flow_action **a);
void flow_push_tables(struct net_flow_tbl *t);
void flow_push_header_fields(struct net_flow_hdr **h);

void flow_pop_tables(struct net_flow_tbl *t);

int find_match(char *header, char *field, int *hi, int *li);
int find_action(char *name);
int find_table(char *name);
int find_header_node(char *name);
int find_field(char *name, int hdr);

void pp_action(FILE *fp, int p, struct net_flow_action *ref);
void pp_table(FILE *fp, int p, struct net_flow_tbl *ref);
void pp_header(FILE *fp, int p, struct net_flow_hdr *ref);
void pp_flows(FILE *fp, int p, struct net_flow_flow *ref);
void pp_flow(FILE *fp, int p, struct net_flow_flow *ref);
void pp_table_graph(FILE *fp, int p, struct net_flow_tbl_node *nodes);

struct net_flow_hdr *get_headers(int uid);
struct net_flow_field *get_fields(int huid, int uid);
struct net_flow_tbl *get_tables(int uid);
struct net_flow_action *get_actions(int uid);
struct net_flow_hdr_node *get_graph_node(int uid);

char *headers_names(int uid);
char *fields_names(int hid, int uid);
char *tables_names(int uid);
char *action_names(int uid);

int gen_table_id(void);
int get_table_id(char *name);

const int ll_addr_a2n(char *lladdr, int len, const char *arg);
const char *ll_addr_n2a(unsigned char *, int, int, char *, int);
