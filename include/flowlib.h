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

#ifdef __GNUC__
#define	UNUSED(x)	UNUSED_ ## x __attribute__((__unused__))
#define UNUSED_FUNC(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#define UNUSED(x)	UNUSED_ ## x
#define UNUSED_FUNC(x)	UNUSED_ ## x
#endif /* __GNUC__ */

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

unsigned int flow_get_flow_errors(struct nlattr *nl);

int flow_put_field_ref(struct nl_msg *nlbuf, struct net_flow_field_ref *ref);
int flow_put_matches(struct nl_msg *nlbuf, struct net_flow_field_ref *ref, int type);
int flow_put_action(struct nl_msg *nlbuf, struct net_flow_action *ref);
int flow_put_actions(struct nl_msg *nlbuf, struct net_flow_action **actions);
int flow_put_headers(struct nl_msg *nlbuf, struct net_flow_hdr **header);
int flow_put_flows(struct nl_msg *nlbuf, struct net_flow_flow *flow);
int flow_put_flow(struct nl_msg *nlbuf, struct net_flow_flow *ref);
int flow_put_flow_error(struct nl_msg *nlbuf, __u32 err);
int flow_put_table(struct nl_msg *nlbuf, struct net_flow_tbl *t);
int flow_put_tables(struct nl_msg *nlbuf, struct net_flow_tbl *t);
int flow_put_table_graph(struct nl_msg *nlbuf, struct net_flow_tbl_node **ref);
int flow_put_header_graph(struct nl_msg *nlbuf, struct net_flow_hdr_node **g);

void flow_push_headers(struct net_flow_hdr **h);
void flow_push_actions(struct net_flow_action **a);
void flow_push_tables(struct net_flow_tbl *t);
void flow_push_header_fields(struct net_flow_hdr **h);
void flow_push_graph_nodes(struct net_flow_hdr_node **n);

void flow_pop_tables(struct net_flow_tbl *t);

int find_match(char *header, char *field, unsigned int *hi, unsigned int *li);
unsigned int find_action(char *name);
unsigned int find_table(char *name);
unsigned int find_header_node(char *name);
unsigned int find_field(char *name, unsigned int hdr);

void pp_action(FILE *fp, int p, struct net_flow_action *ref, bool print_values);
void pp_table(FILE *fp, int p, struct net_flow_tbl *ref);
void pp_header(FILE *fp, int p, struct net_flow_hdr *ref);
void pp_flows(FILE *fp, int p, struct net_flow_flow *ref);
void pp_flow(FILE *fp, int p, struct net_flow_flow *ref);
void pp_table_graph(FILE *fp, int p, struct net_flow_tbl_node *nodes);

struct net_flow_hdr *get_headers(unsigned int uid);
struct net_flow_field *get_fields(unsigned int huid, unsigned int uid);
struct net_flow_tbl *get_tables(unsigned int uid);
struct net_flow_action *get_actions(unsigned int uid);
struct net_flow_hdr_node *get_graph_node(unsigned int uid);

char *headers_names(unsigned int uid);
char *fields_names(unsigned int hid, unsigned int uid);
char *tables_names(unsigned int uid);
char *action_names(unsigned int uid);

unsigned int gen_table_id(void);
unsigned int get_table_id(char *name);

int ll_addr_a2n(char *lladdr, int len, char *arg);
const char *ll_addr_n2a(unsigned char *, int, char *, size_t);
