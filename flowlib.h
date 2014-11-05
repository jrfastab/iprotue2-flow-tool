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

int flow_get_field(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_field_ref *ref);
int flow_get_matches(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_field_ref **ref);
int flow_get_action(FILE *fp, bool p, struct nlattr *nl, struct hw_flow_action **a);
int flow_get_actions(FILE  *fp, bool print, struct nlattr *nl, struct hw_flow_action **actions);
int flow_get_headers(FILE *fp, bool print, struct nlattr *nl);
int flow_get_flows(FILE *fp, bool print, struct nlattr *attr, struct hw_flow_flow **f);
int flow_get_table(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_table *t);
int flow_get_tables(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_table **t);
int flow_get_table_field(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_header *hdr);

int flow_put_field(struct nl_msg *nlbuf, struct hw_flow_field_ref *ref);
int flow_put_matches(struct nl_msg *nlbuf, struct hw_flow_field_ref *ref);
int flow_put_action(struct nl_msg *nlbuf, struct hw_flow_action *ref);
int flow_put_actions(struct nl_msg *nlbuf, struct hw_flow_action *actions);
int flow_put_headers(struct nl_msg *nlbuf, struct hw_flow_header *header);
int flow_put_flows(struct nl_msg *nlbuf, struct hw_flow_flow *flow);
int flow_put_table(struct nl_msg *nlbuf, struct hw_flow_table *t);
int flow_put_tables(struct nl_msg *nlbuf, struct hw_flow_table *t);

void pp_action(FILE *fp, bool p, struct hw_flow_action *ref);
void pp_table(FILE *fp, bool p, struct hw_flow_table *ref);
void pp_header(FILE *fp, bool p, struct hw_flow_header *ref);
void pp_flows(FILE *fp, bool p, struct hw_flow_flow *ref);
void pp_flow(FILE *fp, bool p, struct hw_flow_flow *ref);

struct hw_flow_header *get_headers(int uid);
struct hw_flow_field *get_fields(int huid, int uid);
struct hw_flow_table *get_tables(int uid);
struct hw_flow_action *get_actions(int uid);

char *headers_names(int uid);
char *fields_names(int uid);
char *tables_names(int uid);
char *action_names(int uid);
