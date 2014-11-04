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

int nl_to_hw_flow_field_ref(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_field_ref *ref);
int nl_to_sw_action(FILE *fp, bool p, struct nlattr *nl, struct hw_flow_action **a);
int nl_to_matches(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_field_ref **ref);
int nl_to_actions(FILE  *fp, bool print, struct nlattr *nl, struct hw_flow_action **actions);
int nl_to_flow_table(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_table *t);
int nl_to_flow_tables(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_table **t);
int nl_to_flows(FILE *fp, bool print, struct nlattr *attr);
int nl_to_hw_headers(FILE *fp, bool print, struct nlattr *nl);
int nl_to_flow_table_field(FILE *fp, bool print, struct nlattr *nl, struct hw_flow_header *hdr);

struct hw_flow_header *get_headers(int uid);
struct hw_flow_field *get_fields(int huid, int uid);
struct hw_flow_table *get_tables(int uid);
struct hw_flow_action *get_actions(int uid);

char *headers_names(int uid);
char *fields_names(int uid);
char *tables_names(int uid);
char *action_names(int uid);
