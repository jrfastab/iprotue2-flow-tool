/*******************************************************************************

  Better Pipeline - A fictional pipeline model for testing
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


#ifndef _MY_PIPELINE_H_
#define _MY_PIPELINE_H_

#include "../../include/if_flow.h"

/********************************************************************
 * HEADER DEFINITIONS
 *******************************************************************/

#define HEADER_ETHERNET_SRC_MAC 1
#define HEADER_ETHERNET_DST_MAC 2
#define HEADER_ETHERNET_ETHERTYPE 3
struct net_flow_field ethernet_fields[3] = {
	{ .name = "src_mac", .uid = HEADER_ETHERNET_SRC_MAC, .bitwidth = 48},
	{ .name = "dst_mac", .uid = HEADER_ETHERNET_DST_MAC, .bitwidth = 48},
	{ .name = "ethertype", .uid = HEADER_ETHERNET_ETHERTYPE, .bitwidth = 16},
};

#define HEADER_ETHERNET 1
struct net_flow_header ethernet = {
	.name = "ethernet",
	.uid = HEADER_ETHERNET,
	.field_sz = 3,
	.fields = ethernet_fields,
};

#define HEADER_VLAN_PCP 1
#define HEADER_VLAN_CFI 2
#define HEADER_VLAN_VID 3
#define HEADER_VLAN_ETHERTYPE 4
struct net_flow_field vlan_fields[4] = {
	{ .name = "pcp", .uid = HEADER_VLAN_PCP, .bitwidth = 3,},
	{ .name = "cfi", .uid = HEADER_VLAN_CFI, .bitwidth = 1,},
	{ .name = "vid", .uid = HEADER_VLAN_VID, .bitwidth = 12,},
	{ .name = "ethertype", .uid = HEADER_VLAN_ETHERTYPE, .bitwidth = 16,},
};

#define HEADER_VLAN 2
struct net_flow_header vlan = {
	.name = "vlan",
	.uid = HEADER_VLAN,
	.field_sz = 4,
	.fields = vlan_fields,
};

#define HEADER_IPV4_VERSION 1
#define HEADER_IPV4_IHL 2
#define HEADER_IPV4_DSCP 3
#define HEADER_IPV4_ECN 4
#define HEADER_IPV4_LENGTH 5
#define HEADER_IPV4_IDENTIFICATION 6
#define HEADER_IPV4_FLAGS 7
#define HEADER_IPV4_FRAGMENT_OFFSET 8
#define HEADER_IPV4_TTL 9
#define HEADER_IPV4_PROTOCOL 10
#define HEADER_IPV4_CSUM 11
#define HEADER_IPV4_SRC_IP 12
#define HEADER_IPV4_DST_IP 13
#define HEADER_IPV4_OPTIONS 14
struct net_flow_field ipv4_fields[14] = {
	{ .name = "version",
	  .uid = 1,
	  .bitwidth = 4,},
	{ .name = "ihl",
	  .uid = 2,
	  .bitwidth = 4,},
	{ .name = "dscp",
	  .uid = 3,
	  .bitwidth = 6,},
	{ .name = "ecn",
	  .uid = 4,
	  .bitwidth = 2,},
	{ .name = "length",
	  .uid = 5,
	  .bitwidth = 8,},
	{ .name = "identification",
	  .uid = 6,
	  .bitwidth = 8,},
	{ .name = "flags",
	  .uid = 7,
	  .bitwidth = 3,},
	{ .name = "fragment_offset",
	  .uid = 8,
	  .bitwidth = 13,},
	{ .name = "ttl",
	  .uid = 9,
	  .bitwidth = 1,},
	{ .name = "protocol",
	  .uid = 10,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 11,
	  .bitwidth = 8,},
	{ .name = "src_ip",
	  .uid = 12,
	  .bitwidth = 32,},
	{ .name = "dst_ip",
	  .uid = 13,
	  .bitwidth = 32,},
	{ .name = "options",
	  .uid = 14,
	  .bitwidth = -1,},
	/* TBD options */
};

#define HEADER_IPV4 3
struct net_flow_header ipv4 = {
	.name = "ipv4",
	.uid = HEADER_IPV4,
	.field_sz = 14,
	.fields = ipv4_fields,
};

#define HEADER_TCP_SRC_PORT 1
#define HEADER_TCP_DST_PORT 2
#define HEADER_TCP_SEQ 3
#define HEADER_TCP_ACK 4
#define HEADER_TCP_OFFSET 5
#define HEADER_TCP_RESERVED 6
#define HEADER_TCP_FLAGS 7
#define HEADER_TCP_WINDOW 8
#define HEADER_TCP_CSUM 9
#define HEADER_TCP_URGENT 10
struct net_flow_field tcp_fields[10] = {
	{ .name = "src_port",
	  .uid = 1,
	  .bitwidth = 16,
	},
	{ .name = "dst_port",
	  .uid = 2,
	  .bitwidth = 16,
	},
	{ .name = "seq",
	  .uid = 3,
	  .bitwidth = 32,
	},
	{ .name = "ack",
	  .uid = 4,
	  .bitwidth = 32,
	},
	{ .name = "offset",
	  .uid = 5,
	  .bitwidth = 4,
	},
	{ .name = "reserved",
	  .uid = 6,
	  .bitwidth = 3},
	{ .name = "flags",
	  .uid = 7,
	  .bitwidth = 9},
	{ .name = "window",
	  .uid = 8,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 9,
	  .bitwidth = 16,},
	{ .name = "urgent",
	  .uid = 10,
	  .bitwidth = 16},
	/* TBD options */
};

#define HEADER_TCP 4
struct net_flow_header tcp = {
	.name = "tcp",
	.uid = HEADER_TCP,
	.field_sz = 10,
	.fields = tcp_fields,
};

#define HEADER_UDP_SRC_PORT 1
#define HEADER_UDP_DST_PORT 2
#define HEADER_UDP_LENGTH 3
#define HEADER_UDP_CSUM 4
struct net_flow_field udp_fields[4] = {
	{ .name = "src_port",
	  .uid = 1,
	  .bitwidth = 16},
	{ .name = "dst_port",
	  .uid = 2,
	  .bitwidth = 16},
	{ .name = "length",
	  .uid = 3,
	  .bitwidth = 16},
	{ .name = "csum",
	  .uid = 4,
	  .bitwidth = 16},
};

#define HEADER_UDP 5
struct net_flow_header udp = {
	.name = "udp",
	.uid = HEADER_UDP,
	.field_sz = 4,
	.fields = udp_fields,
};

#define HEADER_VXLAN_VXLAN_HEADER 1
#define HEADER_VXLAN_VNI 2
#define HEADER_VXLAN_RESERVED 3
struct net_flow_field vxlan_fields[3] = {
	{ .name = "vxlan_header",
	  .uid = 1,
	  .bitwidth = 32},
	{ .name = "vni",
	  .uid = 2,
	  .bitwidth = 24},
	{ .name = "reserved",
	  .uid = 3,
	  .bitwidth = 8},
};

#define HEADER_VXLAN 6
struct net_flow_header vxlan = {
	.name = "vxlan",
	.uid = HEADER_VXLAN,
	.field_sz = 3,
	.fields = vxlan_fields,
};

#define HEADER_METADATA_EGRESS_QUEUE 1
#define HEADER_METADATA_HOST_METADATA 2
#define HEADER_METADATA_TUNNEL_ID 3
#define HEADER_METADATA_ECMP_INDEX 4
#define HEADER_METADATA_INGRESS_PORT 5
struct net_flow_field metadata_fields[5] = {
	{ .name = "egress_queue",
	  .uid = HEADER_METADATA_EGRESS_QUEUE,
	  .bitwidth = 8,},
	{ .name = "host_metadata",
	  .uid = HEADER_METADATA_HOST_METADATA,
	  .bitwidth = 16,},
	{ .name = "tunnel_id",
	  .uid = HEADER_METADATA_TUNNEL_ID,
	  .bitwidth = 16,},
	{ .name = "ecmp_index",
	  .uid = HEADER_METADATA_ECMP_INDEX,
	  .bitwidth = 32,},
	{ .name = "ingress_port",
	  .uid = HEADER_METADATA_INGRESS_PORT,
	  .bitwidth = 32,},
};

#define HEADER_METADATA 7
struct net_flow_header metadata_t = {
	.name = "metadata_t",
	.uid = HEADER_METADATA,
	.field_sz = 5,
	.fields = metadata_fields,
};

struct net_flow_action_arg set_egress_port_args[2] = {
	{
		.name = "egress_port",
		.type = NET_FLOW_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_header nill = {.name = "", .uid = 0, .field_sz=0, .fields = NULL};

struct net_flow_header *my_header_list[8] =
{
	&ethernet,
	&vlan,
	&ipv4,
	&tcp,
	&udp,
	&vxlan,
	&metadata_t,
	&nill,
};

/********************************************************************
 * ACTION DEFINITIONS
 *******************************************************************/

#define ACTION_SET_EGRESS_PORT 1
struct net_flow_action set_egress_port = {
	.name = "set_egress_port",
	.uid = ACTION_SET_EGRESS_PORT,
	.args = set_egress_port_args,
};

struct net_flow_action_arg set_tunnel_id_args[2] = {
	{
		.name = "tunnel_id",
		.type = NET_FLOW_ACTION_ARG_TYPE_U16,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

#define ACTION_SET_TUNNEL_ID 2
struct net_flow_action set_tunnel_id = {
	.name = "set_tunnel_id",
	.uid = ACTION_SET_TUNNEL_ID,
	.args = set_tunnel_id_args,
};

struct net_flow_action_arg set_egress_queue_args[2] = {
	{
		.name = "egress_queue",
		.type = NET_FLOW_ACTION_ARG_TYPE_U16,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

#define ACTION_SET_EGRESS_QUEUE	3
struct net_flow_action set_egress_queue = {
	.name = "set_egress_queue",
	.uid = ACTION_SET_EGRESS_QUEUE,
	.args = set_egress_queue_args,
};

struct net_flow_action_arg set_host_metadata_args[2] = {
	{
		.name = "host_metadata",
		.type = NET_FLOW_ACTION_ARG_TYPE_U16,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

#define ACTION_SET_HOST_METADATA 4
struct net_flow_action set_host_metadata = {
	.name = "set_host_mata",
	.uid = ACTION_SET_HOST_METADATA,
	.args = set_host_metadata_args,
};

struct net_flow_action_arg vxlan_decap_args[2] = {
	{
		.name = "vxlan_decap",
		.type = NET_FLOW_ACTION_ARG_TYPE_U16,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

#define ACTION_VXLAN_DECAP 5
struct net_flow_action vxlan_decap = {
	.name = "vxlan_decap",
	.uid = ACTION_VXLAN_DECAP,
	.args = vxlan_decap_args,
};

struct net_flow_action_arg vxlan_encap_args[2] = {
	{
		.name = "vxlan_encap",
		.type = NET_FLOW_ACTION_ARG_TYPE_U16,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

#define ACTION_VXLAN_ENCAP 6
struct net_flow_action vxlan_encap = {
	.name = "vxlan_encap",
	.uid = ACTION_VXLAN_ENCAP,
	.args = vxlan_encap_args,
};

#define ACTION_DROP_PACKET 7
struct net_flow_action drop_packet = {
	.name = "drop_packet",
	.uid = ACTION_DROP_PACKET,
	.args = NULL,
};

struct net_flow_action_arg route_via_ecmp_args[3] = {
	{ .name = "ecmp_group_base",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U16,},
	{ .name = "ecmp_group_size",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U16,},
	{ .name = "",
	  .type = NET_FLOW_ACTION_ARG_TYPE_NULL,},
};

#define ACTION_ROUTE_VIA_ECMP 8
struct net_flow_action route_via_ecmp = {
	.name = "route_via_ecmp",
	.uid = ACTION_ROUTE_VIA_ECMP,
	.args = route_via_ecmp_args,
};

struct net_flow_action_arg route_args[3] = {
	{ .name = "newDMAC",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U64,},
	{ .name = "newVLAN",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U16,},
	{ .name = "",
	  .type = NET_FLOW_ACTION_ARG_TYPE_NULL,},
};

#define ACTION_ROUTE 9
struct net_flow_action route = {
	.name = "route",
	.uid = ACTION_ROUTE,
	.args = route_args,
};

struct net_flow_action_arg forward_via_ecmp_args[3] = {
	{ .name = "fwd_group_base",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U32,},
	{ .name = "fwd_group_size",
	  .type = NET_FLOW_ACTION_ARG_TYPE_U32,},
	{ .name = "",
	  .type = NET_FLOW_ACTION_ARG_TYPE_NULL,},
};

#define ACTION_FORWARD_VIA_ECMP 10
struct net_flow_action forward_via_ecmp = {
	.name = "forward_via_ecmp",
	.uid = ACTION_FORWARD_VIA_ECMP,
	.args = forward_via_ecmp_args,
};

struct net_flow_action nil_action = {
	.name = "",
	.uid = 0,
	.args = NULL
};

struct net_flow_action *my_action_list[11] =
{
	&set_egress_port,
	&set_tunnel_id,
	&set_egress_queue,
	&set_host_metadata,
	&vxlan_decap,
	&vxlan_encap,
	&drop_packet,
	&route_via_ecmp,
	&route,
	&forward_via_ecmp,
	&nil_action,
};

/********************************************************************
 * TABLE DEFINITIONS
 *******************************************************************/
#define HEADER_INSTANCE_ETHERNET 1
#define HEADER_INSTANCE_VXLAN 2
#define HEADER_INSTANCE_VLAN_OUTER 3
#define HEADER_INSTANCE_VLAN_INNER 4
#define HEADER_INSTANCE_IPV4 5
#define HEADER_INSTANCE_TCP 6
#define HEADER_INSTANCE_UDP 7
#define HEADER_INSTANCE_ROUTING_METADATA 8
#define HEADER_INSTANCE_FORWARD_METADATA 9
#define HEADER_INSTANCE_TUNNEL_METADATA 10
#define HEADER_INSTANCE_INGRESS_PORT_METADATA 11

struct net_flow_field_ref matches_ecmp_group[2] =
{
	{ .instance = HEADER_INSTANCE_ROUTING_METADATA, .header = HEADER_METADATA, .field = HEADER_METADATA_ECMP_INDEX, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref matches_vxlan_decap[4] =
{
	{ .instance = HEADER_INSTANCE_VXLAN, .header = HEADER_VXLAN, .field = HEADER_VXLAN_VNI, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_DST_IP, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_SRC_IP, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref matches_l2fwd[3] =
{
	{ .instance = HEADER_INSTANCE_ETHERNET, .header = HEADER_ETHERNET, .field = HEADER_ETHERNET_DST_MAC, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = HEADER_VLAN_VID, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref matches_forward_group[2] =
{
	{ .instance = HEADER_INSTANCE_FORWARD_METADATA, .header = HEADER_METADATA, .field = HEADER_METADATA_ECMP_INDEX, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref matches_tunnel_encap[2] =
{
	{ .instance = HEADER_INSTANCE_TUNNEL_METADATA, .header = HEADER_METADATA, .field = HEADER_METADATA_TUNNEL_ID, .mask_type = NET_FLOW_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref matches_tcam[20] =
{
	{ .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA, .header = HEADER_METADATA, .field = HEADER_METADATA_INGRESS_PORT, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_ETHERNET, .header = HEADER_ETHERNET, .field = HEADER_ETHERNET_DST_MAC, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_ETHERNET, .header = HEADER_ETHERNET, .field = HEADER_ETHERNET_SRC_MAC, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_ETHERNET, .header = HEADER_ETHERNET, .field = HEADER_ETHERNET_ETHERTYPE, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = HEADER_VLAN_PCP, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = HEADER_VLAN_CFI, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = HEADER_VLAN_VID, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = HEADER_VLAN_ETHERTYPE, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_DSCP, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_ECN, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_TTL, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_PROTOCOL, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_DST_IP, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4, .header = HEADER_IPV4, .field = HEADER_IPV4_SRC_IP, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = HEADER_TCP_SRC_PORT, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = HEADER_TCP_DST_PORT, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = HEADER_TCP_FLAGS, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_UDP, .header = HEADER_UDP, .field = HEADER_UDP_SRC_PORT, .mask_type = NET_FLOW_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_UDP, .header = HEADER_UDP, .field = HEADER_UDP_DST_PORT, .mask_type = NET_FLOW_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_VXLAN, .header = HEADER_VXLAN, .field = HEADER_VXLAN_VNI, .mask_type = NET_FLOW_MASK_TYPE_LPM},
};

int actions_ecmp_group[4] = {ACTION_ROUTE, ACTION_SET_EGRESS_PORT, ACTION_SET_TUNNEL_ID, 0};
int actions_vxlan_decap[2] = {ACTION_VXLAN_DECAP,0};
int actions_l2fwd[3] = {ACTION_SET_EGRESS_PORT, ACTION_SET_TUNNEL_ID, 0};
int actions_forward_group[3] = {ACTION_SET_EGRESS_PORT, ACTION_SET_TUNNEL_ID, 0};
int actions_tunnel_encap[2] = {ACTION_VXLAN_ENCAP, 0};
int actions_tcam[5] = {ACTION_SET_EGRESS_PORT, ACTION_ROUTE_VIA_ECMP, ACTION_SET_TUNNEL_ID, ACTION_DROP_PACKET, 0};

#define TABLE_TCAM 1
#define TABLE_ECMP_GROUP 2
#define TABLE_FORWARD_GROUP 3
#define TABLE_L2FWD 4
#define TABLE_TUNNEL_ENCAP 5
#define TABLE_VXLAN_DECAP 6

struct net_flow_table my_table_ecmp_group = {
	.name = "ecmp_group",
	.uid = TABLE_ECMP_GROUP,
	.source = 2,
	.apply_action = 3,
	.size = 128,
	.matches = matches_ecmp_group,
	.actions = actions_ecmp_group,
};

struct net_flow_table my_table_vxlan_decap = {
	.name = "vxlan_decap",
	.uid = TABLE_VXLAN_DECAP,
	.source = 3,
	.apply_action = 4,
	.size = 2000,
	.matches = matches_vxlan_decap,
	.actions = actions_vxlan_decap,
};

struct net_flow_table my_table_l2fwd = {
	.name = "l2fwd",
	.uid = TABLE_L2FWD,
	.source = 1,
	.apply_action = 2,
	.size = 2000,
	.matches = matches_l2fwd,
	.actions = actions_l2fwd,
};

struct net_flow_table my_table_forward_group = {
	.name = "forward_group",
	.uid = TABLE_FORWARD_GROUP,
	.source = 1,
	.apply_action = 2,
	.size = 2000,
	.matches = matches_forward_group,
	.actions = actions_forward_group,
};	

struct net_flow_table my_table_tunnel_encap = {
	.name = "tunnel_encap",
	.uid = TABLE_TUNNEL_ENCAP,
	.source = 3,
	.apply_action = 4,
	.size = 2000,
	.matches = matches_tunnel_encap,
	.actions = actions_tunnel_encap,
};

struct net_flow_table my_table_tcam = {
	.name = "tcam",
	.uid = TABLE_TCAM,
	.source = 1,
	.apply_action = 1,
	.size = 4096,
	.matches = matches_tcam,
	.actions = actions_tcam,
};

struct net_flow_table my_table_null = {
	.name = "",
	.uid = 0,
	.source = 0,
	.size = 0,
	.matches = NULL,
	.actions = NULL,
};

struct net_flow_table *my_table_list[7] =
{
	&my_table_tcam,
	&my_table_forward_group,
	&my_table_l2fwd,
	&my_table_ecmp_group,
	&my_table_tunnel_encap,
	&my_table_vxlan_decap,
	&my_table_null,	
};

/********************************************************************
 * Jump Table
 ********************************************************************/

struct net_flow_jump_table my_parse_ethernet[3] =
{
	{
		.field = {
		   .header = HEADER_ETHERNET,
		   .field = HEADER_ETHERNET_ETHERTYPE,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x08000,
		},
		.node = HEADER_INSTANCE_IPV4,
	},
	{
		.field = {
		   .header = HEADER_ETHERNET,
		   .field = HEADER_ETHERNET_ETHERTYPE,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x08100,
		},
		.node = HEADER_INSTANCE_VLAN_OUTER,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int my_ethernet_headers[2] = {HEADER_ETHERNET, 0};
struct net_flow_hdr_node my_header_node_ethernet = {
	.name = "ethernet",
	.uid = HEADER_INSTANCE_ETHERNET,
	.hdrs = my_ethernet_headers,
	.jump = my_parse_ethernet,
};

struct net_flow_jump_table my_parse_vlan[3] =
{
	{
		.field = {
		   .header = HEADER_ETHERNET,
		   .field = HEADER_ETHERNET_ETHERTYPE,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x08000,
		},
		.node = HEADER_INSTANCE_IPV4,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int my_vlan_headers[2] = {HEADER_VLAN, 0};
struct net_flow_hdr_node my_header_node_vlan = {
	.name = "vlan",
	.uid = HEADER_INSTANCE_VLAN_OUTER,
	.hdrs = my_vlan_headers,
	.jump = my_parse_vlan,
};

struct net_flow_jump_table my_terminal_headers[2] = {
	{
		.field = {0},
		.node = NET_FLOW_JUMP_TABLE_DONE,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int my_tcp_headers[2] = {HEADER_TCP, 0};
struct net_flow_hdr_node my_header_node_tcp = {
	.name = "tcp",
	.uid = HEADER_INSTANCE_TCP,
	.hdrs = my_tcp_headers,
	.jump = my_terminal_headers,
};

struct net_flow_jump_table my_parse_ipv4[3] =
{
	{
		.field = {
		   .header = HEADER_IPV4,
		   .field = HEADER_IPV4_PROTOCOL,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 6,
		},
		.node = HEADER_INSTANCE_TCP,
	},
	{
		.field = {
		   .header = HEADER_IPV4,
		   .field = HEADER_IPV4_PROTOCOL,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 17,
		},
		.node = HEADER_INSTANCE_UDP,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int my_ipv4_headers[2] = {HEADER_IPV4, 0};
struct net_flow_hdr_node my_header_node_ipv4 = {
	.name = "ipv4",
	.uid = HEADER_INSTANCE_IPV4,
	.hdrs = my_ipv4_headers,
	.jump = my_parse_ipv4,
};

struct net_flow_jump_table my_parse_udp[2] =
{
	{
		.field = {
		   .header = HEADER_UDP,
		   .field = HEADER_UDP_DST_PORT,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 4789,
		},
		.node = HEADER_INSTANCE_VXLAN,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int my_udp_headers[2] = {HEADER_UDP, 0};
struct net_flow_hdr_node my_header_node_udp = {
	.name = "udp",
	.uid = HEADER_INSTANCE_UDP,
	.hdrs = my_udp_headers,
	.jump = my_parse_udp,
};

int my_vxlan_headers[2] = {HEADER_VXLAN, 0};
struct net_flow_hdr_node my_header_node_vxlan = {
	.name = "vxlan",
	.uid = HEADER_INSTANCE_VXLAN,
	.hdrs = my_vxlan_headers,
	.jump = my_terminal_headers,
};

int my_metadata_headers[2] = {HEADER_METADATA, 0};
struct net_flow_hdr_node my_header_node_routing_metadata = {
	.name = "routing_metadata",
	.uid = HEADER_INSTANCE_ROUTING_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

struct net_flow_hdr_node my_header_node_forward_metadata = {
	.name = "forward_metadata",
	.uid = HEADER_INSTANCE_FORWARD_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

struct net_flow_hdr_node my_header_node_tunnel_metadata = {
	.name = "tunnel_metadata",
	.uid = HEADER_INSTANCE_TUNNEL_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

struct net_flow_hdr_node my_header_node_ig_port_metadata = {
	.name = "ig_port_metadata",
	.uid = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

struct net_flow_hdr_node my_header_nil = {.name = "", .uid = 0,};

struct net_flow_hdr_node *my_hdr_nodes[11] = {
	&my_header_node_ethernet,
	&my_header_node_vlan,
	&my_header_node_ipv4,
	&my_header_node_udp,
	&my_header_node_vxlan,
	&my_header_node_tcp,
	&my_header_node_routing_metadata,
	&my_header_node_forward_metadata,
	&my_header_node_tunnel_metadata,
	&my_header_node_ig_port_metadata,
	&my_header_nil,
};

/********************************************************************
 * TABLE GRAPH
 *******************************************************************/
struct net_flow_jump_table my_table_node_ecmp_group_jump[2] = {
	{ .field = {0}, .node = TABLE_L2FWD},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_ecmp_group = {.uid = TABLE_ECMP_GROUP, .jump = my_table_node_ecmp_group_jump};


struct net_flow_jump_table my_table_node_vxlan_decap_jump[2] = {
	{ .field = {0}, .node = NET_FLOW_JUMP_TABLE_DONE},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_vxlan_decap = {.uid = TABLE_VXLAN_DECAP, .jump = my_table_node_vxlan_decap_jump};

struct net_flow_jump_table my_table_node_l2_fwd_jump[2] = {
	{ .field = {0}, .node = TABLE_FORWARD_GROUP},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_l2_fwd = {.uid = TABLE_L2FWD, .jump = my_table_node_l2_fwd_jump};

struct net_flow_jump_table my_table_node_forward_group_jump[2] = {
	{ .field = {0}, .node = TABLE_TUNNEL_ENCAP},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_forward_group = {.uid = TABLE_FORWARD_GROUP, .jump = my_table_node_forward_group_jump};

struct net_flow_jump_table my_table_node_tunnel_encap_jump[2] = {
	{ .field = {0}, .node = TABLE_VXLAN_DECAP},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_tunnel_encap = {.uid = TABLE_TUNNEL_ENCAP, .jump = my_table_node_tunnel_encap_jump};

struct net_flow_jump_table my_table_node_terminal_jump[2] = {
	{ .field = {0}, .node = TABLE_ECMP_GROUP},
	{ .field = {0}, .node = 0},
};
struct net_flow_tbl_node my_table_node_tcam = {
	.uid = TABLE_TCAM,
	.flags = NET_FLOW_TABLE_INGRESS_ROOT |
		 NET_FLOW_TABLE_EGRESS_ROOT  |
		 NET_FLOW_TABLE_DYNAMIC,
	.jump = my_table_node_terminal_jump};
struct net_flow_tbl_node my_table_node_nil = {.uid = 0, .jump = NULL};

struct net_flow_tbl_node *my_tbl_nodes[7] = {
	&my_table_node_tcam,
	&my_table_node_ecmp_group,
	&my_table_node_l2_fwd,
	&my_table_node_forward_group,
	&my_table_node_tunnel_encap,
	&my_table_node_vxlan_decap,
	&my_table_node_nil,
};
#endif /*_MY_PIPELINE_H*/
