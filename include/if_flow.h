/*
 * if_flow.h - Flow table interface for Switch devices
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Author: John Fastabend <john.r.fastabend@intel.com>
 */

#ifndef _IF_FLOW_H
#define _IF_FLOW_H

/**
 * @struct net_flow_fields
 * @brief defines a field in a header
 *
 * @name string identifier for pretty printing
 * @uid  unique identifier for field
 * @bitwidth length of field in bits
 */
struct net_flow_field {
	char *name;
	__u32 uid;
	__u32 bitwidth;
};

/**
 * @struct net_flow_hdr
 * @brief defines a match (header/field) an endpoint can use
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for header
 * @field_sz number of fields are in the set
 * @fields the set of fields in the net_flow_hdr
 */
struct net_flow_hdr {
	char *name;
	__u32 uid;
	__u32 field_sz;
	struct net_flow_field *fields;
};

enum net_flow_action_arg_type {
	NET_FLOW_ACTION_ARG_TYPE_NULL,
	NET_FLOW_ACTION_ARG_TYPE_U8,
	NET_FLOW_ACTION_ARG_TYPE_U16,
	NET_FLOW_ACTION_ARG_TYPE_U32,
	NET_FLOW_ACTION_ARG_TYPE_U64,
	__NET_FLOW_ACTION_ARG_TYPE_VAL_MAX,
};

/**
 * @struct net_flow_action_arg
 * @brief encodes action arguments in structures one per argument
 *
 * @name    string identifier for pretty printing
 * @type    type of argument either u8, u16, u32, u64
 * @value_# indicate value/mask value type on of u8, u16, u32, or u64
 */
struct net_flow_action_arg {
	char *name;
	enum net_flow_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	}v;
};

/**
 * @struct net_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @args null terminated list of action arguments
 */
struct net_flow_action {
	char *name;
	__u32 uid;
	struct net_flow_action_arg *args;
};

/**
 * @struct net_flow_field_ref
 * @brief uniquely identify field as instance:header:field tuple
 *
 * @next_node next node in jump table otherwise ignored
 * @instance identify unique instance of field reference
 * @header   identify unique header reference
 * @field    identify unique field in above header reference
 * @mask_type indicate mask type
 * @type     indicate value/mask value type on of u8, u16, u32, or u64
 * @value_u# value of field reference
 * @mask_u#  mask value of field reference
 */
struct net_flow_field_ref {
	__u32 instance;
	__u32 header;
	__u32 field;
	__u32 mask_type;
	__u32 type;
	union {
		struct {
			__u8 value_u8;
			__u8 mask_u8;
		} u8;
		struct {
			__u16 value_u16;
			__u16 mask_u16;
		} u16;
		struct {
			__u32 value_u32;
			__u32 mask_u32;
		} u32;
		struct {
			__u64 value_u64;
			__u64 mask_u64;
		} u64;
	}v;
};

/**
 * @struct net_flow_tbl
 * @brief define flow table with supported match/actions
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for table
 * @source uid of parent table
 * @size max number of entries for table or -1 for unbounded
 * @matches null terminated set of supported match types given by match uid
 * @actions null terminated set of supported action types given by action uid
 */
struct net_flow_tbl {
	char *name;
	__u32 uid;
	__u32 source;
	__u32 apply_action;
	__u32 size;
	struct net_flow_field_ref *matches;
	__u32 *actions;
};

/**
 * @struct net_flow_jump_table
 * @brief encodes an edge of the table graph or header graph
 *
 * @field   field reference must be true to follow edge
 * @node    node identifier to connect edge to
 */

struct net_flow_jump_table {
	struct net_flow_field_ref field;
	__u32 node; /* <0 is a parser error */
};

/* @struct net_flow_hdr_node
 * @brief node in a header graph of header fields.
 *
 * @name string identifier for pretty printing
 * @uid  unique id of the graph node
 * @hdrs null terminated list of hdrs identified by this node
 * @jump encoding of graph structure as a case jump statement
 */
struct net_flow_hdr_node {
	char *name;
	__u32 uid;
	__u32 *hdrs;
	struct net_flow_jump_table *jump;
};

/* @struct net_flow_tbl_node
 * @brief
 *
 * @uid	  unique id of the table node
 * @flags bitmask of table attributes
 * @jump  encoding of graph structure as a case jump statement
 */
struct net_flow_tbl_node {
	__u32 uid;
	__u32 flags;
	struct net_flow_jump_table *jump;
};

/**
 * @struct net_flow_flow
 * @brief describes the match/action entry
 *
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @actoin null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct net_flow_flow {
	__u32 table_id;
	__u32 uid;
	__u32 priority;
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
};

enum {
	NET_FLOW_FIELD_UNSPEC,
	NET_FLOW_FIELD,
	__NET_FLOW_FIELD_MAX,
};
#define NET_FLOW_FIELD_MAX (__NET_FLOW_FIELD_MAX - 1)

/* Max length supported by kernel name strings only the first n characters
 * will be used by the kernel API. This is to prevent arbitrarily long
 * strings being passed from user space.
 */
#define NET_FLOW_MAX_NAME 80

enum {
	NET_FLOW_FIELD_ATTR_UNSPEC,
	NET_FLOW_FIELD_ATTR_NAME,
	NET_FLOW_FIELD_ATTR_UID,
	NET_FLOW_FIELD_ATTR_BITWIDTH,
	__NET_FLOW_FIELD_ATTR_MAX,
};
#define NET_FLOW_FIELD_ATTR_MAX (__NET_FLOW_FIELD_ATTR_MAX - 1)

enum {
	NET_FLOW_HEADER_UNSPEC,
	NET_FLOW_HEADER,
	__NET_FLOW_HEADER_MAX,
};
#define NET_FLOW_HEADER_MAX (__NET_FLOW_HEADER_MAX - 1)

enum {
	NET_FLOW_HEADER_ATTR_UNSPEC,
	NET_FLOW_HEADER_ATTR_NAME,
	NET_FLOW_HEADER_ATTR_UID,
	NET_FLOW_HEADER_ATTR_FIELDS,
	__NET_FLOW_HEADER_ATTR_MAX,
};
#define NET_FLOW_HEADER_ATTR_MAX (__NET_FLOW_HEADER_ATTR_MAX - 1)

enum {
	NET_FLOW_MASK_TYPE_UNSPEC,
	NET_FLOW_MASK_TYPE_EXACT,
	NET_FLOW_MASK_TYPE_LPM,
	NET_FLOW_MASK_TYPE_MASK,
};

enum {
	NET_FLOW_FIELD_REF_UNSPEC,
	NET_FLOW_FIELD_REF_NEXT_NODE,
	NET_FLOW_FIELD_REF_INSTANCE,
	NET_FLOW_FIELD_REF_HEADER,
	NET_FLOW_FIELD_REF_FIELD,
	NET_FLOW_FIELD_REF_MASK_TYPE,
	NET_FLOW_FIELD_REF_TYPE,
	NET_FLOW_FIELD_REF_VALUE,
	NET_FLOW_FIELD_REF_MASK,
	__NET_FLOW_FIELD_REF_MAX,
};
#define NET_FLOW_FIELD_REF_MAX (__NET_FLOW_FIELD_REF_MAX - 1)

enum {
	NET_FLOW_FIELD_REFS_UNSPEC,
	NET_FLOW_FIELD_REF,
	__NET_FLOW_FIELD_REFS_MAX,
};
#define NET_FLOW_FIELD_REFS_MAX (__NET_FLOW_FIELD_REFS_MAX - 1)

enum {
	NET_FLOW_FIELD_REF_ATTR_TYPE_UNSPEC,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U8,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U32,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U64,
};

enum {
	NET_FLOW_ACTION_ARG_UNSPEC,
	NET_FLOW_ACTION_ARG_NAME,
	NET_FLOW_ACTION_ARG_TYPE,
	NET_FLOW_ACTION_ARG_VALUE,
	__NET_FLOW_ACTION_ARG_MAX,
};
#define NET_FLOW_ACTION_ARG_MAX (__NET_FLOW_ACTION_ARG_MAX - 1)

enum {
	NET_FLOW_ACTION_ARGS_UNSPEC,
	NET_FLOW_ACTION_ARG,
	__NET_FLOW_ACTION_ARGS_MAX,
};
#define NET_FLOW_ACTION_ARGS_MAX (__NET_FLOW_ACTION_ARGS_MAX - 1)

enum {
	NET_FLOW_ACTION_UNSPEC,
	NET_FLOW_ACTION,
	__NET_FLOW_ACTION_MAX,
};
#define NET_FLOW_ACTION_MAX (__NET_FLOW_ACTION_MAX - 1)

enum {
	NET_FLOW_ACTION_ATTR_UNSPEC,
	NET_FLOW_ACTION_ATTR_NAME,
	NET_FLOW_ACTION_ATTR_UID,
	NET_FLOW_ACTION_ATTR_SIGNATURE,
	__NET_FLOW_ACTION_ATTR_MAX,
};
#define NET_FLOW_ACTION_ATTR_MAX (__NET_FLOW_ACTION_ATTR_MAX - 1)

enum {
	NET_FLOW_ACTION_SET_UNSPEC,
	NET_FLOW_ACTION_SET_ACTIONS,
	__NET_FLOW_ACTION_SET_MAX,
};
#define NET_FLOW_ACTION_SET_MAX (__NET_FLOW_ACTION_SET_MAX - 1)

enum {
	NET_FLOW_TABLE_UNSPEC,
	NET_FLOW_TABLE,
	__NET_FLOW_TABLE_MAX,
};
#define NET_FLOW_TABLE_MAX (__NET_FLOW_TABLE_MAX - 1)

enum {
	NET_FLOW_TABLE_ATTR_UNSPEC,
	NET_FLOW_TABLE_ATTR_NAME,
	NET_FLOW_TABLE_ATTR_UID,
	NET_FLOW_TABLE_ATTR_SOURCE,
	NET_FLOW_TABLE_ATTR_APPLY,
	NET_FLOW_TABLE_ATTR_SIZE,
	NET_FLOW_TABLE_ATTR_MATCHES,
	NET_FLOW_TABLE_ATTR_ACTIONS,
	__NET_FLOW_TABLE_ATTR_MAX,
};
#define NET_FLOW_TABLE_ATTR_MAX (__NET_FLOW_TABLE_ATTR_MAX - 1)

#define NET_FLOW_JUMP_TABLE_DONE 0

enum {
	NET_FLOW_JUMP_ENTRY_UNSPEC,
	NET_FLOW_JUMP_ENTRY,
	__NET_FLOW_JUMP_ENTRY_MAX,
};

enum {
	NET_FLOW_HEADER_NODE_HDRS_UNSPEC,
	NET_FLOW_HEADER_NODE_HDRS_VALUE,
	__NET_FLOW_HEADER_NODE_HDRS_MAX,
};
#define NET_FLOW_HEADER_NODE_HDRS_MAX (__NET_FLOW_HEADER_NODE_HDRS_MAX - 1)

enum {
	NET_FLOW_HEADER_NODE_UNSPEC,
	NET_FLOW_HEADER_NODE_NAME,
	NET_FLOW_HEADER_NODE_UID,
	NET_FLOW_HEADER_NODE_HDRS,
	NET_FLOW_HEADER_NODE_JUMP,
	__NET_FLOW_HEADER_NODE_MAX,
};
#define NET_FLOW_HEADER_NODE_MAX (__NET_FLOW_HEADER_NODE_MAX - 1)

enum {
	NET_FLOW_HEADER_GRAPH_UNSPEC,
	NET_FLOW_HEADER_GRAPH_NODE,
	__NET_FLOW_HEADER_GRAPH_MAX,
};
#define NET_FLOW_HEADER_GRAPH_MAX (__NET_FLOW_HEADER_GRAPH_MAX - 1)

#define	NET_FLOW_TABLE_EGRESS_ROOT 1
#define	NET_FLOW_TABLE_INGRESS_ROOT 2
#define	NET_FLOW_TABLE_DYNAMIC 4

enum {
	NET_FLOW_TABLE_GRAPH_NODE_UNSPEC,
	NET_FLOW_TABLE_GRAPH_NODE_UID,
	NET_FLOW_TABLE_GRAPH_NODE_FLAGS,
	NET_FLOW_TABLE_GRAPH_NODE_JUMP,
	__NET_FLOW_TABLE_GRAPH_NODE_MAX,
};
#define NET_FLOW_TABLE_GRAPH_NODE_MAX (__NET_FLOW_TABLE_GRAPH_NODE_MAX - 1)

enum {
	NET_FLOW_TABLE_GRAPH_UNSPEC,
	NET_FLOW_TABLE_GRAPH_NODE,
	__NET_FLOW_TABLE_GRAPH_MAX,
};
#define NET_FLOW_TABLE_GRAPH_MAX (__NET_FLOW_TABLE_GRAPH_MAX - 1)

enum {
	NET_FLOW_NET_FLOW_UNSPEC,
	NET_FLOW_FLOW,
	__NET_FLOW_NET_FLOW_MAX,
};
#define NET_FLOW_NET_FLOW_MAX (__NET_FLOW_NET_FLOW_MAX - 1)

enum {
	NET_FLOW_TABLE_FLOWS_UNSPEC,
	NET_FLOW_TABLE_FLOWS_TABLE,
	NET_FLOW_TABLE_FLOWS_MINPRIO,
	NET_FLOW_TABLE_FLOWS_MAXPRIO,
	NET_FLOW_TABLE_FLOWS_FLOWS,
	__NET_FLOW_TABLE_FLOWS_MAX,
};
#define NET_FLOW_TABLE_FLOWS_MAX (__NET_FLOW_TABLE_FLOWS_MAX - 1)

enum {
	/* Abort with normal errmsg */
	NET_FLOW_FLOWS_ERROR_ABORT,
	/* Ignore errors and continue without logging */
	NET_FLOW_FLOWS_ERROR_CONTINUE,
	/* Abort and reply with invalid flow fields */
	NET_FLOW_FLOWS_ERROR_ABORT_LOG,
	/* Continue and reply with list of invalid flows */
	NET_FLOW_FLOWS_ERROR_CONT_LOG,
	__NET_FLOWS_FLOWS_ERROR_MAX,
};
#define NET_FLOWS_FLOWS_ERROR_MAX (__NET_FLOWS_FLOWS_ERROR_MAX - 1)

enum {
	NET_FLOW_ATTR_UNSPEC,
	NET_FLOW_ATTR_ERROR,
	NET_FLOW_ATTR_TABLE,
	NET_FLOW_ATTR_UID,
	NET_FLOW_ATTR_PRIORITY,
	NET_FLOW_ATTR_MATCHES,
	NET_FLOW_ATTR_ACTIONS,
	__NET_FLOW_ATTR_MAX,
};
#define NET_FLOW_ATTR_MAX (__NET_FLOW_ATTR_MAX - 1)

enum {
	NET_FLOW_IDENTIFIER_UNSPEC,
	NET_FLOW_IDENTIFIER_IFINDEX, /* net_device ifindex */
};

enum {
	NET_FLOW_UNSPEC,
	NET_FLOW_IDENTIFIER_TYPE,
	NET_FLOW_IDENTIFIER,

	NET_FLOW_TABLES,
	NET_FLOW_HEADERS,
	NET_FLOW_ACTIONS,
	NET_FLOW_HEADER_GRAPH,
	NET_FLOW_TABLE_GRAPH,

	NET_FLOW_FLOWS,
	NET_FLOW_FLOWS_ERROR,

	__NET_FLOW_MAX,
	NET_FLOW_MAX = (__NET_FLOW_MAX - 1),
};

enum {
	NET_FLOW_TABLE_CMD_GET_TABLES,
	NET_FLOW_TABLE_CMD_GET_HEADERS,
	NET_FLOW_TABLE_CMD_GET_ACTIONS,
	NET_FLOW_TABLE_CMD_GET_HDR_GRAPH,
	NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH,

	NET_FLOW_TABLE_CMD_GET_FLOWS,
	NET_FLOW_TABLE_CMD_SET_FLOWS,
	NET_FLOW_TABLE_CMD_DEL_FLOWS,
	NET_FLOW_TABLE_CMD_UPDATE_FLOWS,

	NET_FLOW_TABLE_CMD_CREATE_TABLE,
	NET_FLOW_TABLE_CMD_DESTROY_TABLE,

	__NET_FLOW_CMD_MAX,
	NET_FLOW_CMD_MAX = (__NET_FLOW_CMD_MAX - 1),
};

#define NET_FLOW_GENL_NAME "net_flow_nl"
#define NET_FLOW_GENL_VERSION 0x1

#endif
