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

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>

#include <linux/if_flow.h>
#include <linux/if_ether.h>

#define MAX_TABLES 100
#define MAX_HDRS 100
#define MAX_FIELDS 100
#define MAX_ACTIONS 100

char *table_names[MAX_TABLES];
char *headers_names[MAX_HDRS];		/* Hack to get this working need a real datastructure */
char *fields_names[MAX_HDRS][MAX_FIELDS]; /* Hack to get this working need a real datastructure */
char *action_names[MAX_TABLES][MAX_ACTIONS];

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

struct flow_msg *alloc_flow_msg(uint32_t type, uint16_t flags, size_t size, int family)
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
};

struct nla_policy hw_flow_tables_policy[HW_FLOW_TABLES_MAX+1] = {
	[HW_FLOW_TABLES_SIZE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLES_TABLE]	= { .type = NLA_NESTED },
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

static int nl_to_hw_flow_field_ref(FILE *fp, bool p,
				 struct hw_flow_field_ref *ref,
				 struct nlattr *attr,
				 char *headers_names[],
				 char *(fields_names[][MAX_HDRS]))
{
	struct nlattr *match[HW_FLOW_FIELD_REF_ATTR_MAX+1];
	int hi, fi, type, last_id = ref->header;
	char b1[10];
	int err;

	err = nla_parse_nested(match, HW_FLOW_FIELD_REF_ATTR_MAX, attr, hw_flow_field_ref_policy);
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

	if (!type) {
		if (last_id == hi && fields_names)
			pfprintf(stdout, p, " %s", fields_names[hi][fi]);
		else if (last_id < 0 && headers_names && fields_names)
			pfprintf(stdout, p, "\t field: %s [%s", headers_names[hi], fields_names[hi][fi]);
		else if (headers_names && fields_names)
			pfprintf(stdout, p, "]\n\t field: %s [%s", headers_names[hi], fields_names[hi][fi]);
	}
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
		pfprintf(stdout, p, "\t\t %s.%s = %02x (%02x)\n",
			headers_names[hi], fields_names[hi][fi], ref->value_u8, ref->mask_u8);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		ref->value_u16 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u16(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u16 = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u16(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		pfprintf(stdout, p, "\n\t\t %s.%s = %04x (%04x)\n",
			headers_names[hi], fields_names[hi][fi], ref->value_u16, ref->mask_u16);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		ref->value_u32 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u32   = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u32(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		pfprintf(stdout, p, " %s.%s = %08x (%08x)\n",
			headers_names[hi], fields_names[hi][fi], ref->value_u32, ref->mask_u32);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		ref->value_u64 = match[HW_FLOW_FIELD_REF_ATTR_VALUE] ? nla_get_u64(match[HW_FLOW_FIELD_REF_ATTR_VALUE]) : 0;
		ref->mask_u64   = match[HW_FLOW_FIELD_REF_ATTR_MASK] ? nla_get_u64(match[HW_FLOW_FIELD_REF_ATTR_MASK]) : 0;
		pfprintf(stdout, p, "\t\t %s.%s = %s (%016x)\n",
			 headers_names[hi], fields_names[hi][fi],
			 ll_addr_n2a((unsigned char *)&ref->value_u64, ETH_ALEN, 0, b1, sizeof(b1)),
			 ref->value_u64, ref->mask_u64);
		break;
	break;
		default:
		type = 0;
	}

	return 0;
}


struct nla_policy hw_flow_action_policy[HW_FLOW_ACTION_ATTR_MAX + 1] = {
	[HW_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING, },
	[HW_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[HW_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};
struct nla_policy hw_flow_action_arg_policy[HW_FLOW_ACTION_ATTR_MAX + 1] = {
	[HW_FLOW_ACTION_ARG_NAME] = {.type = NLA_STRING, .maxlen = IFNAMSIZ-1 },
	[HW_FLOW_ACTION_ARG_TYPE] = {.type = NLA_U32 },
	[HW_FLOW_ACTION_ARG_VALUE] = {.type = NLA_UNSPEC, },
};

const char *flow_table_arg_type_str[__HW_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

static int nl_to_sw_action(FILE *fp, bool p, bool flows, int tbl,
			   struct hw_flow_action *act,
			   struct nlattr *attr,
			   char *action_names[][MAX_ACTIONS])
{
	int rem;
	struct nlattr *signature, *l;
	struct nlattr *action[HW_FLOW_ACTION_ATTR_MAX+1];
	int err, uid, count = 0;
	char *name;

	err = nla_parse_nested(action, HW_FLOW_ACTION_ATTR_MAX, attr, hw_flow_action_policy);
	if (err) {
		fprintf(stdout, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	uid = action[HW_FLOW_ACTION_ATTR_UID] ? nla_get_u32(action[HW_FLOW_ACTION_ATTR_UID]) : -1;
	if (uid < 0)
		return 0;

	name = action[HW_FLOW_ACTION_ATTR_NAME] ?
		nla_get_string(action[HW_FLOW_ACTION_ATTR_NAME]) : NULL;

	if (name)
		action_names[tbl][uid] = name;

	pfprintf(stdout, p, "\t %i: %s ( ", uid, action_names[tbl][uid]);

	if (!action[HW_FLOW_ACTION_ATTR_SIGNATURE])
		return 0;

	signature = action[HW_FLOW_ACTION_ATTR_SIGNATURE];

	if (act) {
		strncpy(act->name, action_names[tbl][uid], IFNAMSIZ);
		act->uid = uid;

		rem = nla_len(signature);
		for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem))
			count++;
	
		act->args = malloc(sizeof(struct hw_flow_action_arg) * count);
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
		pfprintf(stdout, flows, "%s %s ", flow_table_arg_type_str[t], argname);

		if (act) {
			strncpy(act->args[count].name, argname, IFNAMSIZ);
			act->args[count].type = t;
		}

		switch (t) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			vu8 = nla_get_u8(arg[HW_FLOW_ACTION_ARG_VALUE]);
			if (act)
				act->args[count].value_u8 = vu8;
			pfprintf(stdout, p, "%02x ", vu8);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			vu16 = nla_get_u16(arg[HW_FLOW_ACTION_ARG_VALUE]);
			if (act)
				act->args[count].value_u16 = vu16;
			pfprintf(stdout, p, "%i ", vu16);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			vu32 = nla_get_u32(arg[HW_FLOW_ACTION_ARG_VALUE]);
			if (act)
				act->args[count].value_u32 = vu32;
			pfprintf(stdout, p, "%i ", vu32);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			vu64 = nla_get_u64(arg[HW_FLOW_ACTION_ARG_VALUE]);
			if (act)
				act->args[count].value_u64 = vu64;
			pfprintf(stdout, p, "%llu ", vu64);
			break;
		default:
			break;
		}

		count++;
	}
	pfprintf(stdout, p, " )\n");
	return 0;
}

static int flow_table_matches_parse(struct nlattr *nl)
{
	struct hw_flow_field_ref ref = {.header = -1, };
	bool print_brace = false;
	struct nlattr *i;
	int err, rem;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		nl_to_hw_flow_field_ref(stdout, true, &ref, i, headers_names, fields_names);
		print_brace = true;
	}

	if (print_brace)
		fprintf(stdout, "]\n");
}

static int flow_table_actions_parse(struct nlattr *nl, int uid)
{
	struct nlattr *i;
	int err, rem;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
 		struct hw_flow_action act = {0};

		nl_to_sw_action(stdout, true, true, uid, &act, i, action_names);
	}
}

static int flow_table_attribs_parse(struct nlattr *nlattr)
{
	struct nlattr *table[HW_FLOW_TABLE_ATTR_MAX+1];
	struct nlattr *i;
	char *name;
	int uid, rem, err = 0;

	err = nla_parse_nested(table, HW_FLOW_TABLE_ATTR_MAX, nlattr, hw_flow_table_policy);
	if (err) {
		fprintf(stdout, "Warning parse error flow attribs, abort parse\n");
		return err;
	}

	name = table[HW_FLOW_TABLE_ATTR_NAME] ? nla_get_string(table[HW_FLOW_TABLE_ATTR_NAME]) : "<none>",
	uid = table[HW_FLOW_TABLE_ATTR_UID] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_UID]) : 0,

	fprintf(stdout, "%s:%i src %i size %i\n",
		name, uid,
		table[HW_FLOW_TABLE_ATTR_SOURCE] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_SOURCE]) : 0,
		table[HW_FLOW_TABLE_ATTR_SIZE] ? nla_get_u32(table[HW_FLOW_TABLE_ATTR_SIZE]) : 0);

	fprintf(stdout, "  matches:\n");
	if (table[HW_FLOW_TABLE_ATTR_MATCHES])
		flow_table_matches_parse(table[HW_FLOW_TABLE_ATTR_MATCHES]);

	fprintf(stdout, "  actions:\n");
	if (table[HW_FLOW_TABLE_ATTR_ACTIONS]) {
		flow_table_actions_parse(table[HW_FLOW_TABLE_ATTR_ACTIONS], uid);
	}

	return 0;
}

static int flow_table_table_parse(struct nlattr *nl)
{
	struct nlattr *i;
	int err, rem;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		flow_table_attribs_parse(i);
	fprintf(stdout, "\n");
}

struct nl_cache *link_cache;

static int flow_table_cmd_to_type(int valid, struct nlattr *tb[])
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
		fprintf(stdout, "%s (%i):\n", iface, ifindex);
		break;
	default:
		fprintf(stderr, "Unknown table identifier, abort\n");
		return -EINVAL;
	}

	return 0;
}

static void flow_table_cmd_get_tables(struct flow_msg *msg, int err)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(FLOW_TABLE_TABLES, tb))
		return;

	if (tb[FLOW_TABLE_TABLES])
		flow_table_table_parse(tb[FLOW_TABLE_TABLES]);
}

static struct nla_policy flow_get_field_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};


static int flow_table_field_parse(int hdr, struct nlattr *nl)
{
	struct nlattr *i;
	struct nlattr *field[HW_FLOW_FIELD_ATTR_MAX+1];
	int rem, err, count = 0;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		int uid, bitwidth;

		count++;

		err = nla_parse_nested(field, HW_FLOW_FIELD_ATTR_MAX, i, flow_get_field_policy);
		if (err) {
			fprintf(stderr, "Warning field parse error\n");
			return -EINVAL;
		}

		uid = field[HW_FLOW_FIELD_ATTR_UID] ? nla_get_u32(field[HW_FLOW_FIELD_ATTR_UID]) : 0;
		fields_names[hdr][uid] = strdup(field[HW_FLOW_FIELD_ATTR_NAME] ?
			nla_get_string(field[HW_FLOW_FIELD_ATTR_NAME]) : "<none>");
		bitwidth = field[HW_FLOW_FIELD_ATTR_BITWIDTH] ?
			nla_get_u32(field[HW_FLOW_FIELD_ATTR_BITWIDTH]) : 0;

		if (bitwidth >= 0)
			pfprintf(stdout, true, " %s:%i ", /*uid1,*/ fields_names[hdr][uid], bitwidth);
		else
			pfprintf(stdout, true, " %s:* ", /*uid1,*/ fields_names[hdr][uid]);

		if (!(count % 5))
			pfprintf(stdout, true, " \n\t");
	}	

	return count;
}

static struct nla_policy flow_get_header_policy[HW_FLOW_FIELD_ATTR_MAX+1] = {
	[HW_FLOW_HEADER_ATTR_NAME]	= { .type = NLA_STRING },
	[HW_FLOW_HEADER_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

static void flow_table_headers_parse(FILE *fp, bool p, struct nlattr *nl)
{
	struct nlattr *i;
	int rem, count;

	pfprintf(fp, p, "\nheaders:\n");

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *hdr[HW_FLOW_HEADER_ATTR_MAX+1];
		struct nlattr *fields, *j;
		int uid, err;

		err = nla_parse_nested(hdr, HW_FLOW_HEADER_ATTR_MAX, i, flow_get_header_policy);
		if (err) {
			fprintf(stderr, "Warning header parse error. aborting.\n");
			return;
		}

		uid = hdr[HW_FLOW_HEADER_ATTR_UID] ?
				nla_get_u32(hdr[HW_FLOW_HEADER_ATTR_UID]) : 0;
		headers_names[uid] = strdup(hdr[HW_FLOW_HEADER_ATTR_NAME] ?
				nla_get_string(hdr[HW_FLOW_HEADER_ATTR_NAME]) : "<none>");
		pfprintf(fp, p, "  %s {\n\t", headers_names[uid]);

		count = flow_table_field_parse(uid, hdr[HW_FLOW_HEADER_ATTR_FIELDS]);

		if (count % 5)
			pfprintf(fp, p, "\n\t");
		pfprintf(fp, p, " }\n");
	}
	return;
}


static void flow_table_cmd_get_headers(struct flow_msg *msg, int err)
{
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[FLOW_TABLE_MAX+1];

	err = genlmsg_parse(nlh, 0, tb, FLOW_TABLE_MAX, flow_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse get tables msg\n");
		return;
	}

	if (flow_table_cmd_to_type(FLOW_TABLE_HEADERS, tb))
		return;

	if (tb[FLOW_TABLE_HEADERS])
		flow_table_headers_parse(stdout, true, tb[FLOW_TABLE_HEADERS]);
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
	    type != FLOW_TABLE_CMD_GET_HEADERS) {
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
	NULL,
	NULL,
	NULL
};

void process_rx_message(void)
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
		type_cb[type](msg, err);
	}
	return;
}

void flow_usage()
{
	fprintf(stdout, "flow <dev> [get_tables | get_headers]\n");
}

int flow_send_recv(int family, int ifindex, int cmd)
{
	struct flow_msg *msg;

	/* open generic netlink socke twith flow table api */
	nsd = nl_socket_alloc();
	nl_connect(nsd, NETLINK_GENERIC);

	msg = alloc_flow_msg(cmd, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER_TYPE, FLOW_TABLE_IDENTIFIER_IFINDEX);
	nla_put_u32(msg->nlbuf, FLOW_TABLE_IDENTIFIER, ifindex);

	set_ack_cb(msg, handle_flow_table_get_tables);
	nl_send(nsd, msg->nlbuf);
	process_rx_message();

	return 0;
}

int main(int argc, char **argv)
{
	int family, err, ifindex;
	struct nl_sock *fd;
	int cmd = FLOW_TABLE_CMD_GET_TABLES;
	bool resolve_names = true;

	if (argc < 2 || argc > 3) {
		flow_usage();
		return 0;
	}

	if (argc == 3) {
		if (strcmp(argv[2], "get_tables") == 0) {
			cmd = FLOW_TABLE_CMD_GET_TABLES;
		} else if (strcmp(argv[2], "get_headers") == 0) {
			cmd = FLOW_TABLE_CMD_GET_HEADERS;
		} else {
			flow_usage();	
			return 0;
		}
	}

	/* Build cache to translate netdev's to names */
	fd = nl_socket_alloc();
	if ((err = nl_connect(fd, NETLINK_ROUTE)) < 0) {
		nl_perror(err, "Unable to connect socket");
		return err;
	}

	if ((err = rtnl_link_alloc_cache(fd, AF_UNSPEC, &link_cache)) < 0) {
		nl_perror(err, "Unable to allocate cache");
		return err;
	}
	if (!(ifindex = rtnl_link_name2i(link_cache, argv[1]))) {
		fprintf(stderr, "Unable to lookup %s", argv[1]);
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

	if (resolve_names && cmd != FLOW_TABLE_CMD_GET_HEADERS) {
		err = flow_send_recv(family, ifindex, FLOW_TABLE_CMD_GET_HEADERS);
		if (err)
			goto out;
	}

	flow_send_recv(family, ifindex, cmd);
out:
	nl_close(fd);
	nl_socket_free(fd);	
	return 0;
}
