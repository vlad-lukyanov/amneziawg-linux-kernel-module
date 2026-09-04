// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal genetlink helper to configure amneziawg interfaces.
 * Usage: awg-set <ifname> [options...]
 *
 * Options mirror wg(8) plus AWG-specific: h1, h2, h3, h4, s1, s2, s3, s4,
 * jc, jmin, jmax, i1..i5, header-protection-key, random-trailers,
 * content-padding-addition.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define WG_KEY_LEN 32
#define WG_GENL_NAME "amneziawg"
#define WG_GENL_VERSION 3

/* Enums matching uapi/wireguard.h */
enum wg_cmd { WG_CMD_GET_DEVICE, WG_CMD_SET_DEVICE, __WG_CMD_MAX };
enum wgdevice_attribute {
	WGDEVICE_A_UNSPEC, WGDEVICE_A_IFINDEX, WGDEVICE_A_IFNAME,
	WGDEVICE_A_PRIVATE_KEY, WGDEVICE_A_PUBLIC_KEY, WGDEVICE_A_FLAGS,
	WGDEVICE_A_LISTEN_PORT, WGDEVICE_A_FWMARK, WGDEVICE_A_PEERS,
	WGDEVICE_A_JC, WGDEVICE_A_JMIN, WGDEVICE_A_JMAX,
	WGDEVICE_A_S1, WGDEVICE_A_S2, WGDEVICE_A_H1, WGDEVICE_A_H2,
	WGDEVICE_A_H3, WGDEVICE_A_H4, WGDEVICE_A_PEER,
	WGDEVICE_A_S3, WGDEVICE_A_S4,
	WGDEVICE_A_I1, WGDEVICE_A_I2, WGDEVICE_A_I3, WGDEVICE_A_I4, WGDEVICE_A_I5,
	WGDEVICE_A_HEADER_PROTECTION_KEY, WGDEVICE_A_CONTENT_PADDING_ADDITION,
	WGDEVICE_A_REKEY_AFTER_TIME, WGDEVICE_A_REKEY_TIMEOUT,
	WGDEVICE_A_REJECT_AFTER_TIME, WGDEVICE_A_KEEPALIVE_TIMEOUT,
	WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, WGDEVICE_A_RANDOM_TRAILERS,
	WGDEVICE_A_DISABLE_COOKIES,
	__WGDEVICE_A_LAST
};
#define WGDEVICE_A_MAX (__WGDEVICE_A_LAST - 1)

enum wgpeer_attribute {
	WGPEER_A_UNSPEC, WGPEER_A_PUBLIC_KEY, WGPEER_A_PRESHARED_KEY,
	WGPEER_A_FLAGS, WGPEER_A_ENDPOINT, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	WGPEER_A_LAST_HANDSHAKE_TIME, WGPEER_A_RX_BYTES, WGPEER_A_TX_BYTES,
	WGPEER_A_ALLOWEDIPS, WGPEER_A_PROTOCOL_VERSION, WGPEER_A_ADVANCED_SECURITY,
	WGPEER_A_RANGED_HEADERS, WGPEER_A_JUNK_OFFSETS, WGPEER_A_LAST_DATA_TIME,
	__WGPEER_A_LAST
};
#define WGPEER_A_MAX (__WGPEER_A_LAST - 1)

enum wgpeer_flag {
	WGPEER_F_REMOVE_ME = 1U << 0,
	WGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,
	WGPEER_F_UPDATE_ONLY = 1U << 2,
	WGPEER_F_HAS_ADVANCED_SECURITY = 1U << 3,
};

enum wgallowedip_attribute {
	WGALLOWEDIP_A_UNSPEC, WGALLOWEDIP_A_FAMILY, WGALLOWEDIP_A_IPADDR,
	WGALLOWEDIP_A_CIDR_MASK, WGALLOWEDIP_A_FLAGS,
	__WGALLOWEDIP_A_LAST
};

static int genl_fd;
static __u32 genl_id;

static inline __u16 nla_get_u16(struct nlattr *attr)
{
	return *(__u16 *)((char *)attr + NLA_HDRLEN);
}

static int send_recv(struct nlmsghdr *nlh, char *buf, int bufsize)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	int ret;

	ret = sendto(genl_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) return -errno;

	while (1) {
		ret = recv(genl_fd, buf, bufsize, 0);
		if (ret < 0) return -errno;
		nlh = (struct nlmsghdr *)buf;
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
			return err->error;
		}
		return ret;
	}
}

static int lookup_genl_family(const char *name)
{
	char buf[4096];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *nla;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;

	ghdr = NLMSG_DATA(nlh);
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;

	nla = (struct nlattr *)((char *)ghdr + GENL_HDRLEN);
	nla->nla_type = CTRL_ATTR_FAMILY_NAME;
	nla->nla_len = NLA_HDRLEN + strlen(name) + 1;
	memcpy((char *)nla + NLA_HDRLEN, name, strlen(name) + 1);
	nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);

	char reply[4096];
	int ret = send_recv(nlh, reply, sizeof(reply));
	if (ret < 0) return ret;

	struct nlmsghdr *rnlh = (struct nlmsghdr *)reply;
	struct nlattr *attrs[CTRL_ATTR_MAX + 1];
	int remain = rnlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	struct nlattr *attr = (struct nlattr *)((char *)NLMSG_DATA(rnlh) + GENL_HDRLEN);

	memset(attrs, 0, sizeof(attrs));
	while (remain >= (int)NLA_HDRLEN) {
		if (attr->nla_type <= CTRL_ATTR_MAX)
			attrs[attr->nla_type] = attr;
		int alen = NLA_ALIGN(attr->nla_len);
		remain -= alen;
		attr = (struct nlattr *)((char *)attr + alen);
	}

	if (!attrs[CTRL_ATTR_FAMILY_ID]) return -ENOENT;
	return nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
}

static int base64_decode(const char *src, unsigned char *dst, int dst_len)
{
	static const signed char b64_table[256] = {
		['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
		['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
		['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
		['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
		['Y'] = 24, ['Z'] = 25,
		['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
		['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
		['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
		['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
		['y'] = 50, ['z'] = 51,
		['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56,
		['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
		['+'] = 62, ['/'] = 63, ['='] = 0,
	};
	int i = 0, j = 0;
	uint32_t val = 0;
	int pad = 0;

	if (src[0] == '\0') return -1;

	while (src[i] && src[i] != '=') i++;
	/* Count padding */
	pad = (src[i] == '=') ? (src[i+1] == '=' ? 2 : 1) : 0;
	int data_len = i;
	int total = data_len + pad;
	int out_len = (total / 4) * 3 - pad;

	if (out_len > dst_len) return -1;

	/* Reset and re-decode properly */
	i = 0;
	j = 0;
	val = 0;
	int group = 0;
	while (j < out_len) {
		signed char c = b64_table[(unsigned char)src[i]];
		if (c < 0 && src[i] != '=') return -1;
		i++;
		val = (val << 6) | c;
		group++;
		if (group == 4) {
			if (j < out_len) dst[j++] = val >> 16;
			if (j < out_len) dst[j++] = (val >> 8) & 0xff;
			if (j < out_len) dst[j++] = val & 0xff;
			val = 0;
			group = 0;
		}
	}
	/* Handle remaining padding */
	if (group == 3) {
		val <<= 6;
		if (j < out_len) dst[j++] = val >> 16;
		if (j < out_len) dst[j++] = (val >> 8) & 0xff;
	} else if (group == 2) {
		val <<= 12;
		if (j < out_len) dst[j++] = val >> 16;
	}

	return j;
}

static void read_key_file(const char *path, unsigned char *key)
{
	FILE *f = fopen(path, "r");
	if (!f) { perror(path); exit(1); }
	char buf[64] = {0};
	if (!fgets(buf, sizeof(buf), f)) { fprintf(stderr, "empty key file\n"); exit(1); }
	int len = strlen(buf);
	while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
	int decoded = base64_decode(buf, key, WG_KEY_LEN);
	if (decoded != WG_KEY_LEN) { fprintf(stderr, "bad key length: %d\n", decoded); exit(1); }
	fclose(f);
}

static inline int nla_put(struct nlmsghdr *nlh, int attrtype, int attrlen, const void *data)
{
	int nla_len = NLA_HDRLEN + attrlen;
	int rta_len = NLA_ALIGN(nla_len);
	struct nlattr *nla = (struct nlattr *)((char *)nlh + nlh->nlmsg_len);

	if (nlh->nlmsg_len + rta_len > 8192) return -EMSGSIZE;
	nla->nla_type = attrtype;
	nla->nla_len = nla_len;
	memcpy((char *)nla + NLA_HDRLEN, data, attrlen);
	nlh->nlmsg_len += rta_len;
	return 0;
}

static inline int nla_put_u32(struct nlmsghdr *nlh, int attrtype, __u32 val)
{
	return nla_put(nlh, attrtype, sizeof(val), &val);
}

static inline int nla_put_u16(struct nlmsghdr *nlh, int attrtype, __u16 val)
{
	return nla_put(nlh, attrtype, sizeof(val), &val);
}

static inline int nla_put_u8(struct nlmsghdr *nlh, int attrtype, __u8 val)
{
	return nla_put(nlh, attrtype, sizeof(val), &val);
}

static inline int nla_put_u64(struct nlmsghdr *nlh, int attrtype, __u64 val)
{
	return nla_put(nlh, attrtype, sizeof(val), &val);
}

static inline int nla_put_flag(struct nlmsghdr *nlh, int attrtype)
{
	return nla_put(nlh, attrtype, 0, NULL);
}

static inline int nla_nest_start(struct nlmsghdr *nlh, int attrtype)
{
	struct nlattr *nla = (struct nlattr *)((char *)nlh + nlh->nlmsg_len);
	nla->nla_type = attrtype;
	nla->nla_len = NLA_HDRLEN;
	nlh->nlmsg_len += NLA_HDRLEN;
	return nlh->nlmsg_len - NLA_HDRLEN;
}

static inline int nla_nest_end(struct nlmsghdr *nlh, int start)
{
	struct nlattr *nla = (struct nlattr *)((char *)nlh + start);
	nla->nla_len = (char *)nlh + nlh->nlmsg_len - (char *)nla;
	return 0;
}

static int parse_key(const char *str, unsigned char *key)
{
	if (strncmp(str, "file:", 5) == 0) {
		read_key_file(str + 5, key);
		return 0;
	}
	return base64_decode(str, key, WG_KEY_LEN) == WG_KEY_LEN ? 0 : -1;
}

int main(int argc, char *argv[])
{
	char buf[8192];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	unsigned char private_key[WG_KEY_LEN] = {0};
	unsigned char psk[WG_KEY_LEN] = {0};
	unsigned char peer_pub[WG_KEY_LEN] = {0};
	const char *ifname = NULL;
	const char *privkey_path = NULL;
	const char *psk_path = NULL;
	const char *endpoint = NULL;
	const char *peer_pubkey = NULL;
	const char *allowed_ips = NULL;
	__u16 listen_port = 0;
	__u32 fwmark = 0;
	__u32 flags = 0;
	__u16 jc = 0, jmin = 0, jmax = 0;
	__u16 s1 = 0, s2 = 0, s3 = 0, s4 = 0;
	__u16 keepalive = 0;
	int has_h1 = 0, has_h2 = 0, has_h3 = 0, has_h4 = 0;
	__u64 h1 = 0, h2 = 0, h3 = 0, h4 = 0;
	int has_listen_port = 0, has_privkey = 0;
	int has_jc = 0, has_s1 = 0, has_s2 = 0, has_s3 = 0, has_s4 = 0;
	int has_flags = 0;
	int i;
	__u32 replace_allowedips = 0;
	int has_peer = 0;
	int has_keepalive = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname> [options...]\n", argv[0]);
		return 1;
	}
	ifname = argv[1];

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "listen-port") == 0 && i + 1 < argc) {
			listen_port = atoi(argv[++i]); has_listen_port = 1;
		} else if (strcmp(argv[i], "private-key") == 0 && i + 1 < argc) {
			privkey_path = argv[++i]; has_privkey = 1;
		} else if (strcmp(argv[i], "fwmark") == 0 && i + 1 < argc) {
			fwmark = atoi(argv[++i]);
		} else if (strcmp(argv[i], "jc") == 0 && i + 1 < argc) {
			jc = atoi(argv[++i]); has_jc = 1;
		} else if (strcmp(argv[i], "jmin") == 0 && i + 1 < argc) {
			jmin = atoi(argv[++i]); has_jc = 1;
		} else if (strcmp(argv[i], "jmax") == 0 && i + 1 < argc) {
			jmax = atoi(argv[++i]); has_jc = 1;
		} else if (strcmp(argv[i], "s1") == 0 && i + 1 < argc) {
			s1 = atoi(argv[++i]); has_s1 = 1;
		} else if (strcmp(argv[i], "s2") == 0 && i + 1 < argc) {
			s2 = atoi(argv[++i]); has_s2 = 1;
		} else if (strcmp(argv[i], "s3") == 0 && i + 1 < argc) {
			s3 = atoi(argv[++i]); has_s3 = 1;
		} else if (strcmp(argv[i], "s4") == 0 && i + 1 < argc) {
			s4 = atoi(argv[++i]); has_s4 = 1;
		} else if (strcmp(argv[i], "h1") == 0 && i + 1 < argc) {
			{ char *arg = argv[++i]; char *dash = strchr(arg, '-');
			if (dash) { *dash = 0; h1 = ((__u64)strtoull(dash+1,NULL,10) << 32) | strtoull(arg,NULL,10); }
			else { h1 = strtoull(arg, NULL, 10); } } has_h1 = 1;
		} else if (strcmp(argv[i], "h2") == 0 && i + 1 < argc) {
			{ char *arg = argv[++i]; char *dash = strchr(arg, '-');
			if (dash) { *dash = 0; h2 = ((__u64)strtoull(dash+1,NULL,10) << 32) | strtoull(arg,NULL,10); }
			else { h2 = strtoull(arg, NULL, 10); } } has_h2 = 1;
		} else if (strcmp(argv[i], "h3") == 0 && i + 1 < argc) {
			{ char *arg = argv[++i]; char *dash = strchr(arg, '-');
			if (dash) { *dash = 0; h3 = ((__u64)strtoull(dash+1,NULL,10) << 32) | strtoull(arg,NULL,10); }
			else { h3 = strtoull(arg, NULL, 10); } } has_h3 = 1;
		} else if (strcmp(argv[i], "h4") == 0 && i + 1 < argc) {
			{ char *arg = argv[++i]; char *dash = strchr(arg, '-');
			if (dash) { *dash = 0; h4 = ((__u64)strtoull(dash+1,NULL,10) << 32) | strtoull(arg,NULL,10); }
			else { h4 = strtoull(arg, NULL, 10); } } has_h4 = 1;
		} else if (strcmp(argv[i], "replace-allowed-ips") == 0) {
			replace_allowedips = 1; has_flags = 1;
		} else if (strcmp(argv[i], "peer") == 0 && i + 1 < argc) {
			peer_pubkey = argv[++i]; has_peer = 1;
		} else if (strcmp(argv[i], "preshared-key") == 0 && i + 1 < argc) {
			psk_path = argv[++i];
		} else if (strcmp(argv[i], "endpoint") == 0 && i + 1 < argc) {
			endpoint = argv[++i];
		} else if (strcmp(argv[i], "allowed-ips") == 0 && i + 1 < argc) {
			allowed_ips = argv[++i];
		} else if (strcmp(argv[i], "persistent-keepalive") == 0 && i + 1 < argc) {
			keepalive = atoi(argv[++i]); has_keepalive = 1;
		} else if (strcmp(argv[i], "peer-flags") == 0 && i + 1 < argc) {
			flags = atoi(argv[++i]); has_flags = 1;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			return 1;
		}
	}

	genl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
	if (genl_fd < 0) { perror("socket"); return 1; }

	genl_id = lookup_genl_family(WG_GENL_NAME);
	if (genl_id == 0) { fprintf(stderr, "Family %s not found\n", WG_GENL_NAME); return 1; }

	if (has_privkey) read_key_file(privkey_path, private_key);
	if (psk_path) read_key_file(psk_path, psk);
	if (peer_pubkey) {
		if (parse_key(peer_pubkey, peer_pub) < 0) { fprintf(stderr, "Bad peer pubkey\n"); return 1; }
	}

	/* Build SET_DEVICE message */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = genl_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;

	ghdr = NLMSG_DATA(nlh);
	ghdr->cmd = WG_CMD_SET_DEVICE;
	ghdr->version = WG_GENL_VERSION;

	/* Ifindex */
	int idx = if_nametoindex(ifname);
	if (idx == 0) { fprintf(stderr, "Interface %s not found\n", ifname); return 1; }
	nla_put_u32(nlh, WGDEVICE_A_IFINDEX, idx);

	/* Private key */
	if (has_privkey)
		nla_put(nlh, WGDEVICE_A_PRIVATE_KEY, WG_KEY_LEN, private_key);

	/* Listen port */
	if (has_listen_port)
		nla_put_u16(nlh, WGDEVICE_A_LISTEN_PORT, listen_port);

	/* FWmark */
	if (fwmark)
		nla_put_u32(nlh, WGDEVICE_A_FWMARK, fwmark);

	/* Replace allowed IPs */
	if (replace_allowedips)
		flags |= WGPEER_F_REPLACE_ALLOWEDIPS;

	/* AWG-specific device options */
	if (has_jc) {
		nla_put_u16(nlh, WGDEVICE_A_JC, jc);
		nla_put_u16(nlh, WGDEVICE_A_JMIN, jmin);
		nla_put_u16(nlh, WGDEVICE_A_JMAX, jmax);
	}
	if (has_s1) nla_put_u16(nlh, WGDEVICE_A_S1, s1);
	if (has_s2) nla_put_u16(nlh, WGDEVICE_A_S2, s2);
	if (has_s3) nla_put_u16(nlh, WGDEVICE_A_S3, s3);
	if (has_s4) nla_put_u16(nlh, WGDEVICE_A_S4, s4);
	if (has_h1) nla_put_u64(nlh, WGDEVICE_A_H1, h1);
	if (has_h2) nla_put_u64(nlh, WGDEVICE_A_H2, h2);
	if (has_h3) nla_put_u64(nlh, WGDEVICE_A_H3, h3);
	if (has_h4) nla_put_u64(nlh, WGDEVICE_A_H4, h4);

	/* Peer */
	if (has_peer) {
		int peer_start = nla_nest_start(nlh, WGDEVICE_A_PEERS);
		int peer_nest = nla_nest_start(nlh, 0);

		nla_put(nlh, WGPEER_A_PUBLIC_KEY, WG_KEY_LEN, peer_pub);

		if (has_flags)
			nla_put_u32(nlh, WGPEER_A_FLAGS, flags);

		if (psk_path)
			nla_put(nlh, WGPEER_A_PRESHARED_KEY, WG_KEY_LEN, psk);

		if (endpoint) {
			struct sockaddr_in addr4;
			struct sockaddr_in6 addr6;
			char ep_buf[256];
			char *colon;
			int port = 0;

			memset(&addr4, 0, sizeof(addr4));
			memset(&addr6, 0, sizeof(addr6));
			strncpy(ep_buf, endpoint, sizeof(ep_buf) - 1);
			ep_buf[sizeof(ep_buf) - 1] = 0;

			colon = strrchr(ep_buf, ':');
			if (colon) { *colon = 0; port = atoi(colon + 1); }

			if (inet_pton(AF_INET, ep_buf, &addr4.sin_addr) == 1) {
				addr4.sin_family = AF_INET;
				addr4.sin_port = htons(port);
				nla_put(nlh, WGPEER_A_ENDPOINT, sizeof(addr4), &addr4);
			} else if (inet_pton(AF_INET6, ep_buf, &addr6.sin6_addr) == 1) {
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = htons(port);
				nla_put(nlh, WGPEER_A_ENDPOINT, sizeof(addr6), &addr6);
			}
		}

		if (has_keepalive)
			nla_put_u16(nlh, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, keepalive);

		/* Parse allowed-ips */
		if (allowed_ips) {
			int ip_nest = nla_nest_start(nlh, WGPEER_A_ALLOWEDIPS);
			char *tmp = strdup(allowed_ips);
			char *saveptr, *token;
			token = strtok_r(tmp, ",", &saveptr);
			while (token) {
				char *slash = strchr(token, '/');
				if (slash) {
					*slash = 0;
					int cidr = atoi(slash + 1);
					struct in_addr addr4;
					struct in6_addr addr6;
					int family_nest = nla_nest_start(nlh, 0);
					__u16 family;
					if (inet_pton(AF_INET, token, &addr4) == 1) {
						family = AF_INET;
						nla_put_u16(nlh, WGALLOWEDIP_A_FAMILY, family);
						nla_put(nlh, WGALLOWEDIP_A_IPADDR, 4, &addr4);
					} else if (inet_pton(AF_INET6, token, &addr6) == 1) {
						family = AF_INET6;
						nla_put_u16(nlh, WGALLOWEDIP_A_FAMILY, family);
						nla_put(nlh, WGALLOWEDIP_A_IPADDR, 16, &addr6);
					} else {
						token = strtok_r(NULL, ",", &saveptr);
						continue;
					}
					nla_put_u8(nlh, WGALLOWEDIP_A_CIDR_MASK, cidr);
					nla_nest_end(nlh, family_nest);
				}
				token = strtok_r(NULL, ",", &saveptr);
			}
			free(tmp);
			nla_nest_end(nlh, ip_nest);
		}

		nla_nest_end(nlh, peer_nest);
		nla_nest_end(nlh, peer_start);
	}

	char reply[4096];
	int ret = send_recv(nlh, reply, sizeof(reply));
	if (ret < 0) {
		fprintf(stderr, "Netlink error: %s\n", strerror(-ret));
		return 1;
	}

	printf("OK: %s configured\n", ifname);
	return 0;
}
