#ifndef _SNIFF_H
#define _SNIFF_H

#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET   14
#define SNAP_LEN        1518
#define	LIVE		    1
#define OFF_LINE	    (!LIVE)
#define CMD_LEN         2048

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	u_int th_seq;                   /* sequence number */
	u_int th_ack;                   /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
	u_char  th_flags;
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

struct pkg_info {
	char *id;
	int tcp_flag;
	int src_port;
	int dst_port;
	char *src_ip;
	char *dst_ip;
};

#endif /* _SNIFF_H */
