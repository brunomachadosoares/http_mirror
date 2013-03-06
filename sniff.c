#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <X11/Xlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <signal.h>
#include <netdb.h>

#include "sniff.h"
#include "remote.h"

static void open_url(char *url)
{
	Display *dpy   = NULL;
	char *cmd[2]   = {0};
	char command[CMD_LEN];


	g_return_if_fail(url != NULL);

	dpy = XOpenDisplay(NULL);
	if(dpy == NULL) {
		fprintf(stderr, "Falha ao abrir display\n");
		return;
	}

	cmd[0] = command;
	cmd[1] = NULL;

	memset(command, 0, CMD_LEN);
	snprintf(command, 2048, "openUrl(%s)", url);

	mozilla_remote_commands(dpy, 0, cmd);
}

static char *parser_data(char *get, char *host)
{
	char *ptr  = NULL;
	char *url  = NULL;
	char **arr = NULL;


	g_return_val_if_fail(get != NULL , NULL);
	g_return_val_if_fail(host != NULL, NULL);

	ptr = strstr(host, " ");
	if(ptr != NULL) {
		ptr++;
	} else {
		return NULL;
	}

	arr = g_strsplit(get, " ", -1);
	if(arr == NULL) {
		fprintf(stderr, "NULL Pointer\n");
		return NULL;
	}

	url = g_strdup_printf("http://%s%s", ptr, arr[1]);

	g_strfreev(arr);

	return url;
}

static void parser_payload(char *payload)
{
	char **arr = NULL;
	char *get  = NULL;
	char *host = NULL;
	char *url  = NULL;


	g_return_if_fail(payload != NULL);

	arr = g_strsplit(payload, "\r\n", -1);
	if(arr == NULL) {
		fprintf(stderr, "NULL Pointer\n");
		return;
	}

	get  = g_strdup(arr[0]);
	host = g_strdup(arr[1]);

	url = parser_data(get, host);

	open_url(url);

	g_strfreev(arr);
}

static void packet_analyze(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int size_ip     = 0;
	int size_tcp    = 0;
	char *payload   = NULL;
	FILE *post_file = NULL;
	static int flag_post        = 0;
	const struct sniff_ip *ip   = NULL;
	const struct sniff_tcp *tcp = NULL;
	char **arr = NULL;

	g_return_if_fail(header != NULL);
	g_return_if_fail(packet != NULL);

	ip      = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = (IP_HL(ip) * 4);
	if (size_ip < 20) {
		fprintf(stderr, "Invalid IP header\n");
		return;
	}

	tcp      = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = (TH_OFF(tcp) * 4);
	if (size_tcp < 20) {
		fprintf(stderr, "Invalid TCP header\n");
		return;
	}

	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	post_file = fopen("post.txt", "a+");

	if(strstr(payload, "\r\n\r\n") != NULL) {
		if(flag_post == 1) {
			arr = g_strsplit(payload, "\r\n", -1);
			if(arr != NULL && g_strv_length(arr) >= 3 && post_file != NULL) {
				fprintf(post_file, "Line-Based [%s]\n\n\n", arr[3]);
			}
			flag_post = 0;
			g_strfreev(arr);
		}
	}

	if(strstr(payload, "POST") != NULL) {
		if(post_file != NULL) {
			fprintf(post_file, "%s\n", payload);
		}
		flag_post = 1;
	}

	if( strstr(payload, "GET") != NULL &&
		strstr(payload, "html") != NULL &&
		strstr(payload, "Referer") == NULL)
	{
		parser_payload(payload);
	}

	fclose(post_file);
}

static void pcap_init(int type, char *data, char *host)
{
	char *filter   = NULL;
	pcap_t *handle = NULL;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];


	g_return_if_fail(data != NULL);
	g_return_if_fail(host != NULL);

	if(type == LIVE) {
		handle = pcap_open_live(data, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Falha ao abrir device %s: %s\n", data, errbuf);
			return;
		}

	} else {
		handle = pcap_open_offline(data, errbuf);
		if(handle == NULL) {
			fprintf(stderr, "Falha: %s\n", errbuf);
			return;
		}
		pcap_file(handle);
	}

	if(strlen(host) > 1) {
		filter = g_strdup_printf("port 80 and host %s", host);
	} else { 
		filter = g_strdup_printf("port 80");
	}

	if (pcap_compile(handle, &fp, filter, 0, 0) == -1) {
		fprintf(stderr, "Falha ao compilar filtro %s: %s\n", filter, pcap_geterr(handle));
		return;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Falha ao utilizar filtro %s: %s\n", filter, pcap_geterr(handle));
		return;
	}

	pcap_loop(handle, -1, packet_analyze, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);
}

int main(int argc, char *argv[])
{
	if(argc != 4) {
		printf("usage: %s -i <device>  <host>  or\n", argv[0]);
		printf("usage: %s -p <capfile> <host>\n"    , argv[0]);
		return 1;
	}

	if(g_ascii_strncasecmp(argv[1], "-i", 2) == 0) {
		pcap_init(LIVE, argv[2], argv[3]);
	} else {
		pcap_init(OFF_LINE, argv[2], argv[3]);
	}

	return 0;
}
