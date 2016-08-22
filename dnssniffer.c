/*	本程序主要功能是通过libpcap捕获DNS响应数据包，然后对数据包进行解析，若查询的域名错误则输出Name Error以及所查询的域名，如果正确则输出No Error以及所查询的域名和域名所对应的所有的IP地址 */
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <features.h>
#include <stdint.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>

#define check_packet_ptr(PKT,DATA,LEN) ((PKT) >= ((DATA) + (LEN)))

static char ipbuf[BUFSIZ];		/* 存储应答数据 */
static char domain[BUFSIZ];
static int subscript;
/* 解析后的TCP/UDP数据包结构*/
struct dispkt
{
	//源地址
	union
	{
		struct in6_addr ip6;
		uint32_t ip;
	} src_addr;

	//目的地址
	union
	{
		struct in6_addr ip6;
		uint32_t ip;
	} dest_addr;

	uint16_t src_port;			/* 源端口 */
	uint16_t dest_port;			/* 目的端口 */
	int family;					/* 地址族 */
	uint8_t ip_proto;			/* ip类型 */
	size_t payload_offset;		/* 有效载荷在数据包中的偏移量 */
	const u_char *payload;		/* 有效载荷 */
};

/* DNS首部  */
struct dnshdr
{
	u_short id;				//标识
	u_short flags;			//标志
	u_short question;		//问题数
	u_short answer;			//资源记录数
	u_short authRRs;		//授权资源记录数
	u_short addRRs;			//额外资源记录数
} __attribute__((packed));

int next_packet(pcap_t * phandle,int link_type);
int dissect_ip_packet(int link_type,struct pcap_pkthdr *header,const u_char *pkt_data,struct dispkt * dpkt);
int dissect_dns_packet(struct dispkt *dpkt,struct pcap_pkthdr *header);
void output_dns_query_domain(u_char *ptr,uint16_t qcount);
u_char * skip_to_answer(u_char *ptr,uint16_t qcount);
void get_dns_domain_name(u_char *ptr,const u_char * payload);

int main()
{
	char *device = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	static char *filter = "src port 53 and (udp or tcp)";
	bpf_u_int32 netmask,ip;
	struct bpf_program bpf;
	pcap_t *phandle;
	int link_type;
	 
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	device = pcap_lookupdev(errbuf);
	if(device == NULL)
	{
		perror(errbuf);
		return 0;
	}

	phandle = pcap_open_live(device,65535,0,500,errbuf);
	if(phandle == NULL)
	{
		perror(errbuf);
		return 0;
	}

	/* link_type链路层类型  */
	link_type = pcap_datalink(phandle);
	if(link_type != DLT_LINUX_SLL && link_type != DLT_EN10MB && 
			link_type != DLT_IPV4 && link_type != DLT_IPV6)
	{
		fprintf(stderr,"Unsupported link type: %d\n",link_type);
		return 0;
	}

	if(pcap_lookupnet(device,&ip,&netmask,errbuf) == -1)
	{
		ip = 0;
		netmask = 0;
	}

	if(pcap_compile(phandle,&bpf,filter,0,netmask) == -1 || pcap_setfilter(phandle,&bpf) == -1)
	{
		pcap_perror(phandle,"Error instaling filter:");
		return 0;
	}

	while(!next_packet(phandle,link_type));
	return 0;
}

/* return 0 on sucess, 1 on error  */
int next_packet(pcap_t * phandle,int link_type)
{
	struct pcap_pkthdr *pkt_hdr = NULL;
	struct dispkt dpkt;
	const u_char * pkt_data = NULL;
	int flag;

	flag = pcap_next_ex(phandle,&pkt_hdr,&pkt_data);
	if( flag < 0)
	{
		pcap_perror(phandle,"Error capturing packet\n");
		return 1;
	}
	else if (!flag)
		return 0;

	if(!pkt_hdr || !pkt_data)
	{
		printf("Dropping corrupted packet\n");
		return 1;
	}

	/* caplen应始终 <= len,否则很可能是pcap收到的数据包损坏，一般这种情况
       不会发生，除非内存损坏或者libpcap出现了什么错误	 */
	if(pkt_hdr->caplen > pkt_hdr->len)	
	{
		fprintf(stderr,"Dropping corrupted packet\n");
		return 1;
	}

	/* 解析数据包IP部分  */
	if(dissect_ip_packet(link_type,pkt_hdr,pkt_data,&dpkt))
		return 0;
	/* 解析数据包DNS部分*/
	dissect_dns_packet(&dpkt,pkt_hdr);

	return 0;
}

/* 解析IP包头 */
int dissect_ip_packet(int link_type,struct pcap_pkthdr *header,const u_char *pkt_data,struct dispkt * dpkt)
{
	const u_char *ptr = pkt_data;		/* pkt_data数据包首地址 */
	uint16_t protocol = 0;
	uint16_t ip_type;					/* IPv6 or IPv4 */
	const char * src_addr,*dest_addr;   /* 源IP地址和目的IP地址 */

	/*link_type:www.tcpdump.org/linktypes/ */
	switch(link_type)
	{
		case DLT_LINUX_SLL:  /* Linux "cooked capture encapsulation"*/
			/*DLT_LINUX_SLL 该类型数据链路层头部16字节*/
			protocol = ntohs(*(uint16_t *)(ptr + 14));
			ptr += 16;
			break;
		case DLT_EN10MB:	/* 以太网，以太网头部14字节  */
			printf("Source Mac:%02x:%02x:%02x:%02x:%02x:%02x	",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
			printf("Destination Mac:%02x:%02x:%02x:%02x:%02x:%02x\n",*(ptr+6),*(ptr+7),*(ptr+8),*(ptr+9),*(ptr+10),*(ptr+11));
			protocol = ntohs(*(uint16_t *)(ptr + 12));
			ptr += 14; //ETH_HLEN = 14
			break;
		case DLT_IPV4:		/* Raw IPv4; the packet begins with an IPv4 
							   header*/
			protocol = ETH_P_IP;
			break;
		case DLT_IPV6:		/* Raw IPv6; the packet begins with an IPv6 
							   header  */
			protocol = ETH_P_IPV6;
			break;
	}

	if(check_packet_ptr(ptr,pkt_data,header->len) || !protocol)
		return 1;

	ip_type = protocol;
	/* 获取IP数据包的协议类型  */
	switch(protocol)
	{
		case ETH_P_IP:
			protocol = ((struct iphdr *)ptr)->protocol;
			dpkt->src_addr.ip = ((struct iphdr *)ptr)->saddr;
			dpkt->dest_addr.ip = ((struct iphdr *)ptr)->daddr;
			dpkt->family = AF_INET;
			ptr += (((struct iphdr *)ptr)->ihl << 2);	/*左移2位求ip头部长度*/
			break;
		case ETH_P_IPV6:
			protocol = ((struct ip6_hdr *)ptr)->ip6_nxt;
			dpkt->src_addr.ip6 =  ((struct ip6_hdr *)ptr)->ip6_src;
			dpkt->dest_addr.ip6 =  ((struct ip6_hdr *)ptr)->ip6_dst;
			dpkt->family = AF_INET6;
			ptr += 40;		/* IPv6头部长度40字节*/
			break;
		default:
			protocol = 0;
			break;
	}

	if(check_packet_ptr(ptr,pkt_data,header->len) || !protocol)
		return 1;

	dpkt->ip_proto = protocol & 0xff;
	
	/* 处理TCP/UDP层 */
	switch(dpkt->ip_proto)
	{
		case IPPROTO_UDP:
			dpkt->src_port = ntohs(((struct udphdr *)ptr)->source);
			dpkt->dest_port = ntohs(((struct udphdr *)ptr)->dest);
			ptr += 8;		/* UDP头部长度8字节 */
			break;
		case IPPROTO_TCP:
			dpkt->src_port = ntohs(((struct tcphdr *)ptr)->source);
			dpkt->dest_port = ntohs(((struct tcphdr *)ptr)->dest);
			ptr += (((struct tcphdr *)ptr)->doff << 2);//  + 1; //需要+1吗？？？
			break;
		default:
			protocol = 0;
	}

	if(check_packet_ptr(ptr,pkt_data,header->len) || !protocol)
		return 1;

	dpkt->payload = ptr;
	dpkt->payload_offset = ptr - pkt_data;

	if(ip_type == ETH_P_IP)
	{
		memset(ipbuf,0,BUFSIZ);
		src_addr = inet_ntop(AF_INET,(const void *)&(dpkt->src_addr.ip),ipbuf,BUFSIZ);
		printf("Source IP:%s	",src_addr);
		memset(ipbuf,0,BUFSIZ);
		dest_addr = inet_ntop(AF_INET,(const void *)&(dpkt->dest_addr.ip),ipbuf,BUFSIZ);
		printf("Destination IP:%s\n",dest_addr);
	}
	else if(ip_type == ETH_P_IPV6)
	{
		memset(ipbuf,0,BUFSIZ);
		src_addr = inet_ntop(AF_INET6,(const void *)&(dpkt->src_addr.ip6),ipbuf,BUFSIZ);
		printf("Source IP:%s    ",src_addr);
		memset(ipbuf,0,BUFSIZ);
		dest_addr = inet_ntop(AF_INET6,(const void *)&(dpkt->dest_addr.ip6),ipbuf,BUFSIZ);
		printf("Destination IP:%s\n",dest_addr);
	}
	
	printf("Source Port:%u		Destination Port:%u\n",dpkt->src_port,dpkt->dest_port);
	return 0;
}

/* 解析DNS响应数据包输出DNS数据包相关信息 */
/* return 1 on fatal error, 0 otherwise */
int dissect_dns_packet(struct dispkt *dpkt,struct pcap_pkthdr *header)
{
	struct dnshdr * dh;
	u_char *ptr = NULL;
	const u_char * end;				/* 数据包尾部指针 */
	uint16_t rcode,query_type;	  /* query_type查询问题类型 */
	int i;
	const u_char *ip_addr;			/* ip 地址 */

	end = dpkt->payload + (header->len - dpkt->payload_offset);
	if(end < dpkt->payload)
		return 1;

	dh = (struct dnshdr *)(dpkt->payload);
	dh->id = ntohs(dh->id);
	dh->flags = ntohs(dh->flags);
	dh->question = ntohs(dh->question);
	dh->answer = ntohs(dh->answer);
	dh->authRRs = ntohs(dh->authRRs);
	dh->addRRs = ntohs(dh->addRRs);
	ptr = (u_char *)(dpkt->payload + 12);	/* 查询部分头部指针 */
		
	/* 返回码，表示响应的差错状态，通常为0或3 */
	rcode = dh->flags & 0x000f;
	switch(rcode)
	{
		case 0:
			printf("No Error\n");
			break;
		case 1:
			printf("Format Error\n");
			break;
		case 2:
			printf("Server Failure\n");
			break;
		case 3:
			printf("Name Error\n");
			break;
		case 4:
			printf("Not Implemented\n");
			break;
		case 5:
			printf("Refused\n");
			break;
		default:
			printf("Reserved Value\n");
			break;
	}
	
	if(dh->answer == 0)
	{
		printf("No Answer\n");
		output_dns_query_domain(ptr,dh->question);
		printf("\n\n");
		return 0;
	}
	else		/* 解析应答部分*/
	{
		ptr = skip_to_answer(ptr,dh->question);
		for(i = 0;i < dh->answer;i++)
		{
			if(ptr + 10 > end)		/*10表示Type,Class,TTL,Data Length的总长度*/
				return 1;

			memset(domain,0,BUFSIZ);
			subscript = 0;
			/* 解析应答内容即域名 */
			get_dns_domain_name(ptr,dpkt->payload);
			/* 解析应答类型,只需要A，AAAA类型 */
			ptr += 2;
			query_type =ntohs(*((uint16_t *)ptr));
			switch(query_type)
			{
				case 0x0001:	/* A type */
					printf("Domain Name:%s\n",&domain[1]);
					ptr += 10;
					memset(ipbuf,0,BUFSIZ);
					ip_addr = inet_ntop(AF_INET,(const void *)ptr,ipbuf,BUFSIZ);
					printf("IP Address:%s\n",ip_addr);
					ptr += 4;
					break;
				case 0x001c:	/* AAAA type */
					printf("Domain Name:%s\n",&domain[1]);
					ptr += 10;
					memset(ipbuf,0,BUFSIZ);
					ip_addr = inet_ntop(AF_INET6,(const void *)ptr,ipbuf,BUFSIZ);
					printf("IP Address:%s\n",ip_addr);
					ptr += 16;
					break;
				case 0x0005:	/* CNAME type */
					printf("Domain Name:%s\n",&domain[1]);
					memset(domain,0,BUFSIZ);
					subscript = 0;
					ptr += 10; 
					get_dns_domain_name(ptr,dpkt->payload);
					printf("CNAME:%s\n",&domain[1]);
					ptr += ntohs(*(uint16_t *)(ptr-2));
					break;
				default:
					printf("Domain Name:%s\n",&domain[1]);
					printf("Other Answer Type\n");
					ptr += 8;
					ptr += 2 + ntohs(*(uint16_t *)ptr);
					break;
			}
		}
		printf("\n\n");
		return 0;
	}
}

/* 若资源记录数为0，输出查询的域名 */
void output_dns_query_domain(u_char *ptr,uint16_t qcount)
{
	int i;
	for(i = 0;i < qcount;i++)
	{
		u_char *tmp = &domain[0];
		u_char *ttmp = ptr;
		memset(domain,0,BUFSIZ);

		while(*ptr)
		{
			*tmp = '.';
			memcpy(tmp+1,ptr+1,*ptr);
			tmp += *ptr + 1;
			ptr += *ptr + 1;
		}
		*tmp = '\0';
		printf("Domain Name:%s",&domain[1]);
		ptr += 5;
	}
}

/* 若资源记录数不为0，跳过查询问题部分到回答部分 */
u_char * skip_to_answer(u_char *ptr,uint16_t qcount)
{
	int i;
	for(i = 0;i < qcount;i++)
	{
		while(*ptr)
		{
			ptr++;
		}
		ptr += 5;
	}
	return ptr;
}

/* 参数ptr应答部分头指针，payload参数为DNS报文头指针 */
void get_dns_domain_name(u_char *ptr,const u_char * payload)
{
	u_char *tmp,*ttmp;
    ttmp = ptr;
	if(*ttmp == 0xc0)
	{
		int count;
		tmp = (u_char *)(payload + (*(ttmp+1)));
		for(count = 0;count <= *tmp;count++,subscript++)
		{
			if(count == 0)
				domain[subscript] = '.';
			else
				domain[subscript] = *(tmp+count);
		}
		tmp += count;
		if(*tmp == 0)
		{
			domain[subscript] = '\0';
			return ;
		}
		else
			get_dns_domain_name(tmp,payload);
	}
	else
	{
		int count;
		for(count = 0;count <= *ttmp;count++,subscript++)
		{
			if(count == 0x00)
				domain[subscript] = '.';
			else
				domain[subscript] = *(ptr+count);
		}
		ttmp += count;
		if(*ttmp == 0x00)
		{
			domain[subscript] = '\0';
			return ;
		}
		else
			get_dns_domain_name(ttmp,payload);
	}
}

