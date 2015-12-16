// server.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <time.h>
#include <WinSock2.h>

#include "pcap.h"
#include "pcap/pcap.h"
#define PCAP_OPENFLAG_PROMISCUOUS       1
#define PCAP_OPENFLAG_NOCAPTURE_LOCAL   8

static pcap_t*    vpn_adapter = NULL;
static SOCKET   vpn_socket = INVALID_SOCKET;

bool set_adapter_filter(pcap_t * handle, pcap_if_t * device, char * targetip)
{
	u_int netmask;
	char packet_filter[256];
	struct bpf_program fcode;

	/* setup our BPF filter */
	_snprintf(packet_filter, 256, "not host %s", targetip);

	/* try to determine the netmask of our device */
	if (device->addresses != NULL)
		netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	/* compile our pcap filter */
	if (pcap_compile(handle, &fcode, packet_filter, 1, netmask))
	{
		printf("Could not compile the filter: %s\n", targetip);
		return false;
	}

	/* set it up */
	if (pcap_setfilter(handle, &fcode) < 0)
	{
		printf("Could not set the filter\n");
		return false;
	}
	return true;
}

bool close_vpn_adapter()
{
	if (vpn_adapter != NULL)
	{
		pcap_close(vpn_adapter);
		vpn_adapter = NULL;
	}
	return true;
}

bool close_vpn_socket()
{
	if (vpn_socket != INVALID_SOCKET)
	{
		closesocket(vpn_socket);
		vpn_socket = INVALID_SOCKET;
	}
	return true;
}

pcap_t * open_vpn_adapter(char * adapter_addr, char* client_addr)
{
	char errbuf[PCAP_ERRBUF_SIZE + 128];
	pcap_if_t* alldevs = NULL;
	DWORD adapter_ip = inet_addr(adapter_addr);
	//获取所有网络设备列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		return NULL;
	}
	//查找指定IP地址的网络设备
	pcap_if_t* opened_device = NULL;
	for (pcap_if_t* device = alldevs; device && opened_device==NULL; device = device->next)
	{
		for (pcap_addr *addr = device->addresses; addr; addr = addr->next)
		{
			if (((struct sockaddr_in *)addr->addr)->sin_addr.S_un.S_addr == adapter_ip)
			{
				opened_device = device;
				break;
			}
		}
	}
	if (opened_device == NULL)
	{//没有找到指定IP地址的网络设备
		printf("Interface for '%s' not found\n", adapter_addr);
		pcap_freealldevs(alldevs);
		return NULL;
	}
	//打开网络设备
	pcap_t* adhandle =pcap_open_live(
		opened_device->name, // interface name 
		65536,                  // max packet size 
		PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL,  // promiscuous mode 
		1000,                   // read timeout in milliseconds 
		errbuf);
	if (adhandle == NULL)
	{//打开指定IP地址的网络设备失败
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", opened_device->name);
		pcap_freealldevs(alldevs);
		return NULL;
	}
	//设置数据包过滤器，抓取client_addr以外的所有数据包
	if (!set_adapter_filter(vpn_adapter, opened_device, client_addr))
	{
		pcap_freealldevs(alldevs);
		close_vpn_adapter();
		return NULL;
	}

	pcap_freealldevs(alldevs);
	return adhandle;
}

// 每次捕获到数据包时，libpcap都会自动调用这个回调函数
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	//发送数据包长度
	if (::send(vpn_socket, (char*)&header->len, 2, 0) != 2)
	{
		printf("Send packet length failed\n");
		pcap_breakloop(vpn_adapter);
		close_vpn_socket();
		return;
	}
	//发送数据包内容
	if (::send(vpn_socket, (char*)pkt_data, header->len, 0) != header->len)
	{
		printf("Send packet failed\n");
		pcap_breakloop(vpn_adapter);
		close_vpn_socket();
	}
}

//VPN通道数据接收、转发线程
//从VPN通道接收数据包及其长度，将其转发给网络设备
DWORD WINAPI vpn_recv_thread(void* param)
{
	int		pkt_len = 0;
	char		packet[0x10000];
	do
	{
		if (::recv(vpn_socket, (char*)pkt_len, 2, MSG_WAITALL)!=2)
		{
			printf("Recv packet length failed\n");
			break;
		}

		if (::recv(vpn_socket, packet, pkt_len, MSG_WAITALL) != pkt_len)
		{
			printf("Recv packet failed\n");
			break;
		}

		if (pcap_sendpacket(vpn_adapter, (u_char *)packet, pkt_len)==-1)
		{
			printf("pcap_sendpacket failed\n");
			break;
		}
	}while (true);
	close_vpn_socket();
	pcap_breakloop(vpn_adapter);
	return 0;
}

bool    start_vpn(char * adapter_addr, char* client_addr)
{
	vpn_adapter = open_vpn_adapter(adapter_addr, client_addr);
	if (vpn_adapter == NULL)
	{
		return false;
	}

	HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&vpn_recv_thread, (LPVOID)NULL, 0, NULL);
	if (th == NULL)
	{
		printf("CreateThread failed\n");
		close_vpn_adapter();
		return false;
	}

	// 开始捕获 ,直到进程结束时才返回
	pcap_loop(vpn_adapter, 0, packet_handler, NULL);
	
	close_vpn_socket();
	close_vpn_adapter();

	WaitForSingleObject(th, INFINITE);

	return 0;
}

bool    start_service(char * adapter_addr, int port, char* vpn_username, char* vpn_password)
{
	char vpn_cookie[256];
	int userlen = strlen(vpn_username);
	int passlen = strlen(vpn_password);

	if (userlen + 2 + passlen + 2 >= sizeof(vpn_cookie))
	{
		printf("VPN username or password too long\n");
		return false;
	}

	sprintf(vpn_cookie, "%s\r\n%s\r\n", vpn_username, vpn_password);
	int cookielen = strlen(vpn_cookie);
	
	SOCKET listen_socket = INVALID_SOCKET;

	//---Create streaming socket---
	if ((listen_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Socket");
		return false;
	}

	//---Initialize address/port structure---
	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(port);
	local_addr.sin_addr.s_addr = INADDR_ANY;

	//---Assign a port number to the socket---
	if (bind(listen_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) != 0)
	{
		perror("socket--bind"); 
		closesocket(listen_socket);
		return false; 
	}

	//---Make it a "listening socket"---
	if (listen(listen_socket, 1) != 0)
	{
		perror("socket--listen");
		closesocket(listen_socket);
		return false;
	}

	//---Forever... ---
	char userpass[256];
	struct sockaddr_in client_addr;
	int addrlen = sizeof(client_addr);
	
	char *client_ip = NULL;
	while (1)
	{
		addrlen = sizeof(client_addr);
		client_ip = NULL;

		//---accept a connection (creating a data pipe)---
		vpn_socket = accept(listen_socket, (struct sockaddr*)&client_addr, &addrlen);
		if (vpn_socket == INVALID_SOCKET)
		{
			perror("socket--accept");
			break;
		}
		client_ip = inet_ntoa(client_addr.sin_addr);
		printf("%s:%d connected\n", client_ip, ntohs(client_addr.sin_port));

		int len = ::recv(vpn_socket, userpass, cookielen, MSG_WAITALL);
		if (len == cookielen && memcmp(userpass, vpn_cookie, cookielen) == 0)
		{
			start_vpn(adapter_addr, client_ip);
			close_vpn_socket();
			closesocket(listen_socket);
			return true;
		}

		//---Close data connection---*/
		close_vpn_socket();
	}
	closesocket(listen_socket);
	return  false;
}

int help()
{
	printf("Usage:\n\tVPN local_ip port vpn_username vpn_password\n");
	printf("e.g:\n\tVPN 192.168.1.100 12345 vpn \"This is vpn password\"\n");
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 5) return help();
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	start_service(argv[1], atoi(argv[2]), argv[3], argv[4]);
	WSACleanup();
	return 0;
}

