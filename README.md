# dnssniffer
本程序主要功能是通过libpcap捕获DNS响应数据包，然后对数据包进行解析，若查询的域名错误则输出Name Error以及所查询的域名，如果正确则输出No Error以及所查询的域名和域名所对应的所有的IP地址

编译：
gcc -O2 -o dnssniffer dnssniffer.c -lpcap -lpthread

使用：
需要管理员权限运行  sudo ./dnssniffer

输入:
程序运行后，会显示可用的网络设备(如下所示)，需要手动输入工作的网络设备.

All available network devices:
Device 1: ens33  Description: no description available  
Device 2: any  Description: Pseudo-device that captures on all interfaces  
Device 3: lo  Description: no description available  
Device 4: nflog  Description: Linux netfilter log (NFLOG) interface  
Device 5: nfqueue  Description: Linux netfilter queue (NFQUEUE) interface  
Device 6: usbmon1  Description: USB bus number 1  
Device 7: usbmon2  Description: USB bus number 2  

Suggestion device: ens33

Please select a device to capture packets:

输出，如下所示：

Source Mac:00:0c:29:09:d9:7d	Destination Mac:bc:46:99:e2:92:39
Source IP:192.168.1.1	Destination IP:192.168.1.104
Source Port:53		Destination Port:31173
No Error
Domain Name:www.baidu.com
IP Address:111.13.100.91


Source Mac:00:0c:29:09:d9:7d	Destination Mac:bc:46:99:e2:92:39
Source IP:192.168.1.1	Destination IP:192.168.1.104
Source Port:53		Destination Port:50194
No Error
Domain Name:www.baidu.com
CNAME:www.a.shifen.com

注意：
1、本程序设置网卡为非混杂模式，只能捕捉本机的DNS数据包。如需将网络接口置于混杂模式下，请手动修改dnssniffer.c:148行。同时sudo ifconfig eth0(所工作的网卡) promisc

2、本程序采用多线程工作模式，线程数默认为10，没有设置线程数参数输入，有兴趣者可以自行添加参数

3、本程序仍有不足，望改进

4、如果需要更高抓包效率，建议安装PF_RING，使用PF_RING自带的Libpcap,在本程序文件头添加#define HAVE_PF_RING，然后重新编译本程序，编译时需要加上-lpfring；也可以使用PF_RING自己的函数库<pfring.h>，请自行学习


