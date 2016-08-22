# dnssniffer
本程序主要功能是通过libpcap捕获DNS响应数据包，然后对数据包进行解析，若查询的域名错误则输出Name Error以及所查询的域名，如果正确则输出No Error以及所查询的域名和域名所对应的所有的IP地址

编译：
gcc -O2 -o dnssniffer dnssniffer.c -lpcap

程序仍有需要修改完善的地方，如未使用多线程，可以一个线程捕获数据包，另一个线程解析数据包；
