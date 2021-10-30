---
id: 71298dc9abeaaab8430e91e9b3cbe9bd
title: Apple XNU内核缓冲区溢出预警
tags: 
  - 安全资讯
  - 360CERT
---

# Apple XNU内核缓冲区溢出预警

0x00 事件背景
---------


2018-10-31 lgtm团队的Kevin Backhouse在lgtm blog上发布了Apple XNU 内核在处理异常ICMP报文时候
触发的缓冲区溢出的一些细节分析，目前作者已经实现可以在同一局域网内使任意受影响的设备直接重启


并提及会在之后直接放出验证poc


0x01 影响版本
---------


Apple iOS 11 及以下: 全设备 


Apple macOS High Sierra, 10.13.6及以下: 全部设备


Apple macOS Sierra, 10.12.6及以下: 全部设备 


Apple OS X El Capitan 全版本: 全部设备


0x02 修复建议
---------


Apple iOS 11 及以下
(更新到 iOS 12)


Apple macOS High Sierra, 10.13.6及以下: 全部设备
(安装安全更新 2018-001)


Apple macOS Sierra, 10.12.6及以下: 全部设备 
(安装安全更新 2018-005)


Apple OS X El Capitan 全版本: 全部设备
(截至目前Apple尚未发布patch，建议更新至高版本)


0x03 漏洞验证
---------


发送数据包之前


![alt](https://p403.ssl.qhimgs4.com/t01ec58829c9728cde7.png)


发送数据包之后


![alt](https://p403.ssl.qhimgs4.com/t0144d79f21a29f84d9.png)


0x04 漏洞触发点
----------


位于公布XNU源码 `bsd/netinet/ip_icmp.c:339`



```
m_copydata(n, 0, icmplen, (caddr\_t)&icp->icmp_ip);

```

根据作者描述该代码是在函数`icmp_error`中，该函数的目的是生成错误类型的错误数据包以响应错误的数据包ip，它会遵从ICMP协议发送一个错误的消息


导致错误的数据包的header包含在ICMP消息中，因此在第339行调用m\_copydata的目的是将错误数据包的header复制到生成ICMP消息中，但问题在于没有校验该header是否会超过被拷贝缓冲区的大小，进而导致缓冲区溢出。


目标缓冲区是一个mbuf。mbuf是一种数据类型，用于存储传入和传出的网络数据包。
在此代码中，n是传入数据包（包含不受信任的数据），m是传出的ICMP数据包。
我们会看到，icp是指向m的指针。m在第294行或第296行分配：



```
if (MHLEN > (sizeof(struct ip) + ICMP_MINLEN + icmplen))
  m = m_gethdr(M_DONTWAIT, MT_HEADER);  /* MAC-OK */
else
  m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);

```

在第314行，mtod用于获取m的数据指针



```
icp = mtod(m, struct icmp *);

```

mtod只是一个宏，所以这行代码不会检查mbuf是否足以容纳icmp结构。
此外，数据不会复制到icp，而是复制到icp-> icmp\_ip，它与icp的偏移量为+8字节。


作者并没对XNU内核进详细的调试
基于作者在源代码中看到的，作者认为m\_gethdr创建了一个可以容纳88个字节的mbuf，对m\_getcl不太确定。
根据作者实际实验，发现当icmplen> = 84时会触发缓冲区溢出。



> 
> 总结
> 
> 
> 


从上述作者所提及的，该漏洞要利用起来还很困难。icmp的数据包的构造也并不详尽。复现尚有难度。360CERT建议大家尽快升级设备系统版本，以免遭受漏洞影响。


0x05 时间线
--------


**2018-08-09** 提交漏洞至apple安全团队


**2018-09-17** iOS 12 发布. 漏洞被修复.


**2018-09-24** macOS Mojave 发布. 漏洞被修复.


**2018-10-30** apple官方发布漏洞声明


**2018-10-31** lgtm团队发布部分细节


**2018-11-01** 360CERT发布预警


0x06 参考链接
---------


1. [lgtm 官方blog](https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407)
2. [apple 安全更新](https://support.apple.com/en-gb/HT209193)


