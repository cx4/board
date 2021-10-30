---
id: ef3c5b6aabf73ca82da32df1c6e73aa2
title: Fortigate SSL VPN 漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# Fortigate SSL VPN 漏洞预警

0x00 漏洞背景
---------


360CERT观测到安全研究员Orange公布Fortigate SSL VPN多个安全漏洞。攻击者可以利用相应漏洞获取账号密码、修改账号密码和多洞结合获取系统SHELL。


0x01 漏洞详情
---------


### 漏洞编号及影响：


* CVE-2018-13379：任意文件读取漏洞
* CVE-2018-13381：缓冲区溢出漏洞
* CVE-2018-13382：magic 参数后门漏洞
* CVE-2018-13383：缓冲区溢出漏洞
* CVE-2018-13380: 跨站可执行脚本漏洞


其中，CVE-2018-13379，可以读取系统任意文件，CVE-2018-13382 可以任意修改系统账号密码，CVE-2018-13383结合任意文件读取漏洞可以GetShell。


### 漏洞分析：


#### CVE-2018-13379: 任意文件读取漏洞


系统获取相应语言文件时，使用以下方法构建文件路径：



```
snprintf(s, 0x40, "/migadmin/lang/%s.json", lang);

```
lang参数没有保护措施，但是生成的路径是读取json文件。利用snprintf函数的特性：‘格式化后的字符串长度 >= size，则只将其中的(size-1)个字符复制到str中’，使得格式化后的字符串长度大于size，json将被剥离，这样可以造成任意文件读取漏洞。


#### CVE-2018-13382：magic 参数后门漏洞


在系统登录时会提交一个magic参数，一旦此参数与后台硬编码字符串相符合，则攻击者可以修改任意用户密码。
![magic 参数后门漏洞](https://p403.ssl.qhimgs4.com/t0158c90385e0a1001f.png)
（注： 图片来自Orange博客）


#### CVE-2018-13383：缓冲区溢出漏洞


此处为WEB VPN功能漏洞。在系统解析javascript时，会将适应如下方式将内容考入缓冲区中



```
memcpy(buffer, js_buf, js_buf_len);

```
缓冲区固定大小为0x2000，但输入的字符串没有限制，此处可造成缓冲区溢出漏洞。


注意：相关漏洞利用脚本部分在已经在网上公开，不否认已经有攻击者开始利用此漏洞进行攻击。


0x02 影响版本
---------


* CVE-2018-13379：FortiOS 5.6.3 至 5.6.7、FortiOS 6.0.0 至 6.0.4 版本
* CVE-2018-13381：FortiOS 6.0.0至6.0.4、FortiOS 5.6.0至5.6.7 、FortiOS 5.4及以下版本
* CVE-2018-13382：FortiOS 6.0.0至6.0.4 、FortiOS 5.6.0至5.6.8 、FortiOS 5.4.1至5.4.10版本
* CVE-2018-13383：FortiOS 所有低于6.0.5 的版本
* CVE-2018-13380：FortiOS 6.0.0至6.0.4 、FortiOS 5.6.0至5.6.7、 FortiOS 5.4及以下版本


0x03 修复建议
---------


官网已发布相应更新，可以至以下链接获取：


 <https://fortiguard.com/psirt/FG-IR-18-384>


 <https://fortiguard.com/psirt/FG-IR-18-387>


 <https://fortiguard.com/psirt/FG-IR-18-389>


 <https://fortiguard.com/psirt/FG-IR-18-388>


 <https://fortiguard.com/psirt/FG-IR-18-383>


0x04 时间线
--------


* 2019年8月10日漏洞公开
* 2019年8月13日相关利用脚本公开
* 2019年8月16日360CERT发布预警


0x05 参考链接
---------


 <https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html?m=1>


 <https://fortiguard.com/psirt/FG-IR-18-384>


 <https://fortiguard.com/psirt/FG-IR-18-387>


 <https://fortiguard.com/psirt/FG-IR-18-389>


 <https://fortiguard.com/psirt/FG-IR-18-388>


 <https://fortiguard.com/psirt/FG-IR-18-383>


