---
id: d4c4efcb8e8effbed9827141a5be9daf
title: Linux包管理器snap本地提权漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# Linux包管理器snap本地提权漏洞预警

0x00 漏洞背景
---------


snap是一个Linux系统上的包管理软件。在Ubuntu18.04后默认预安装到了系统中。2019年2月13日，Chris Moberly公开了利用snap包管理工具的服务进程snapd中提供的REST API服务因对请求客户端身份鉴别存在问题从而提权的
漏洞细节。下面是利用已公开的exp进行提权成功后的截图。


![利用dirty_sockv1.py进行提权，需要外网连接](https://p403.ssl.qhimgs4.com/t01f07a31397b09ca9f.png)


![利用dirty_sockv2.py进行提权，无需网络连接](https://p403.ssl.qhimgs4.com/t01f61b2adf9d73b7f6.png)


0x01 漏洞影响
---------


利用该漏洞可以让普通用户伪装成root用户向snapd提供的REST API发送请求。攻击者利用精心构造的安装脚本或Ubuntu SSO可以让并不具有sudo权限的普通用户获得执行sudo的权限，从而获得提升到root用户权限的能力，达到本地
提权的效果。


0x02 漏洞细节
---------


snapd是snap包管理器的一个服务进程。它以root用户权限在后台运行，并允许普通用户以UNIX套接字的方式与其进行通信，并提供服务,其中一些特权操作需要鉴别用户身份(uid)才能执行。其中获取客户端信息的代码最终会使用ucrednetGet(如下)函数来获取客户端用户id，在该函数中会把字符串remoteAddr按";"分割后寻找"uid="字符串来判断当前用户的uid，通常情况下，remoteAddr大致为“ pid=5100;uid=1002;socket=/run/snapd.socket;@”这样的格式。从代码逻辑可以看出，后面出现的"uid="结果会覆盖前面得到的uid。攻击者利用这一点即可通过构造UNIX socket绑定地址，例如"/tmp/sock;uid=0;"。达到伪装root用户发出请求的目的。进而通过snapd执行一些特权操作达到提权的目的。



```
func ucrednetGet(remoteAddr string) (pid uint32, uid uint32, socket string, err error) {
...
    for _, token := range strings.Split(remoteAddr, ";") {
        var v uint64
...
        } else if strings.HasPrefix(token, "uid=") {
            if v, err = strconv.ParseUint(token[4:], 10, 32); err == nil {
                uid = uint32(v)
            } else {
                break
}

```
0x03 修复建议
---------


目前漏洞细节已经披露，官方也在2.37.1中予以修复。Ubuntu用户可以通过apt update && apt-get install snap ,将snap升级至最新版本予以修复。


0x04 时间线
--------


**2019-01-25** 研究人员向snap官方提交漏洞信息


**2019-02-13** 研究人员公开漏洞细节


**2019-02-14** 360CERT发布预警通告


0x05 参考链接
---------


1. <https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html>


