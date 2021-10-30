---
id: 3b126a923aacefebd3a68beeb2e46cd6
title: 大量Android第三方ROM未正确配置导致信息泄漏预警
tags: 
  - 安全资讯
  - 360CERT
---

# 大量Android第三方ROM未正确配置导致信息泄漏预警

0x00 漏洞背景
---------


11月22日，Magisk作者topjohnwu发表文章，提到他在研究Fate/Grand Order手游的root检测机制时发现了存在于数百万台android设备上的漏洞，利用该漏洞会泄漏系统上的进程信息。


0x01 漏洞影响
---------


根据XDA论坛上的信息，受影响和不受影响的设备如下：




| 制造商 | 设备 | android版本 | 是否受该漏洞影响 |
| --- | --- | --- | --- |
| Asus | ZenFone 5Z | Android 8.0 Oreo | Yes |
| BlackBerry | KEY2 | Android 8.0 Oreo | No |
| Essential | PH-1 | Android 9 Pie | No |
| Google | Pixel 2 | Android 9 Pie | No |
| Google | Pixel 3 | Android 9 Pie | No |
| Google | Pixel 3 XL | Android 9 Pie | No |
| Honor | Magic 2 | Android 9 Pie | Yes |
| HTC | U12+ | Android 8.0 Oreo | Yes |
| Huawei | Mate 20 X | Android 9 Pie | Yes |
| LG | G7 ThinQ | Android 8.0 Oreo | Yes |
| LG | V40 ThinQ | Android 8.1 Oreo | Yes |
| Motorola | Moto G4 | Android 8.1 Oreo | No |
| Nokia | 7.1 | Android 8.1 Oreo | No |
| OnePlus | 6 | Android 8.1 Oreo/Android 9 Pie | Yes |
| OnePlus | 6T | Android 9 Pie | Yes |
| Razer | Phone 2 | Android 8.1 Oreo | Yes |
| Samsung | Galaxy Note 8 | Android 8.0 Oreo | No |
| Samsung | Galaxy Note 9 | Android 8.1 Oreo/Android 9 Pie | No |
| Samsung | Galaxy S7 | Android 8.0 Oreo | No |
| Samsung | Galaxy S8 | Android 8.0 Oreo | No |
| Samsung | Galaxy S9 | Android 9 Pie | No |
| Samsung | Galaxy S9+ (Exynos) | Android 8.0 Oreo | Yes |
| Sony | Xperia XZ1 | Android 9 Pie | No |
| Xiaomi | Mi Mix 2S | Android 9 Pie | Yes |
| Xiaomi | POCO F1 | Android 8.1 Oreo | Yes |


0x03 漏洞分析
---------


在linux系统中可以通过/proc文件系统访问到许多内核的内部信息。linux内核3.2以上增加了hidepid选项，该选项定义了一个用户可以查看到多少其它用户的信息。


hidepid=0：可以访问/proc/PID/下的所有文件


hidepid=1：如cmdline, io, sched*, status, wchan这样的敏感文件不允许他人访问


hidepid=2：在hidepid=1的基础之上/proc/PID/下的所有文件不允许他人访问


从android7.0开始，在挂载/proc时hidepid=2就应该被设置为2。在android9.0中SELinux得到了增强，如果APP编译时的目标API为API 28(Android 9.0)，那么即使没有设置hidepid=2一个进程也不能够获取其它进程的信息。然而现在很多APP编译时的目标API还低于API 28(Android 9.0)。


在最新的一加6T手机上可以看到并没有设置hidepid=2。


![alt](https://p403.ssl.qhimgs4.com/t0121f83c62eac550a0.png)


ps -A可以看到其它的进程。


![alt](https://p403.ssl.qhimgs4.com/t01b7ea4624b1486ace.png)


0x03 缓解措施
---------


目前部分OEM厂商已经得知了此问题，在系统更新发布之前，用户可以到 <https://github.com/topjohnwu/ProcGate/releases> 下载安装topjohnwu编写的检测工具，如果存在该漏洞屏幕上会显示其它进程的cmdline。


![alt](https://p403.ssl.qhimgs4.com/t0148ef2890afbe9b2f.jpeg)


如果具有root权限用户可以选择使用该APP运行“mount -o remount,hidepid=2,gid=3009 /proc”命令重新挂载/proc来修复该问题。存在漏洞但是没有root权限暂时不能修复的用户也不必过于担心，该漏洞的危害较为有限，仅能泄漏一些其它进程信息，不能通过该漏洞获取root权限或者用户密码等敏感数据。


0x04 时间线
--------


**2018-11-22** topjohnwu披露漏洞


**2018-11-23** 360CERT发布预警


0x04 参考链接
---------


1. [From Anime Game to Android System Security Vulnerability](https://medium.com/@topjohnwu/from-anime-game-to-android-system-security-vulnerability-9b955a182f20)
2. [How an Anime Game’s Root Detection led to the discovery of a Security Vulnerability in phones from LG, OnePlus, Huawei, Xiaomi, and others](https://www.xda-developers.com/procfs-leak-lg-oneplus-huawei-xiaomi-asus/)


