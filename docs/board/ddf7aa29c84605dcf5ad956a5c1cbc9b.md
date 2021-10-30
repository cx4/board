---
id: ddf7aa29c84605dcf5ad956a5c1cbc9b
title: 【在野利用】Apple Mail多个严重漏洞在野利用通告
tags: 
  - 安全资讯
  - 360CERT
---

# 【在野利用】Apple Mail多个严重漏洞在野利用通告

0x01 漏洞背景
---------


2020年04月24日， 360CERT监测发现安全取证公司`zecOps`在其博客中发布了一篇`Apple Mail`多个在野漏洞分析，该漏洞在一定的条件下可以无交互触发远程代码执行漏洞，漏洞等级：`严重`。


`Apple Mail`是iOS系统上默认的邮件管理应用程序，被广泛的应用于不同国家和地区。


`Apple Mail`存在多个漏洞，其中包含一个堆溢出漏洞最为严重，恶意攻击者可以向用户发送特制邮件触发攻击，完成远程代码执行。


该漏洞影响搭载iOS 6及更高版本（包括iOS 13.4.1）的iPhone和iPad。目前Apple官方仅提供了一个beta版本的补丁程序，还未出正式版补丁，漏洞还处于在野利用的状态。


对此，360CERT建议广大用户持续关注Apple官方系统更新推送，在iOS更新可用后及时安装最新补丁，以免遭受黑客攻击。 


0x02 风险等级
---------


360CERT对该事件的评定结果如下




| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 严重 |
| 影响面 | 广泛 |


0x03 漏洞详情
---------


zecOps发现iOS MIME库中MFMutableData的实现缺少对系统调用ftruncate()方法的异常检测，这将导致越界写入漏洞。同时zecOps还发现了一种无须等待系统调用失败即可触发ftruncate()导致越界写入漏洞的利用链。此外，他们还发现了一个可以远程触发的堆溢出漏洞。


当`Apple Mail`在处理下载的电子邮件时可以远程触发漏洞，不同的iOS版本所对应的漏洞利用尝试效果是不同的：


* 在iOS 12上尝试利用漏洞（成功/失败）后，用户可能会看到`Apple Mail`应用程序崩溃的现象
* 在iOS 13上，除了会造成系统暂时卡顿外，并无其他特征现象


失败的漏洞利用会致使用户收到`This message has no content`的邮件内容。


* 受影响的库：`/System/Library/PrivateFrameworks/MIME.framework/MIME`
* 存在漏洞方法：`-[MFMutableData appendBytes:length:]`


zecOps的安全研究员发现该漏洞被多个APT组织在野利用了2年，目前发现最早的在野利用可以追溯到2018年1月，影响面及其广泛。


0x04 影响版本
---------


* iOS 6及更高的版本，包括iOS 13.4.1
* 根据zecoOps的安全研究员所述，iOS 6之前的版本可能也容易受到攻击，目前还未进行验证


0x05 修复建议
---------


目前Apple官方仅提供了一个beta版本的补丁程序，还未出正式版补丁，漏洞还处于在野利用的状态。


360CERT建议广大用户持续关注Apple官方系统更新推送，在iOS更新可用后及时安装最新补丁。


0x06 时间线
--------


**2020-04-20** zecOps公司发布在野漏洞分析


**2020-04-24** 360CERT发布预警


0x07 参考链接
---------


1. [zecOps漏洞分析报告](https://blog.zecops.com/vulnerabilities/youve-got-0-click-mail/)

