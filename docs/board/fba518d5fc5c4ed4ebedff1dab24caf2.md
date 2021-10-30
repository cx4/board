---
id: fba518d5fc5c4ed4ebedff1dab24caf2
title: Apache Solr Velocity模版注入远程命令执行漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# Apache Solr Velocity模版注入远程命令执行漏洞预警

0x00 漏洞背景
---------


2019年10月31日，360CERT监测到国外的安全研究员S00pY在GitHub发布了Apache Solr Velocity模版注入远程命令执行的poc，经360CERT研判后该poc真实有效，360CERT判断漏洞等级严重，危害面/影响面广。目前Apache Solr官方未发布该漏洞的补丁，360CERT建议使用Apache Solr的用户采用修复建议中的措施进行防御，以免遭受黑客攻击。


0x01 漏洞详情
---------


该漏洞的产生是由于两方面的原因：


1. 当攻击者可以直接访问Solr控制台时，可以通过发送类似`/节点名/config`的POST请求对该节点的配置文件做更改。
2. `Apache Solr`默认集成`VelocityResponseWriter`插件，在该插件的初始化参数中的`params.resource.loader.enabled`这个选项是用来控制是否允许参数资源加载器在Solr请求参数中指定模版，默认设置是`false`。


当设置`params.resource.loader.enabled`为`true`时，将允许用户通过设置请求中的参数来指定相关资源的加载，这也就意味着攻击者可以通过构造一个具有威胁的攻击请求，在服务器上进行命令执行。


漏洞利用效果如下：


![public_image](https://p403.ssl.qhimgs4.com/t01d23bad9fecefb0a3.png)


0x02 影响版本
---------


经过测试，目前影响Apache Solr 5.x到8.2.0版本。


0x03 修复建议
---------


临时修补建议：


目前Apache Solr官方未发布该漏洞的补丁，360CERT建议确保网络设置只允许可信的流量与Solr进行通信。


0x04 时间线
--------


**2019-10-31** 360CERT监测到GitHub上出现漏洞poc


**2019-10-31** 360CERT发布预警


0x05 参考链接
---------


1. <https://gist.github.com/s00py/a1ba36a3689fa13759ff910e179fc133>


