---
id: faad61d52c89c8fceaee08a5c7c36efe
title: Influxdb 认证绕过漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# Influxdb 认证绕过漏洞预警

0x00 漏洞背景
---------


2019年 5月 31日，360CERT监测到 @Moti Harmats 在 Komodosec 发布了 `InfluxDB` 数据库认证绕过漏洞的详细信息。恶意的攻击者可以轻松的获得数据库完整的控制权限，可以任意执行增删改操作。


360CERT 判断此次漏洞影响面广，危害严重。 `InfluxDB`官方已经及时完成版本更新迭代，建议广大用户及时更新，以免珍贵数据遭受损害。


0x01 漏洞详情
---------


@Moti Harmats 提及可以在如下路径进行用户名发现


`https://<influx-server-address>:8086/debug/requests`


![](https://p403.ssl.qhimgs4.com/t019e8fd7a2f3670dcb.png)


但实际测试的时候，此处不一定有明显的用户名返回。


但 `InfluxDB` 默认的 admin 用户，除非配置特殊指定，一般都是直接存在的。


利用用户名生成 jwt token 后即可获得完整的用户权限。


首先不带 jwt token 进行请求


![](https://p403.ssl.qhimgs4.com/t01e4bee3bd12cd1ef5.png)


带上 jwt token


![](https://p403.ssl.qhimgs4.com/t0142db56fd6e180331.png)


成功获得数据


尝试创建数据库


![](https://p403.ssl.qhimgs4.com/t01a7dd9d0d232654ab.png)
![](https://p403.ssl.qhimgs4.com/t0152c8f2da83d8845b.png)


成功创建数据库


1.7.6 版本修复


![](https://p403.ssl.qhimgs4.com/t01ec94888cc6b2d24f.png)


0x02 影响版本
---------


`InfluxDB` 1.7.5 及以下全版本


0x03 修复建议
---------


InfluxDB 官方已经完成修复，并且迭代新版本


360CERT 建议您及时更新到 `InfluxDB` 1.7.6 版本


0x04 时间线
--------


**2019-05-31** 360CERT监测到@Moti Harmats 发布漏洞信息


**2019-05-31** 360CERT发布预警


0x05 参考链接
---------


1. [When all else fails - find a 0-day](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day)
2. [Authentication and authorization in InfluxDB | InfluxData Documentation](https://docs.influxdata.com/influxdb/v1.7/administration/authentication_and_authorization/)


