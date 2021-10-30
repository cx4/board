---
id: df1ba30fbbfe62a3629dfef6ed96ac1c
title: VMWare 虚拟环境逃逸漏洞通告
tags: 
  - 安全资讯
  - 360CERT
---

# VMWare 虚拟环境逃逸漏洞通告

0x01 事件简述
---------


2020年11月25日，360CERT监测发现 `VMWare` 发布了 `VMSA-2020-0026` 的风险通告，漏洞编号为 `CVE-2020-4004,CVE-2020-4005` ，事件等级： `高危` ，事件评分： `8.8` 。

VMWare发布 `缓冲区溢出` 、 `权限提升` 两处漏洞

本地具有管理员权限的攻击者通过执行特制的二进制程序，可造成虚拟环境逃逸，并控制宿主主机/服务器。

 **两处漏洞均由Qihoo 360 Vulcan Team 在天府杯向VMWare提交** 

对此，360CERT建议广大用户及时将 `VMware软件` 升级到最新版本。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。

0x02 风险等级
---------

360CERT对该事件的评定结果如下



| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 高危 |
| 影响面 | 一般 |
| 360CERT评分 | 8.8 |

0x03 漏洞详情
---------

### CVE-2020-4004: 缓冲区/栈溢出漏洞

VMware ESXi，Workstation和Fusion在XHCI USB控制器(用于USB3.x协议接入)中包含一个Use-After-Free漏洞。 

本地具有管理员权限的攻击通过执行特制的二进制程序，可造成虚拟环境逃逸，并取得宿主主机/服务器控制权限。

### CVE-2020-4005: 权限提升漏洞

VMware ESXi存在一处特权升级漏洞。

本地具有VMX进程控制权限的攻击者通过执行特制的二进制程序，可在受影响的系统上获得权限提升（VMX进程权限提升到本地管理员）。

 **该漏洞可和CVE-2020-4004进行组合利用，最终控制宿主主机/服务器** 

0x04 影响版本
---------

- `vmware:esxi` : 6.5/6.7/7.0

- `vmware:fusion` : 11.x

- `vmware:vmware_cloud_foundation` : 3.x/4.x

- `vmware:workstation` : 11.x/15.x

0x05 修复建议
---------

### 通用修补建议

根据 `VMWare` 官方通告进行修复

[VMWare VMSA-2020-0026](https://www.vmware.com/security/advisories/VMSA-2020-0026.html)

### 临时修补建议

根据 VMWare 的建议移除 `XHCI` 控制器能有效的缓解漏洞影响

[VMWare-移除XHCI手册](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-ACA30034-EC88-491B-8D8B-4E319611C308.html)

