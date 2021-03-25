


#Search-Tools [![License](https://img.shields.io/aur/license/yaourt.svg)](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/LICENSE)[![GitHub stars](https://img.shields.io/github/stars/atdpa4sw0rd/Search-Tools)](https://github.com/atdpa4sw0rd/Search-Tools)
----------

**Search-Tools**
**集合比较常见的网络空间探测引擎**

**Fofa,Zoomeye,Quake,Shodan,Censys,BinaryEdge,threatbook**

<<<<<<< HEAD
**HW蓝队情报收集**
=======
## 1.5.3更新说明
```
1.增加搜索引擎开关
2.增加设置资产拉取数量
3.修复延迟6秒整理信息（如果没有整理可在查询一次）
4.添加小图标
5.增加结果自动保存到result文件夹下excel
6.修复线程冲突问题

```
>>>>>>> 02b5cac5870f3db0dc8a91744b2bfbd7fa74f25f

## 1.5.4更新说明
```
1.增加微步威胁情报
2.微步威胁情报日志存档
3.增加IP逆地址解析(GCJ-02坐标，然而并无卵用，后续会更换)
4.增加目标IP地图展示
注：需要配置微步API和百度地图API,在config.ini填写；
    有木有白嫖的情报源，告知一下谢谢
```
![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/ip_location.gif)


## 简单说明
- **ICO搜索目前只有Fofa,Shodan,Quake支持**
- **代理设置是防止在API请求过于频繁，或者在实战中，好多红队打开某一个搜索引擎，导致出口IP被封禁**
- **代理自动采集，或者从搜索引擎搜索相关的代理池**
- **存活代理IP日志保存一天，非存活代理IP保存2天 **
- **从搜索引擎调取过来的数据保存5天**
- **第一是节省积分，第二可以观察拉取的数据结构**
- **最后有个信息比对结果**
- **想要开启代理需要先验证代理**
- **Fofa,Quake的永久会员都很便宜**
- **Shodan黑五1美元一个，淘宝也有很多卖的**
- **censys,binaryedge都可以免费注册，但每个月只能查询250次**
- **大佬勿喷**

## 自定义APP规则说明
```
1.首先在apprule.json文件里添加三个引擎的app规则
  注意格式和标点符号(否则会报错)
  可以是三个搜索引擎官方带的app规则名(例如:app=泛微协同办公OA)
  可以是三个搜索引擎原始字符串搜索(例如:app=锐捷EG易网关)
  app=(名字任意)
{
    "app=泛微协同办公OA": {
        "fofa": "app=\"泛微-协同办公OA\"",
        "zoomeye": "app:\"泛微 协同办公OA\"",
        "quake": "app:\"泛微协同办公OA\""
    },
    "app=泛微云桥": {
        "fofa": "app=\"泛微-云桥e-Bridge\"",
        "zoomeye": "app:\"泛微云桥\"",
        "quake": "app:\"泛微-云桥e-Bridge\""
    },
    "app=锐捷EG易网关": {
        "fofa": "body=\"锐捷在线客服\"",
        "zoomeye": "锐捷在线客服",
        "quake": "app:\"锐捷-EG易网关\""
    }
}
2.在./temp/items文件中填入输入框联想词汇,这样在输入框填写APP等规则会有联想

ip=
ips=
port=
domain=
hostname=
title=
header=
body=
cert=
protocol=
status_code=
app=泛微协同办公OA
app=泛微云桥
app=锐捷EG易网关

```

## 使用指南

[![Python 3.9](https://img.shields.io/badge/python-3.9-yellow.svg)](https://www.python.org/) 
```
配置KEY
1.在config.ini里填写已有的api KEY

单语法搜索
1.IP: ip=10.20.30.1 
2.Cidr: ips=10.20.30.1/24 
3.Port: port=443 
4.domain: domain=XXX.com 
5.title: title=xxxx 
6.header: header=200 
7.body: body=xxx
8.status_code: status_code=200 
9.cert: cert=huawei
10.protocol: protocol=https

多语法搜索
and: ++
or: --
not: ^^
ips=10.20.30.1/24++protocol=https
ips=10.20.30.1/24--protocol=https
ips=10.20.30.1/24^^protocol=https

```

<<<<<<< HEAD
![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/search_tools.jpg)
![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/search_main.jpg)
=======
![image](https://ggithub.com//atdpa4sw0rd/Search-Tools/blob/main/search_tools.jpg)
![image](https://github.com//atdpa4sw0rd/Search-Tools/blob/main/search_main.jpg)
>>>>>>> 02b5cac5870f3db0dc8a91744b2bfbd7fa74f25f
![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/15a65458-5a94-4302-8bc6-66a82310e9f7.gif)







## 文件结构

    │  README.md  # 说明文档
    │  config.ini  # 配置文件
    │  items.py  # 调用提示符
    │  favicon.py  # 图标
    │  apprule.json  # app规则库
    │  rules.json  # 语法规则库
    │
    ├─temp
    │  ├─binaryedge_search.log #存储binaryedge日志
    │  ├─censys_search.log #存储censys日志
    │  ├─fofa_search.log #存储fofa日志
    │  ├─quake_search.log #存储quake日志
    │  ├─shodan_search.log #存储shodan储日志
    │  ├─zoomeye_search.log #存储zoomeye日志
    │  ├─rapiddns_search.log #存储shodan储日志
    │  ├─items #存储输入框提示符
    │  ├─proxylist #存储存活代理IP
    │  └─proxylist_unalive #存储非存活代理IP
    ├─result
    │  └─xxxxxxxx.xls #搜索结果
    ├─img
    │  └─*.png #小图标
    │
    └─icon
        └─xxx.ico # 存储Quake下载的ICO图标

## 1.5.3更新说明
```
1.增加搜索引擎开关
2.修复延迟6秒整理信息（如果没有整理可在查询一次）
3.添加小图标
4.增加结果自动保存到result文件夹下excel
5.修复线程冲突问题

```

## 1.5.2更新说明
```
1.增加自定义app规则(Fofa,Zoomeye,Quake支持app)
2.修复整合数据问题
3.增加Rapiddns域名反查、IP反查询
4.增加自定义输入框提示

```

