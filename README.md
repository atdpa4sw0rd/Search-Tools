


#Search-Tools [![License](https://img.shields.io/aur/license/yaourt.svg)](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/LICENSE)
----------

**Search-Tools**集合比较常见的网络空间探测引擎

**Fofa,Zoomeye,Quake,Shodan,Censys,BinaryEdge**


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

## 使用指南

[![Python 3.9](https://img.shields.io/badge/python-3.9-yellow.svg)](https://www.python.org/) 
```

1.IP ip=10.20.30.1 
2.Cidr ips=10.20.30.1/24 
3.Port port=443 
4.domain domain=XXX.com 
5.title title=xxxx 
6.header header=200 
7.body body=xxx
8.status_code status_code=200 
9.cert cert=huawei
10.protocol protocol=https

```

![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/search_tools.jpg)
![image](https://github.com/atdpa4sw0rd/Search-Tools/blob/main/15a65458-5a94-4302-8bc6-66a82310e9f7.gif)







## 文件结构

    │  README.md  # 说明文档
    │  config.ini  # 配置文件
    │  rule.json  # 集合搜索语句
    │
    ├─temp
    │  ├─binaryedge_search.log #存储binaryedge日志
    │  ├─censys_search.log #存储censys日志
    │  ├─fofa_search.log #存储fofa日志
    │  ├─quake_search.log #存储quake日志
    │  ├─shodan_search.log #存储shodan储日志
    │  ├─zoomeye_search.log #存储zoomeye日志
    │  ├─proxylist #存储存活代理IP
    │  └─proxylist_unalive #存储非存活代理IP
    │
    └─icon
        └─xxx.ico # 存储Quake下载的ICO图标
