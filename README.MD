# vip

## 原理

### arp 请求监测

因为 arp 请求是基于广播的， 所以我们可以使用 xdp 程序监听子网内对 vip 的 arp 解析请求，然后在收到请求后做出回复，这样对方就会认为这个 vip 的地址绑定的是本机了

### 选举

如果有多个 vip 后端节点，需要选举一个作为主节点，这里使用的算法就是通过健康监测+优先级排序，在健康节点中选择一个优先级最高的作为主节点

### 负载均衡

负载均衡器是运行在用户态的，主节点在收到tcp或者udp流量后，需要让linux主机把流量路由到应用端，所以需要创建一个 dummy interface，然后把 vip 绑定这个 dummy interface， 
这样linux内核就会认为自己拥有这个 vip

## 使用

配置vip 和 负载均衡器


```json
 [
        {
            "interface": "ens160",
            "dummyIf": "vip",
            "vips": [
                 "192.168.1.199"
            ],
            "discovery": {
                "port": 7777,
                "group": ["192.168.1.33", "192.168.1.39", "192.168.1.49"]
            },
            "lb": ["/usr/bin/caddy", "run", "--config", "Caddyfile"]
        }
 ]
```

配置 caddy 作为负载均衡器

```Caddyfile
http://:80 {
    reverse_proxy {
        to http://192.168.1.33:30737 http://192.168.1.39:30737 http://192.168.1.49:30737
        lb_policy ip_hash
        health_uri /
        health_headers {
            Host localhost
        }
        health_status 404
    }
}
```
