# vip


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
