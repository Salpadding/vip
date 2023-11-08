# 创建一个 dummy 设备绑 vip 便于本地访问ipvs
ip link show vip || ip link add vip type dummy
ip link set dev vip up
ip a add "192.168.1.199/32" dev vip 

