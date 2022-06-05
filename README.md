#### ssbc预言机系统

##### ssbc1和ssbc2跨链
1. 启动ssbc1和ssbc2两条链
2. 在config.toml配置链信息(name,端口号)和预言机节点信息(默认四个节点)
3. 本地6379端口开启redis server
4. 执行go build编译
5. 
```
启动服务：
sh ./startOracle.sh
停止服务：
sh ./stopOracle.sh
```
