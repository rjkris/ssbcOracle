#### ssbc预言机系统

##### ssbc1和ssbc2跨链测试(多节点共识版本)
1. 启动ssbc1和ssbc2两条链
2. 在config.toml配置链信息
3. 本地6379端口开启redis server
4. 执行go build编译
5. 执行./ssbcOracle n0, ./ssbcOracle n1, ./ssbcOracle n2 启动三个预言机节点
6. 开启新端口执行./ssbcOracle account 注册链账户
7. 继续执行./ssbcOracle dkg 开始分布式密钥生成
8. 预言机节点启动完成，前端调用跨链合约


