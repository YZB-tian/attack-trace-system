# 内核级系统调用监控验证（2026-09-10）

本文件记录在 Ubuntu DMZ 主机（03-Ubuntu-Web，192.168.60.30）上用 **bpftrace 内核
跟踪点** 采集进程、文件、网络行为的实验，用于补齐「系统调用拦截：在内核层监控所有
系统调用」的要求。监控与数据生产都在隔离靶场内完成。

## 1. 采集方式

`/tmp/<run>/trace.bt` 加载四个内核跟踪点，输出 `类型|毫秒|pid|进程名|载荷`：

| 跟踪点 | 对应系统调用 | 采集内容 |
| --- | --- | --- |
| `tracepoint:syscalls:sys_enter_execve` | execve | 可执行文件路径（进程创建边界） |
| `tracepoint:syscalls:sys_enter_openat` | openat | 被打开的文件路径 |
| `tracepoint:syscalls:sys_enter_connect` | connect | 目标 IPv4 地址与端口（sockaddr 解析，端口做字节序转换） |
| `tracepoint:syscalls:sys_enter_sendto` | sendto | 发送字节数 |

微秒级单调时钟（`nsecs`）通过目标机 `/proc/stat` 的 `btime` 换算成 UTC 墙上时间，
换算值经 `date -u` 与 `uptime` 交叉校验。

## 2. 实验与结果

| run | 窗口内容 | 跟踪记录 | 事件 | 告警 | 溯源阶段 |
| --- | --- | ---: | ---: | --- | --- |
| `kernel-monitor-20260910T181500Z` | 受控后渗透序列：读取 `/etc/passwd`、`/etc/hosts`，sudo 读取 `/etc/shadow`、`/etc/sudoers`，打包并上传 | open 637 / exec 18 / connect 41 / sendto 37 | 1145 | `HOST-LINUX-SUDO-TO-ROOT`、`HOST-LINUX-SENSITIVE-FILE-ACCESS` ×2 | collection:T1005 |
| `kernel-monitor-20260910T183000Z` | 单个 root 进程读取 `/etc/shadow` 后直接 POST 到 C2，形成同进程「存储→外传」链 | open 451 / exec 5 / connect 13 / sendto 25 | 929 | 同上 ×3 | collection:T1005 ×2 |

第二个 run 的同一 PID（2953）同时产生 `open /etc/shadow` 与 `connect 192.168.56.40:8080`，
因此溯源结果中的 `attribution.data_access_to_network_candidates` 由 0 变为 **10 条**，
即系统能够给出「先读凭据文件、后向外部地址通信」的完整候选路径（`content_transfer_proven`
仍为 false，因为字节内容是否外传需要接收侧证据）。

导入命令：

```powershell
python scripts/import_kernel_monitor.py --evidence-dir D:\AttackTraceLab\evidence\kernel-monitor-20260910T183000Z --output runtime/kernel-monitor2 --task-id task_kernel-monitor-20260910T183000Z --run-id kernel-monitor-20260910T183000Z --stix runtime/stix/enterprise-attack.json
```

## 3. 限制

1. bpftrace 是**跟踪点级**的内核观测，不是把所有系统调用都持久化落盘；本次只采集了
   进程创建、文件打开、连接与发送四类事件，读取/写入内容与参数未做全量记录。
2. 受内核版本限制，同样的方式无法用于 Metasploitable2（内核 2.6.24，无 eBPF），
   因此真实入侵链那两台靶标只有应用层日志与网络证据，没有 syscall 级证据。
3. `sendto` 事件没有对端地址，规则不会把它当作完整连接；只有 `connect` 带端点。
4. 受控序列由实验人员执行（授权范围内的后渗透动作模拟），不是对第三方的攻击。
