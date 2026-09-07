# Windows 日志模块

**输出只能是 `NormalizedEvent`。**

建议输入：EVTX/Sysmon 导出的日志或公开数据集中的 Windows 日志。
必须完成：
- 时间字段转换；
- host_id 映射；
- 用户/进程/文件等实体提取；
- 输出 `list[NormalizedEvent]`。

禁止修改公共模型。
