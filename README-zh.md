###muls
[![Build Status](https://travis-ci.org/nullne/muls.svg?branch=master)](https://travis-ci.org/nullne/muls)

根据`golang ssh` 实现ssh命令批量执行，有以下特性：

- 支持执行命令，脚本
- 支持多次无记忆交互，例如sudo输入密码
- 可选择过滤shell原始输出的特殊字符
- 支持tty/非tty模式执行命令

###muls-ctl
以`muls`为基础实现命令行批量ssh命令执行工具，具体细节见其文档

##muls-daemon
以`muls`为基础实现以消息队列为通信方式的批量命令执行服务，目前仅为demo版本
