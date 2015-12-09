####命令参数说明：  
	
	Usage: muls [optional flags][-h host|-l list] [-c cmd|-s shell script]
	-C=10: number of concurrency channel,max is 200
	-I=false: provide interactive menu
	-P="": authentication by password and the pass string goes after -P
	-c="": command to be excuted
	-debug=false: show debug message
	-fast=false: fast because not request a tty and do NOT verify hostname
	-h="": single host/ip
	-key="": authentication by key
	-l="": list of hosts/ips
	-o="/tmp/muls-1449199943-5.log": file to which details are output
	-p=false: authentication by password
	-sudo=false: need to provide sudo password if set
	-t=300: timeout, default value is 300s
	-u="": user name
	-v=false: verbose messages
	-version=false: show version messages

####使用举例：
- 指定多台设备执行命令

		[le.yu@MIS_CC_bridge3 ~]$ muls -c "uptime" -l list    # list 为设备列表文件，文件中每行为一个IP或者Hostname
		[100.00%]	Total    3 hosts/ips, Done:    3, Error:    0    # 默认只显示进度， 如需显示详情可加 -v 参数
		错误统计:
			
		The detail was written to /tmp/muls-1448364834.log    # 执行细节写入临时文件
	
	
	一般情况下只需要指定设备或者设备列表文件，命令或者脚本即可执行，正常情况下输出如上图所示。  
	下面的是出错情况：
		
		[le.yu@MIS_CC_bridge3 ~]$  muls -c "uptime" -l list -I               # 指定-I参数在命令执行完成之后显示交互菜单，可针对错误情况进行信息收集或者处理
		[100.00%]	Total    3 hosts/ips, Done:    3, Error:    3
		错误统计:                                                                   # 此处显示多种错误，包括服务器报错，程序执行非零返回值，不合法Host/IP,Hostname与ris记录不匹配
		服务器报错：1种,其中                                                          
			ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain：3台
		
		选择继续进行的操作：
		  1	列出所有出错服务器(如连接超时等)及其原因
		  2	列出所有命令返回值不为零的机器列表
		  3	列出所有不合法IP/HOST
		  4	列出所有HOSTNAME不匹配机器
		  5	在所有出错机器上面重试
		  6	只在Hostname不正确机器上面重试
		  7	只在命令返回值不正确机器上面重试
		  8	只在服务器本身出错(如连接超时等)机器上面重试
		  h	查看菜单
		  q	退出
		Please type: 1
		ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain
			CNC-TI-3-3WN
			CNC-TI-3-3WO
			CNC-TI-3-3WP
		Please type: q
		The detail was written to /tmp/muls-1448365111.log


- 指定多台设备执行sudo命令

		[le.yu@MIS_CC_bridge3 ~]$  muls -c "whoami" -l list -sudo -v
		Password: ******
		33.33%  CNC-TI-3-3WO        OK           1      [sudo] password for le.yu:                       # 第三列为机器状态， 第四列为命令Exit Code， 第五列为程序输出
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             sudo: 3 incorrect password attempts
		66.67%  CNC-TI-3-3WN        OK           1      [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             sudo: 3 incorrect password attempts
		100.00%  CNC-TI-3-3WP        OK           1      [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             [sudo] password for le.yu:
		                                             Sorry, try again.
		                                             sudo: 3 incorrect password attempts
		
		错误统计:
		命令返回值不为0：3台
		
		The detail was written to /tmp/muls-1448365570.log

- 指定单台设备执行脚本

		[le.yu@MIS_CC_bridge3 ~]$ muls -h "CNC-TI-3-3WG" -c "uptime" -fast -v                       # -fast 参数适用于执行单条指令（不指定sudo），并且不需要校验Hostname
		100.00%  CNC-TI-3-3WG        OK           0       19:50:10 up 102 days, 23:41,  0 users,  load average: 8.44, 7.48, 7.21
		错误统计:
		
		The detail was written to /tmp/muls-1448365809.log

- 通过key/password认证

		[le.yu@MIS_CC_bridge3 ~]$ muls -h "192.168.15.211" -c "whoami"  -v -u root -p      # -key指定私钥， -p 输入登陆密码， -P 后面接密码字符串
		Password: ***********************
		100.00%  192.168.15.211      OK           0      root
		
		错误统计:
		
		The detail was written to /tmp/muls-1448366006.log 
