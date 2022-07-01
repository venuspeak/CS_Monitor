常量：
1.today_attackIp：存储今天所有不在白名单里的IP，是个set表。
2.all_attackIP：存储从脚本运行开始所有不在白名单里的IP。
3.global all_attackIP_copy：全局变量: 复制一份 all_attackIP_copy 才能进行删除。原因是在脚本运行过程中，all_attackIP在遇到误报的IP时要把误报IP移除，从而减少列表的元素，然而在后续代码中要遍历all_attackIP，这个过程是列表动态变换的过程，python不允许在列表动态变化过程中继续遍历，会报错，所以copy一份是一种解决办法。下个today_attackIP_copy是同样的道理。
4.global today_attackIp_copy
5.global OK：全局变量: 这个是今日有效日志完成率。计算公式是，脚本运行开始累计处理的日志条数除以今日所有的日志条数
6.dev_list：CS设备的IP跟Session
7.second、minute、hour：请求获取CS日志的推迟时间，second、minute、hour。
8.req_num：每次请求CS日志获取的条数，定义 20000条。测试过一次获取15000条，貌似也没啥问题。
9.timeout：http请求响应超时时间
10.remove_attackIP：定义个set集合，存储移除掉的误报IP
11.http_proxy：外网代理
12.req_header：http请求头，固定的，定义成常量
13.Interval：cs监控频率的间隔时间，定义120秒
14.allLogNumbers：存储每次监控频率处理的日志条数
15.timeList：定义的时间列表，写死的时间，每到时间列表中，才开始处理攻击IP是否误报、进行IO写入，xlsx输出，攻击IP列表清零等操作
16.sourIP_whiteList：研判分析表中，源IP为安全扫描器和监控室ip
17.destIP_whiteList：研判分析表中，目的IP为集团的安全日志的 kafka 集群(安全日志)
18.dev_whiteList：研判分析表中，源IP为安全设备转发(无需重点关注)
19.proxy_whiteList：研判分析表中，IP为公网代理地址(无需重点关注)
20.overload_whiteList：研判分析表中，IP为负载域的地址(无需重点关注)
21.WhiteList1：白名单列表1，源
22.WhiteList2：白名单列表2，目的
23.global zz：zz 是处理SS()函数的时间
函数：
1.monitor() 函数
(1)功能1：获取 请求开始时间-请求结束时间内的日志条数，如果期间日志条数大于0，则将所有日志传给managerData函数处理，
(2)功能2： 计算有效日志完成率
(3)功能3：记录屏幕信息到文本文件
2.managerData(eventDict) 函数
(1)功能1： 从monitor函数中传来的数据是的json数据。遍历每一条数据（一条数据对应一个IP的相关字段）。将源IP、             目的IP从白名单中过滤掉，将源IP为 '已合并' 的字段过滤掉，通过每个源IP的事件等级（低=20，中=30，高=40）划分源IP。
(2)功能2： 创建 （低、中、高）、（源、目的）列表共6个，将低、中、高列表传给judge_lowLevel,jude_midLevel,judge_highLevel处理
(3)功能3： 将每一个源IP 添加到 today_attaclIP 和 all_attackIp 列表中
3.judge_lowLevel(lowLevel)、judge_middleLevel(midLevel)、judge_highLevel(highLevel)  三个函数
处理低、中、高危事件的数据：将获取的低、中、高 源IP列表生成为set(）表，并对IP地址进行排序。对于set()表中每一个源IP，获取请求开始时间到结束时间之间的日志条数，并输出到文本中。文本在monitorLog文件夹下，以monitor2022_xx_xx为名。
4.sendTime(rTime) 函数
重写请求开始-结束时间，具体到 年-月-日-时-分-秒。定义发送的时间，共25个时间点，分别是1-23点，23:40:00, 23:59:30。其中23:40:00是表示查询24小时之内的时间，23:59:30是一天中攻击IP清零的时间。
5.SS() 函数
当时间在定义的时间列表中时，则触发 analysisEvent()函数。
6.analysisEvent(rTime) 函数
(1)功能1：通过sendTime传过来的时间，遍历 today_attackIP列表中的源IP，处理每个源IP在当天的前10000条数据。将处理的10000条数据中，根据源IP，创建目的IP列表、攻击时间列表、事件ID列表、攻击事件类型列表，低危、中危、高危事件列表，并添加数据。将这些创建的列表字段传给 detailEvent函数处理，将detailEvent返回的数据传给xlsxContent处理
(2)功能2：如果从sendTime中传来的时间，即请求开始时间跟结束时间相等，则对today_attack、remove_attack 、allLogNumbers列表清零，并记录到文本文件中
7.detailEvent(eventIDList, eventTimeList, sourIPList, destIPList, eventNameList, logDict, lowLevelList, midLevelList,
highLevelList)  函数	
(1)功能1：根据源IP，事件ID，时间，等字段获取具体的事件细节。主要获取的是源端口跟目的端口
(2)功能2：自定义的规则，是为了处理误报的IP。规则才是脚本处理的核心
(3)功能3：返回处理后的7个字段
8.sendFeishu(out) 函数
具体发送给飞书的数据格式跟内容。共发送相关的7个字段到飞书群。分别是 时间、攻击ip、高、中、低危条数、低、中、高危条数跟事件类型。其中时间是从当天0点到发送时间这个时间段，条数是0点到发送点之间出现的总条数，事件类型是不重复的。每次查看飞书群，根据当前时间最近的时间节点查看。定义了10个飞书机器人，随机挑选机器人发送。
9.xlsxOutContent(x, rTime)， xlsxOut(outList) 函数
(1)功能：每隔一个小时，将每个攻击IP的相关16个字段全部记录到表格中。在eventXlsx目录下，创建以时间为名的文件夹，文件夹下是每隔1小时都会创建的表格
(2)功能：记录IP的相关16个字段到表格中。字段分别是：'设备IP', '攻击ip', '受害ip', '攻击端口', '受害端口', '一年之内最早的一条事件攻击时间', '当天攻击的总事件条数', '当天低危攻击事件类型', '当天中危攻击事件类型', '当天高危攻击事件类型', '本周攻击的总事件条数', '本月攻击的总事件条数', '两个月攻击的总事件条数', '三个月攻击的总事件条数','六个月攻击的总事件条数', '一年之内攻击的事件条数'
10.sendSingle(out) 函数
当出现误报的IP时，将IP记录到 errorLog文件夹里以时间命名的文件中。
11.oneMessage() 函数
发送给飞书群的测试消息

主函数
功能1：创建四个文件夹，分别记录屏幕输出信息、监控频率日志、表格分析日志、误报事件日志。文件夹名为 screenTxt、monitorLog、eventXlsx、errorLog
功能2：永真循环monitor()函数。
