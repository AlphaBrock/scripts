#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: Debian7/8, Ubuntu14+, Centos6/7
#	Description: Install the ShadowsocksR server
#	Version: 1.1 (中文)
#	Author: Toyo + AlphaBrock                      
#=================================================

#Check Root
[ $(id -u) != "0" ] && { echo "${CFAILURE}错误：你必须以root用户运行此脚本${CEND}"; exit 1; }

config_file="/usr/local/shadowsocksr/config.json"
config_user_file="/usr/local/shadowsocksr/config.json"
Libsodiumr_file="/root/libsodium-1.0.11"

#检查系统
check_sys(){
    local checkType=$1
    local value=$2

    local OS=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        OS="Centos"
        systemPackage="yum"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        OS="Debian"
        systemPackage="apt"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        OS="Ubuntu"
        systemPackage="apt"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        OS="Centos"
        systemPackage="yum"
    elif cat /proc/version | grep -q -E -i "debian"; then
        OS="Debian"
        systemPackage="apt"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        OS="Ubuntu"
        systemPackage="apt"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        OS="Centos"
        systemPackage="yum"
    fi

    if [[ ${checkType} == "sysRelease" ]]; then
        if [ "$value" == "$OS" ]; then
            return 0
        else
            return 1
        fi
    elif [[ ${checkType} == "packageManager" ]]; then
        if [ "$value" == "$systemPackage" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Get version
getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else    
        grep -oE  "[0-9.]+" /etc/issue
    fi    
}
# CentOS version
centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi   
}

# 关闭 selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

#获取用户账号信息
getUser(){
	# 获取IP
	ip=`curl -s http://members.3322.org/dyndns/getip`
	if [ -z $ip ]; then
		ip="ip"
	fi
	port=`jq '.server_port' ${config_user_file}`
	password=`jq '.password' ${config_user_file} | sed 's/^.//;s/.$//'`
	method=`jq '.method' ${config_user_file} | sed 's/^.//;s/.$//'`
	protocol=`jq '.protocol' ${config_user_file} | sed 's/^.//;s/.$//'`
	obfs=`jq '.obfs' ${config_user_file} | sed 's/^.//;s/.$//'`
}


#设置用户账号信息
setUser(){
    # 不支持 CentOS 5
    if centosversion 5; then
        echo -e "\033[41;37m [错误] \033[0m 暂不支持 CentOS 5, 请更换系统到 CentOS 6+/Debian 7+/Ubuntu 14+ 后再尝试一遍."
        exit 1
    fi
	#设置端口
	while true
	do
	echo -e "请输入ShadowsocksR账号的 端口 [1-65535]:"
	read -p "(默认端口: 2333):" ssport
	[ -z "$ssport" ] && ssport="2333"
	expr ${ssport} + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ ${ssport} -ge 1 ] && [ ${ssport} -le 65535 ]; then
			echo
			echo "========================================="
			echo -e "	端口 : \033[41;37m ${ssport} \033[0m"
			echo "========================================="
			echo
			break
		else
			echo "输入错误，请输入正确的数字 !"
		fi
	else
		echo "输入错误，请输入正确的数字 !"
	fi
	done
	#设置密码
	echo "请输入ShadowsocksR账号的 密码:"
	read -p "(默认密码: alphabrock.cn):" sspwd
	[ -z "${sspwd}" ] && sspwd="alphabrock.cn"
	echo
	echo "========================================="
	echo -e "	密码 : \033[41;37m ${sspwd} \033[0m"
	echo "========================================="
	echo
	#设置加密方式
	echo "请输入ShadowsocksR账号的 加密方式:"
	echo "1. rc4-md5"
	echo "2. aes-128-cfb"
	echo "3. aes-256-cfb"
	echo "4. chacha20"
	echo "5. camellia-128-cfb"
	echo "6. camellia-256-cfb"
	echo
	read -p "(默认加密方式: chacha20):" ssmethod
	[ -z "${ssmethod}" ] && ssmethod="4"
	if [ ${ssmethod} == "1" ]; then
		ssmethod="rc4-md5"
	elif [ ${ssmethod} == "2" ]; then
		ssmethod="aes-128-cfb"
	elif [ ${ssmethod} == "3" ]; then
		ssmethod="aes-256-cfb"
	elif [ ${ssmethod} == "4" ]; then
		ssmethod="chacha20"
	elif [ ${ssmethod} == "5" ]; then
		ssmethod="camellia-128-cfb"
	elif [ ${ssmethod} == "6" ]; then
		ssmethod="camellia-256-cfb"
	else
		ssmethod="chacha20"
	fi
	echo "========================================="
	echo -e "	加密方式 : \033[41;37m ${ssmethod} \033[0m"
	echo "========================================="
	echo
	#设置协议
	echo "请输入数字 来选择ShadowsocksR账号的 协议:"
	echo "1. origin"
	echo "2. verify_sha1"
	echo "3. auth_sha1_v2"
	echo "4. auth_sha1_v4"
	echo "5. auth_aes128_md5"
	echo "6. auth_aes128_sha1"
	echo -e "\033[42;37m [Tip] \033[0m : 如果协议是origin，那么混淆也必须是plain !"
	echo
	read -p "(默认协议: auth_sha1_v4):" ssprotocol
	[ -z "${ssprotocol}" ] && ssprotocol="4"
	if [ ${ssprotocol} == "1" ]; then
		ssprotocol="origin"
	elif [ ${ssprotocol} == "2" ]; then
		ssprotocol="verify_sha1"
	elif [ ${ssprotocol} == "3" ]; then
		ssprotocol="auth_sha1_v2"
	elif [ ${ssprotocol} == "4" ]; then
		ssprotocol="auth_sha1_v4"
	elif [ ${ssprotocol} == "5" ]; then
		ssprotocol="auth_aes128_md5"
	elif [ ${ssprotocol} == "6" ]; then
		ssprotocol="auth_aes128_sha1"
	else
		ssprotocol="auth_sha1_v4"
	fi
	echo
	echo "======================================="
	echo -e "	协议 : \033[41;37m ${ssprotocol} \033[0m"
	echo "======================================="
	echo
	#设置混淆
	if [ ${ssprotocol} != "origin" ];
	then
		echo "请输入数字 来选择ShadowsocksR账号的 混淆:"
		echo "1. http_simple"
		echo "2. http_post"
		echo "3. random_head"
		echo "4. tls1.2_ticket_auth"
		echo -e "\033[42;37m [Tip] \033[0m : 如果协议是origin，那么混淆也必须是plain !"
		echo
		read -p "(默认混淆: tls1.2_ticket_auth):" ssobfs
		[ -z "${ssobfs}" ] && ssobfs="4"
		if [ ${ssobfs} == "1" ]; then
			ssobfs="http_simple"
		elif [ ${ssobfs} == "2" ]; then
			ssobfs="http_post"
		elif [ ${ssobfs} == "3" ]; then
			ssobfs="random_head"
		elif [ ${ssobfs} == "4" ]; then
			ssobfs="tls1.2_ticket_auth"
		else
			ssobfs="tls1.2_ticket_auth"
		fi
	else
		ssobfs="plain"
	fi
	echo
	echo "======================================="
	echo -e "	混淆 : \033[41;37m ${ssobfs} \033[0m"
	echo "======================================="
	echo
	#询问是否设置 协议/混淆 兼容原版
	#if [ ${ssprotocol} != "origin" ];
	#then
		#if [ ${ssobfs} != "plain" ];
		#then
			#read -p "是否设置 混淆和协议 兼容原版 ( _compatible )? [Y/n] :" yn1
			#[ -z "${yn1}" ] && yn1="y"
			#if [[ $yn1 == [Yy] ]];
			#then
				#ssobfs=${ssobfs}"_compatible"
				#ssprotocol=${ssprotocol}"_compatible"
			#fi
		#fi
	#fi
	#最后确认
	echo
	echo "========================================="
	echo "      请检查Shadowsocks账号配置是否有误 !"
	echo
	echo -e "	端口 : \033[42;37m ${ssport} \033[0m"
	echo -e "	密码 : \033[42;37m ${sspwd} \033[0m"
	echo -e "	加密方式 : \033[42;37m ${ssmethod} \033[0m"
	echo -e "	协议 : \033[42;37m ${ssprotocol} \033[0m"
	echo -e "	混淆 : \033[42;37m ${ssobfs} \033[0m"
	echo "========================================="
	echo
	read -p "请按任意键继续，如有配置错误请使用 Ctrl+C 退出。" var
}
#显示用户账号信息
viewUser(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	
	getUser
	#base64加密
	#SSRprotocol=`echo ${protocol} | sed 's/_compatible//g'`
	#SSRobfs=`echo ${obfs} | sed 's/_compatible//g'`
	#SSbase64=`echo -n "${method}:${password}@${ip}:${port}" | base64`
	SSRPWDbase64=`echo -n "${password}" | base64`
	SSRbase64=`echo -n "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}" | base64`
	#SSurl="ss://"${SSbase64}
	#SSRurl="ssr://"${SSRbase64}
	SSQRcode="http://pan.baidu.com/share/qrcode?w=300&h=300&url="${SSurl}
	SSRQRcode="http://pan.baidu.com/share/qrcode?w=300&h=300&url="${SSRurl}
	clear
	echo "############################################################"
	echo
	echo -e "	你的ShadowsocksR 账号配置 : "
	echo
	echo -e "	I P: \033[42;37m ${ip} \033[0m"
	echo -e "	端口: \033[42;37m ${port} \033[0m"
	echo -e "	密码: \033[42;37m ${password} \033[0m"
	echo -e "	加密方式: \033[42;37m ${method} \033[0m"
	echo -e "	协议: \033[42;37m ${protocol} \033[0m"
	echo -e "	混淆: \033[42;37m ${obfs} \033[0m"
	echo
	echo -e "	SS链接: \033[42;37m ${SSurl} \033[0m"
	echo -e "	SS二维码: \033[42;37m ${SSQRcode} \033[0m"
	echo -e "	SSR链接: \033[42;37m ${SSRurl} \033[0m"
	echo -e "	SSR二维码: \033[42;37m ${SSRQRcode} \033[0m"
	echo
	echo -e "提示："
	echo -e "在浏览器中，打开上面的二维码链接，就可以看到二维码图片了"
	echo -e "协议和混淆后面的[ _compatible ]，指的是兼容原版Shadowsocks协议混淆。"
	echo
	echo "############################################################"
}

#防火墙设置
firewall_set(){
	echo -e "\033[42;37m [Tips] \033[0m 开始设置防火墙..."	 
    if check_sys packageManager apt; then
	        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
	        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
    elif centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep '${ssport}' | grep 'ACCEPT' > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "\033[41;37m [警告]:  \033[0m 端口 ${ssport} 已经存在."
            fi
        else
            echo -e "\033[41;37m [警告]:  \033[0m iptables 似乎未运行或者未安装，如有必要请手动设置...."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ];then
            firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
            firewall-cmd --reload
        else
            echo -e "\033 [41;37m [警告]:  \033[0m Firewalld 似乎未运行，正在尝试启动..."
            systemctl start firewalld.service
            if [ $? -eq 0 ];then
                firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
                firewall-cmd --reload
            else
                echo -e "\033[41;37m [警告]:  \033[0m 尝试开启 firewalld 失败. 如有必要请手动开启  ${ssport} 端口."
            fi
        fi
    fi
    echo -e "\033[42;37m [Tips] \033[0m firewall 设置完成..."
}

#重置防火墙
reset_firewall(){
	echo -e "\033[42;37m [Tips] \033[0m 开始重置防火墙配置..."	 
    if check_sys packageManager apt; then
	        iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	        iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
	        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
    elif centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep '${ssport}' | grep 'ACCEPT' > /dev/null 2>&1
            if [ $? -ne 0 ]; then
		        iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	            iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "\033[41;37m [警告]:  \033[0m 端口 ${ssport} 已经存在."
            fi
        else
            echo -e "\033[41;37m[警告]:  \033[0m iptables 似乎未运行或者未安装，如有必要请手动设置...."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ];then
		    firewall-cmd --permanent --zone=public --remove-port=${port}/tcp 
			firewall-cmd --permanent --zone=public --remove-port=${port}/udp
            firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
            firewall-cmd --reload
        else
            echo -e "\033[41;37m [警告]:  \033[0m Firewalld 似乎未运行，正在尝试启动..."
            systemctl start firewalld.service
            if [ $? -eq 0 ];then
			    firewall-cmd --permanent --zone=public --remove-port=${port}/tcp 
				firewall-cmd --permanent --zone=public --remove-port=${port}/udp
                firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
                firewall-cmd --reload
            else
                echo -e "\033[41;37m [警告]:  \033[0m 尝试开启 firewalld 失败. 如有必要请手动更换  ${ssport} 端口."
            fi
        fi
    fi
    echo -e "\033[42;37m [Tips] \033[0m firewall 重置完成..."	
}

#删除防火墙配置
del_firewall(){
	echo -e "\033[42;37m [Tips] \033[0m 开始删除防火墙配置..."	 
    if check_sys packageManager apt; then
	        iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	        iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
    elif centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep '${ssport}' | grep 'ACCEPT' > /dev/null 2>&1
            if [ $? -ne 0 ]; then
		        iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	            iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "\033[41;37m [警告]:  \033[0m 端口 ${ssport} 已经存在."
            fi
        else
            echo -e "\033[41;37m [警告]:  \033[0m iptables 似乎未运行或者未安装，如有必要请手动设置...."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ];then
		    firewall-cmd --permanent --zone=public --remove-port=${port}/tcp 
			firewall-cmd --permanent --zone=public --remove-port=${port}/udp
            firewall-cmd --reload
        else
            echo -e "\033[41;37m [警告]:  \033[0m Firewalld 似乎未运行，正在尝试启动..."
            systemctl start firewalld.service
            if [ $? -eq 0 ];then
			    firewall-cmd --permanent --zone=public --remove-port=${port}/tcp 
				firewall-cmd --permanent --zone=public --remove-port=${port}/udp
                firewall-cmd --reload
            else
                echo -e "\033[41;37m [警告]:  \033[0m 尝试开启 firewalld 失败. 如有必要请手动删除  ${ssport} 端口."
            fi
        fi
    fi
    echo -e "\033[42;37m [Tips] \033[0m firewall 删除完成..."	
}

#安装软链，方便后续管理
Install_Softlink(){
wget -N --no-check-certificate -O /usr/local/bin/ssr https://soft.alphabrock.cn/Linux/scripts/ssr.sh
chmod +x /usr/local/bin/ssr
 }

#改成北京时间
check_datetime(){
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	ntpdate 1.asia.pool.ntp.org
}

#安装ShadowsocksR
installSSR(){
	#判断是否安装ShadowsocksR
	if [ -e $config_user_file ]; then
		echo -e "\033[41;37m [错误] \033[0m 发现已安装ShadowsocksR，如果需要继续安装，请先卸载 !"
		exit 1
	fi
	
	# 系统判断
	check_sys
    if ! check_sys packageManager yum && ! check_sys packageManager apt; then
        echo -e "\033[42;37m [错误]: \033[0m 暂不支持该系统. 请更换系统为 CentOS6/7，,Debian7/8，Ubuntu14+ 再尝试安装."
        exit 1
    fi
	
	setUser
	#修改DNS为8.8.8.8
	echo "nameserver 8.8.8.8" > /etc/resolv.conf
	echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	
	#添加jq安装源
	if grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
	   echo "deb http://ftp.us.debian.org/debian wheezy-backports main" >> /etc/apt/sources.list
	elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
	   echo "deb http://mirrors.kernel.org/ubuntu trusty-backports main universe" >> /etc/apt/sources.list
    elif centosversion 6; then
	   wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
	   rpm -ivh epel-release-latest-6.noarch.rpm
	   wget  http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-6 
       rpm --import /root/RPM-GPG-KEY-EPEL-6
	   rm -rf *noarch.rpm RPM-GPG-KEY-EPEL-6
    elif centosversion 7; then
	   wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
	   rpm -ivh epel-release-latest-7.noarch.rpm
	   wget http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7 
       rpm --import /root/RPM-GPG-KEY-EPEL-7
	   rm -rf *noarch.rpm RPM-GPG-KEY-EPEL-7
	else
	   echo -e "\033[41;37m [错误] \033[0m 本脚本仅支持 Debian / Ubuntu / Centos 系统"
	   exit 1
	fi
	
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y wget unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent git ntpdate
        yum install -y m2crypto automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel jq
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install python python-dev python-pip python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential git ntpdate jq
    fi
	
	cd /usr/local
	
	git clone https://github.com/shadowsocksr/shadowsocksr.git
	
	if [ ! -e $config_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m ShadowsocksR 下载失败 !"
		exit 1
	fi
	
	cp ${config_file} ${config_user_file}
	#询问是否安装 libsodium 支持库（chacha20加密方式）
	read -t 10 -p " 是否安装 libsodium(chacha20) 支持库 ? 回车默认安装 [Y/n] : " yn
	[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]];
		 then
             installLibsodium
		fi
	
	#修改配置文件的密码 端口 加密方式
	cat > ${config_user_file}<<-EOF
{
    "server": "0.0.0.0",
    "server_ipv6": "::",
    "server_port": ${ssport},
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "${sspwd}",
    "timeout": 120,
    "udp_timeout": 60,
    "method": "${ssmethod}",
    "protocol": "${ssprotocol}",
    "protocol_param": "",
    "obfs": "${ssobfs}",
    "obfs_param": "",
    "dns_ipv6": false,
    "connect_verbose_info": 0,
    "redirect": "",
    "fast_open": false
}
EOF

	#添加新端口的规则
    firewall_set
		
	#添加开机启动
    if centosversion 6; then
	    chmod +x /etc/rc.d/rc.sysinit
        echo -e "python /usr/local/shadowsocksr/shadowsocks/server.py -d start" >> /etc/rc.d/rc.sysinit
	elif centosversion 7;then
	    chmod +x /etc/rc.d/rc.local
		echo -e "python /usr/local/shadowsocksr/shadowsocks/server.py -d start" >> /etc/rc.d/rc.local
    elif check_sys packageManager apt; then
 	    chmod +x /etc/rc.local
	    sed -i '$d' /etc/rc.local
	    echo -e "python /usr/local/shadowsocksr/shadowsocks/server.py -d start" >> /etc/rc.local
	    echo -e "exit 0" >> /etc/rc.local   
    fi

    Install_Softlink
	check_datetime

	#启动SSR服务端，并判断是否启动成功
	python /usr/local/shadowsocksr/shadowsocks/server.py -d start
	if [ -f "/var/run/shadowsocks.pid" ];
	then
		viewUser
	
		echo
		echo -e "\033[42;37m [Tips] \033[0m ShadowsocksR 安装完成 !"
		echo 
		echo
		echo "############################################################"
	else
		echo -e "\033[41;37m [错误] \033[0m ShadowsocksR服务端启动失败 !"
	fi
}

installLibsodium(){
	#判断是否安装Libsodium
	if [ -e $Libsodiumr_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 发现已安装 Libsodium，如果需要继续安装，请先卸载 !"
		exit 1
	fi
	
	# 系统判断
	check_sys
    if ! check_sys packageManager yum && ! check_sys packageManager apt; then
        echo -e "\033[42;37m [错误]: \033[0m 暂不支持该系统. 请更换系统为 CentOS6/7，,Debian7/8，Ubuntu14+ 再尝试安装."
        exit 1
    fi
	
	#apt-get install build-essential -y
    cd /root
    wget --no-check-certificate -O libsodium-1.0.10.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.10/libsodium-1.0.10.tar.gz
    tar -xf libsodium-1.0.10.tar.gz && cd libsodium-1.0.10
    ./configure && make && make install
    echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig
	
	echo "=============================="
	echo
	echo -e "\033[42;37m [Tips]: \033[0m Libsodium 安装完成 !"
	echo
	echo "=============================="
}
#修改用户配置
modifyUser(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi

	getUser
	setUser

	#修改配置文件的密码 端口 加密方式
	sed -i 's/'$(echo ${port})'/'$(echo ${ssport})'/g' ${config_user_file}
	sed -i 's/'$(echo ${password})'/'$(echo ${sspwd})'/g' ${config_user_file}
	sed -i 's/'$(echo ${method})'/'$(echo ${ssmethod})'/g' ${config_user_file}
	sed -i 's/'$(echo ${obfs})'/'$(echo ${ssobfs})'/g' ${config_user_file}
	sed -i 's/'$(echo ${protocol})'/'$(echo ${ssprotocol})'/g' ${config_user_file}

	#删除旧端口的防火墙规则，添加新端口的规则

    reset_firewall

	python /usr/local/shadowsocksr/shadowsocks/server.py -d restart
	viewUser
}
#手动修改用户配置
manuallyModifyUser(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	
	getUser

	vi $config_user_file
	#删除旧端口的防火墙规则，添加新端口的规则
	ssport=`jq '.server_port' ${config_user_file}`
    reset_firewall
	#/etc/init.d/iptables save
	#/etc/init.d/iptables restart
	
	python /usr/local/shadowsocksr/shadowsocks/server.py -d restart
	viewUser
}
#卸载ShadowsocksR
UninstallSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	
	echo -e "\033[41;37m [警告]: \033[0m 确定要卸载ShadowsocksR ? (y/N)"
	echo 
	read -p "(默认: n):" unyn
	[ -z ${unyn} ] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		#停止ShadowsocksR服务端并删除防火墙规则，删除Shadowsocks文件夹。
		python /usr/local/shadowsocksr/shadowsocks/server.py -d stop
		port=`jq '.server_port' ${config_user_file}`
		#iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		#iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		del_firewall
		#/etc/init.d/iptables save
		#/etc/init.d/iptables restart
		#取消开机启动
		if centosversion 6; then
            sed -i '/python \/usr\/local\/shadowsocksr\/shadowsocks\/server.py -d start/d' /etc/rc.d/rc.sysinit
		elif centosversion 7;then
		    sed -i '/python \/usr\/local\/shadowsocksr\/shadowsocks\/server.py -d start/d' /etc/rc.d/rc.local
        elif check_sys packageManager apt; then
		    sed -i '/python \/usr\/local\/shadowsocksr\/shadowsocks\/server.py -d start/d' /etc/rc.local
        fi
		#删除一开始添加的 apt 源
		if [ "$OS" == 'Debian' ]; then
			sed -i '/deb http:\/\/ftp.us.debian.org\/debian wheezy-backports main/d' /etc/apt/sources.list
		elif [ "$OS" == 'Ubuntu' ]; then
			sed -i '/deb http:\/\/mirrors.kernel.org\/ubuntu trusty-backports main universe/d' /etc/apt/sources.list
		fi
	    
		rm -rf /usr/local/bin/ssr
		rm -rf /usr/local/shadowsocksr
	    echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m ShadowsocksR 卸载完成 !"
		echo
        echo "=============================="
	else
		echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m 卸载已取消..."
		echo
    	echo "=============================="
	fi
}
#更新ShadowsocksR
UpdateSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi

	#进入SS目录，更新代码，然后重启SSR
	cd /usr/local/shadowsocksr
	git pull
	python /usr/local/shadowsocksr/shadowsocks/server.py -d restart
}
#启动ShadowsocksR
StartSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	python /usr/local/shadowsocksr/shadowsocks/server.py -d start
	
	if [ -f "/var/run/shadowsocks.pid" ];
	then
		echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m ShadowsocksR 已启动 !"
		echo
		echo "=============================="
	else
		echo -e "\033[41;37m [错误] \033[0m ShadowsocksR启动失败 !"
	fi
}
#停止ShadowsocksR
StopSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	python /usr/local/shadowsocksr/shadowsocks/server.py -d stop
	
	if [ ! -f "/var/run/shadowsocks.pid" ];
	then
        echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m ShadowsocksR 已停止 !"
		echo
		echo "=============================="
	else
		echo -e "\033[41;37m [错误] \033[0m ShadowsocksR 停止失败 !"
	fi
}
#重启ShadowsocksR
RestartSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	python /usr/local/shadowsocksr/shadowsocks/server.py -d restart
	
	if [ -f "/var/run/shadowsocks.pid" ];
	then
		echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m ShadowsocksR 已启动 !"
		echo
		echo "=============================="
	else
		echo -e "\033[41;37m [错误] \033[0m ShadowsocksR 启动失败 !"
	fi
}
#查看 ShadowsocksR 状态
StatusSSR(){
	#判断是否安装ShadowsocksR
	if [ ! -e $config_user_file ];
	then
		echo -e "\033[41;37m [错误] \033[0m 没有发现安装ShadowsocksR，请检查 !"
		exit 1
	fi
	if [ ! -f "/var/run/shadowsocks.pid" ];
	then
		echo "=============================="
		echo
		echo -e "\033[41;37m [Tips]: \033[0mShadowsocksR 没有运行!"
		echo
		echo "=============================="
	else
		PID=`cat "/var/run/shadowsocks.pid"`
		echo "=============================="
		echo
		echo -e "\033[42;37m [Tips]: \033[0m ShadowsocksR 正在运行(PID: ${PID}) !"
		echo
		echo "=============================="
	fi
}
#安装锐速
installServerSpeeder(){
	#判断是否安装 锐速
	if [ -e "/serverspeeder" ];
	then
		echo -e "\033[41;37m [错误] \033[0m 锐速(ServerSpeeder) 已安装 !"
		exit 1
	fi
	cd /root
	#借用91yun.rog的开心版锐速
	wget -N --no-check-certificate https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder-all.sh
	bash serverspeeder-all.sh
    #添加系统启动
    if check_sys packageManager yum; then
	    chmod +x /etc/rc.d/rc.sysinit
        echo -e "/serverspeeder/bin/serverSpeeder.sh start" >> /etc/rc.d/rc.sysinit
    elif check_sys packageManager apt; then
 	    chmod +x /etc/rc.local
	    sed -i '$d' /etc/rc.local
	    echo -e "/serverspeeder/bin/serverSpeeder.sh start" >> /etc/rc.local
	    echo -e "exit 0" >> /etc/rc.local   
    fi
}

#查看锐速状态
StatusServerSpeeder(){
	#判断是否安装 锐速
	if [ ! -e "/serverspeeder" ];
	then
		echo -e "\033[41;37m [错误] \033[0m 锐速(ServerSpeeder) 没有安装，请检查 !"
		exit 1
	fi
	/serverspeeder/bin/serverSpeeder.sh status
}
#停止锐速
StopServerSpeeder(){
	#判断是否安装 锐速
	if [ ! -e "/serverspeeder" ];
	then
		echo -e "\033[41;37m [错误] \033[0m 锐速(ServerSpeeder) 没有安装，请检查 !"
		exit 1
	fi
	/serverspeeder/bin/serverSpeeder.sh stop
}
#重启锐速
RestartServerSpeeder(){
	#判断是否安装 锐速
	if [ ! -e "/serverspeeder" ];
	then
		echo -e "\033[41;37m [错误] \033[0m 锐速(ServerSpeeder) 没有安装，请检查 !"
		exit 1
	fi
	/serverspeeder/bin/serverSpeeder.sh restart
	/serverspeeder/bin/serverSpeeder.sh status
}
#卸载锐速
UninstallServerSpeeder(){
	#判断是否安装 锐速
	if [ ! -e "/serverspeeder" ];
	then
		echo -e "\033[41;37m [错误] \033[0m 锐速(ServerSpeeder) 没有安装，请检查 !"
		exit 1
	fi
	
	printf "确定要卸载 锐速(ServerSpeeder) ? (y/N)"
	printf "\n"
	read -p "(默认: n):" un1yn
	[ -z ${un1yn} ] && un1yn="n"
	if [[ ${un1yn} == [Yy] ]]; then
		rm -rf /root/serverspeeder-all.sh
	    rm -rf /root/91yunserverspeeder
	    rm -rf /root/91yunserverspeeder.tar.gz
		if check_sys packageManager yum; then
            sed -i '/\/serverspeeder\/bin\/serverSpeeder.sh start/d' /etc/rc.d/rc.sysinit
        elif check_sys packageManager apt; then
		    sed -i '/\/serverspeeder\/bin\/serverSpeeder.sh start/d' /etc/rc.local
        fi
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo
		echo "锐速(ServerSpeeder) 卸载完成 !"
		echo
	else
		echo
		echo "卸载已取消..."
		echo
	fi
}
install_bbr(){
    # 不支持 CentOS 5
    if centosversion 5; then
        echo "暂不支持CentOS 5, 请更换系统为 CentOS 6+/Debian 7+/Ubuntu 14+ 后再试."
        exit 1
    fi
    # 选择安装bbr
    #if check_sys packageManager yum; then
       # wget -O- https://soft.alphabrock.cn/Linux/scripts/bbr_centos_6_7_x86_64.sh | bash
   # elif check_sys packageManager apt; then
       # wget -N --no-check-certificate https://soft.alphabrock.cn/Linux/scripts/bbr.sh && bash bbr.sh
   # fi
   wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh
}


#菜单判断
echo "请输入一个数字来选择对应的选项。"
echo
echo "=================================="
echo
#安装 ShadowsocksR
echo "1. 安装 ShadowsocksR"
#安装 libsodium(chacha20加密方式)
echo "2. 安装 libsodium(chacha20)"
#显示用户账号信息
echo "3. 显示 账号信息"
#修改用户配置
echo "4. 修改 用户配置"
#手动修改用户配置
echo "5. 手动 修改用户配置"
#卸载ShadowsocksR
echo "6. 卸载 ShadowsocksR"
#更新ShadowsocksR
echo "7. 更新 ShadowsocksR"
echo
echo "=================================="
echo
#启动ShadowsocksR
echo "8. 启动 ShadowsocksR"
#停止ShadowsocksR
echo "9. 停止 ShadowsocksR"
#重启ShadowsocksR
echo "10. 重启 ShadowsocksR"
#查看ShadowsocksR状态
echo "11. 查看 ShadowsocksR 状态"
echo
echo "=================================="
echo
echo -e "\033[41;37m [警告]: \033[0m 锐速和TCP-BBR只能安装其中一个"
echo
echo "=================================="
#安装锐速
echo "12. 安装 锐速(ServerSpeeder)"
#查看锐速状态
echo "13. 查看 锐速(ServerSpeeder) 状态"
#停止锐速
echo "14. 停止 锐速(ServerSpeeder)"
#重启锐速
echo "15. 重启 锐速(ServerSpeeder)"
#卸载锐速
echo "16. 卸载 锐速(ServerSpeeder)"
echo
echo "=================================="
echo
# 
echo "17. 安装 Google TCP-BBR拥塞控制算法"
echo
echo "=================================="
echo
echo -e "\033[42;37m 【Tips】: \033[0m BBR安装完毕请执行以下操作以验证是否安装成功"
echo
echo "18. 查看 BBR 状态"
echo "=================================="
read -p "(请输入数字):" num

case "$num" in
	1)
	installSSR
	;;
	2)
	installLibsodium
	;;
	3)
	viewUser
	;;
	4)
	modifyUser
	;;
	5)
	manuallyModifyUser
	;;
	6)
	UninstallSSR
	;;
	7)
	UpdateSSR
	;;
	8)
	StartSSR
	;;
	9)
	StopSSR
	;;
	10)
	RestartSSR
	;;
	11)
	StatusSSR
	;;
	12)
	installServerSpeeder
	;;
	13)
	StatusServerSpeeder
	;;
	14)
	StopServerSpeeder
	;;
	15)
	RestartServerSpeeder
	;;
	16)
	UninstallServerSpeeder
	;;
	17)
	install_bbr
	;;
	18)
	lsmod | grep bbr
	;;
	*)
	echo '请选择 1-20 的数字。'
	;;
esac
