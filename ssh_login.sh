#!/bin/bash

Green_font_prefix="\033[32m" && Blue_font_prefix="\033[36m" && Yellow_font_prefix="\033[33m" &&  Red_font_prefix="\033[31m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"

#默认服务器配置项
#    "服务器名称 端口号 IP地址 登录用户名 登录密码/秘钥文件Key 秘钥文件地址"
CONFIGS=(
    "Vultr_JP 22 45.76.212.28 root r_M9,,1=z1\\\$?f\}UA"
    "Aliyun_SGP_4 22 47.74.148.105 root chenfei537527@"
    "Aliyun_SGP_1 22 47.74.253.121 root chenfei537527@"
    "Aliyun_SGP_3 22 47.74.188.213 root chenfei537527@"
    "Aliyun_SGP_2 22 47.88.230.232 root chenfei537527@"
    "Qcloud_SH 22 115.159.181.237 root chenfei537527@"
    "Qcloud_HK 22 119.28.54.185 root chenfei537527@"
    "psychz 22 192.184.35.199 root wbrtF9te"
    "Azure 22 13.75.91.52 alphabrock chenfei537527@"
)

#读取自定义服务器配置文件（server_config）列表，合并服务器配置列表
if [ -f server_config ]; then
	while read line
	do
		CONFIGS+=("$line")
	done < server_config
fi

#服务器配置数
CONFIG_LENGTH=${#CONFIGS[*]}  #配置站点个数

if [[ $CONFIG_LENGTH -le 0 ]] ;
then
    echo -e "${Error}:未检测到服务器配置项!"
    echo -e "${Info}:请在脚本CONFIGS变量中配置或单独创建一个server_config文件并配置"
    exit ;
fi

#服务器配置菜单
function ConfigList(){
    for ((i=0;i<${CONFIG_LENGTH};i++));
    do
        CONFIG=(${CONFIGS[$i]}) #将一维sites字符串赋值到数组
        serverNum=$(($i+1))
        echo -e "${Green_font_prefix}${serverNum}.${Font_color_suffix}${CONFIG[0]}--${Blue_font_prefix}(${CONFIG[2]})${Font_color_suffix}"
    done
}

#登录菜单
function LoginMenu(){
    if [  ! -n $1 ]; then
        AutoLogin $1
    else
        echo -e "${Yellow_font_prefix}-------请输入登录的服务器序号---------${Font_color_suffix}"
        ConfigList
        echo -e "${Info}:请输入您选择登录的服务器序号: "
    fi
}

#选择登录的服务器
function ChooseServer(){
    read serverNum
    if [[ $serverNum -gt $CONFIG_LENGTH ]] ;
    then
        echo -e "${Error}:输入的序号不正确，请重新输入:"
        ChooseServer ;
        return ;
    fi
    if [[ $serverNum -lt 1 ]] ;
    then
        echo -e "${Error}:输入的序号不正确，请重新输入:"
        ChooseServer ;
        return ;
    fi

    AutoLogin $serverNum;
}

#自动登录
function AutoLogin(){

     num=$(($1-1))
    CONFIG=(${CONFIGS[$num]})
    echo -e "${Info}:正在登录【${CONFIG[0]}】"

	command="
        expect {
                \"*assword\" {set timeout 6000; send \"${CONFIG[4]}\n\"; exp_continue ; sleep 3; }
                \"*passphrase\" {set timeout 6000; send \"${CONFIG[4]}\r\n\"; exp_continue ; sleep 3; }
                \"yes/no\" {send \"yes\n\"; exp_continue;}
                \"Last*\" {  send_user \"\n成功登录【${CONFIG[0]}】\n\";}
        }
       interact
    ";
   pem=${CONFIG[5]}
   if [ -n "$pem" ]
   then
	expect -c "
		spawn ssh -p ${CONFIG[1]} -i ${CONFIG[5]} ${CONFIG[3]}@${CONFIG[2]}
		${command}
	"
   else
	expect -c "
		spawn ssh -p ${CONFIG[1]} ${CONFIG[3]}@${CONFIG[2]}
		${command}
	"
   fi
    echo -e "${Info}:您已退出【${CONFIG[0]}】"

}

# 程序入口
if [ 1 == $# ]; then
    if [ 'list' == $1 ]; then
        ConfigList
    else
        AutoLogin $1
    fi
else
    LoginMenu 
    ChooseServer 
  fi
