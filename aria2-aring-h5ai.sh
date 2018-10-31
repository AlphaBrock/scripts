# ====================================================
#	System Request:Debian 8、9 Ubuntu 16+ Centos 6+
#	Author:AlphaBrock
#	Aria2+Aria2Ng+H5ai一键安装脚本
# ====================================================

#fonts color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

#folder
cur_dir="$(pwd)"

aria2_new_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/q3aql/aria2-static-builds/releases | grep -o '"tag_name": ".*"' |head -n 1| sed 's/"//g;s/v//g' | sed 's/tag_name: //g') 
aria2_dl="https://github.com/q3aql/aria2-static-builds/releases/download/v${aria2_new_ver}/aria2-${aria2_new_ver}-linux-gnu-64bit-build1.tar.bz2"
aria2_Name="aria2-${aria2_new_ver}-linux-gnu-64bit-build1"
aria2ng_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/mayswind/AriaNg/releases/latest | grep -o '"tag_name": ".*"' | sed 's/"//g;s/tag_name: //g')
aria2ng_dl="https://github.com/mayswind/AriaNg/releases/download/${aria2ng_ver}/AriaNg-${aria2ng_ver}.zip"
h5ai_dl=""

nginx_conf_dir="/etc/nginx/conf.d"

#check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error:${plain} This script must be run as root!" && exit 1

get_char() {
  SAVEDSTTY=`stty -g`
  stty -echo
  stty cbreak
  dd if=/dev/tty bs=1 count=1 2> /dev/null
  stty -raw
  stty echo
  stty $SAVEDSTTY
}

#check system
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Get version
getversion(){
    if [ x"${release}" == x"centos" ]; then
        if [[ -s /etc/redhat-release ]]; then
            grep -oE  "[0-9.]+" /etc/redhat-release
        else
            grep -oE  "[0-9.]+" /etc/issue
        fi
    elif [[ x"${release}" == x"debian" ]]; then
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# CentOS version
CentOS_ver(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# Debian version
Debian_ver(){
    if [ x"${release}" == x"debian" ]; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

#Ubuntu version
Ubuntu_ver() {
    if [ x"${release}" == x"ubuntu" ]; then
        local code=$1
        local version="$(getVersion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

Debian_source(){
    # 添加源
    echo "deb http://packages.dotdeb.org jessie all" | tee --append /etc/apt/sources.list
    echo "deb-src http://packages.dotdeb.org jessie all" | tee --append /etc/apt/sources.list
    # 添加key
    wget --no-check-certificate https://www.dotdeb.org/dotdeb.gpg
    if [[ -f dotdeb.gpg ]];then
        apt-key add dotdeb.gpg
        if [[ $? -eq 0 ]];then
            echo -e "${green} 导入 GPG 秘钥成功 ${plain}"
            sleep 1
        else
            echo -e "${red} 导入 GPG 秘钥失败 ${plain}"
            exit 1
        fi
    else
        echo -e "${red} 下载 GPG 秘钥失败 ${plain}"
        exit 1
    fi
}

Ubuntu_source(){
    #add nginx and php70 ppa
    apt-get install python-software-properties -y
    apt-get install software-properties-common -y
    sudo add-apt-repository ppa:nginx/stable
    sudo add-apt-repository ppa:ondrej/php
    sudo add-apt-repository ppa:jonathonf/ffmpeg-4
    sudo add-apt-repository ppa:rwky/graphicsmagick
}

#install nginx and php7
installNginx(){
    if check_sys packageManager yum ; then
        #not support centos
        echo -e "$[{red}Error:${plain}] Not supported CentOS , please change to Debian 8+/Ubuntu 16+ and try again."
    elif
        if [[ x"${release}" == x"debian" ]]; then
             if [ ${Debian_ver} -eq 8 ]; then
                Debian_source
            fi
        else
            if [ ${Ubuntu_ver} -eq 16 ]; then
                Ubuntu_source
            fi
        fi
    fi
    apt-get update -y
    apt-get install nginx -y
    if [[ $? -eq 0 ]]; then
        echo -e "${green}[Info]：${plain}nginx install successfull!"
        sleep 1
    else
        echo -e "${red}[Error]:${plain}nginx install failed!"
        exit 1
    fi
}

installPHP7(){
    # if [[ x"${release}" == x"debian" ]];then
        apt-get install php7.0-cgi php7.0-fpm php7.0-curl php7.0-gd -y
        if [[ $? -eq 0 ]];then
            echo -e "${green}[Info]: ${plain} php7 install successful! "
            sleep 1
        else
            echo -e "${red}[Error]: ${plain} php7 install failed!"
            exit 1
        fi
    # else

    # fi    
}

nginx_conf_ssl(){
    cat > ${nginx_conf_dir}/aria2ng.conf <<EOF
server
    {
        listen 443 ssl http2;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        server_name ${aria2ng_domain};
        root /data/wwwroot/aria2ng;
        index index.html index.php;
        ssl on;
        ssl_certificate /data/wwwroot/ssl/aria2ng.crt;
        ssl_certificate_key /data/wwwroot/ssl/aria2ng.key;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        }
        location ~ / {
             rewrite /(.*)/$ /index.php?dir=$1 last;
        }
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        access_log off;
    }
server
    {
        listen 80;
        server_name ${domain};
        rewrite ^(.*) https://${aria2ng_domain}\$1 permanent;
    }
EOF
    cat > ${nginx_conf_dir}/h5ai.conf <<EOF
server
    {
        listen 443 ssl http2;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        server_name ${h5ai_domain};
        root /data/wwwroot/h5ai/_h5ai/public/index.php;
        index index.html index.php;
        ssl on;
        ssl_certificate /data/wwwroot/ssl/h5ai.crt;
        ssl_certificate_key /data/wwwroot/ssl/h5ai.key;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        }
        location ~ / {
             rewrite /(.*)/$ /index.php?dir=$1 last;
        }
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        access_log off;
    }
server
    {
        listen 80;
        server_name ${domain};
        rewrite ^(.*) https://${h5ai_domain}\$1 permanent;
    }
EOF
    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info] ${plain} nginx configuration is successfully imported!"
        sleep 1
    else
        echo -e "${red}[Error]: ${plain} nginx configuration import failed!"
        exit 1
    fi
}

installSSL(){
    apt install socat netcat -y
    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info] ${plain} SSL certificate generation script relies on successful installation!"
        sleep 2
    else
        echo -e "${red}[Error] ${plain}  SSL certificate generation script relies on installation failure"
        exit 6
    fi

    curl  https://get.acme.sh | sh

    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info] ${plain}  SSL certificate generation script installed successfully"
        sleep 2
    else
        echo -e "${red}[Error] ${plain}  The SSL certificate generation script failed to install. Please check if the related dependencies are installed properly."
        exit 7
    fi

}
acme(){
    mkdir -p /data/wwwroot/ssl
    ~/.acme.sh/acme.sh --issue -d ${aria2ng_domain} --standalone -k ec-256 --force
    ~/.acme.sh/acme.sh --issue -d ${h5ai_domain} --standalone -k ec-256 --force
    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info] ${plain} SSL Certificate generation succeeded!"
        sleep 2
        ~/.acme.sh/acme.sh --installcert -d ${aria2ng_domain} --fullchainpath /data/wwwroot/ssl/aria2ng.crt --keypath /data/wwwroot/ssl/aria2ng.key --ecc
        ~/.acme.sh/acme.sh --installcert -d ${h5ai_domain} --fullchainpath /data/wwwroot/ssl/h5ai.crt --keypath /data/wwwroot/ssl/h5ai.key --ecc
        if [[ $? -eq 0 ]];then
        echo -e "${green}[Info] ${plain} Certificate configuration succeeded!"
        sleep 2
        else
        echo -e "${red}[Error] ${plain} Certificate configuration failed! "
        fi
    else
        echo -e "${red}[Info] ${plain} SSL certificate generation failed!"
        exit 1
    fi
}

port_exist_check(){
    if [[ 0 -eq `netstat -tlpn | grep "$1"| wc -l` ]];then
        echo -e "${green}[Info] ${plain} $1 Port is not occupied"
        sleep 1
    else
        echo -e "${red}[Error] ${plain} $1 The port is occupied, please check the occupied process and restart the script after the end."
        netstat -tlpn | grep "$1"
        exit 1
    fi
}

installAria2(){
    echo -e "${green}[Info]:${plain} starting install aria2....."
    apt-get install build-essential unzip net-tools bc curl sudo -y
    cd ${cur_dir}
    [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        wget -N --no-check-certificate ${aria2_dl}
        tar jxvf ${aria2_Name}.tar.bz2
        mv ${aria2_Name} aria2
        cd aria2
        make install 
        chmod +x aria2c
    else
        echo -e "${red}[Error]:${plain} Not support 32bit system!"
        exit 1
    fi

    #clean aria2
    cd ${cur_dir}
    rm -rf aria2 ${aria2_Name}.tar.bz2
    #set aria2 config
    mkdir ${cur_dir}/.aria2
    wget -N --no-check-certificate 
    wget -N --no-check-certificate
    echo '' > ${cur_dir}/.aria2/aria2.session
    chmod 777 ${cur_dir}/.aria2/aria2.session

    cat > ${cur_dir}/.aria2/aria2.conf << EOF
## '#'开头为注释内容, 选项都有相应的注释说明, 根据需要修改 ##
## 被注释的选项填写的是默认值, 建议在需要修改时再取消注释  ##

## 文件保存相关 ##

# 文件的保存路径(可使用绝对路径或相对路径), 默认: 当前启动位置
dir=/data/wwwroot/h5ai
# 启用磁盘缓存, 0为禁用缓存, 需1.16以上版本, 默认:16M
#disk-cache=32M
# 文件预分配方式, 能有效降低磁盘碎片, 默认:prealloc
# 预分配所需时间: none < falloc ? trunc < prealloc
# falloc和trunc则需要文件系统和内核支持
# NTFS建议使用falloc, EXT3/4建议trunc, MAC 下需要注释此项
# file-allocation=none
# 断点续传
continue=true

## 下载连接相关 ##

# 最大同时下载任务数, 运行时可修改, 默认:5
max-concurrent-downloads=10
# 同一服务器连接数, 添加时可指定, 默认:1
max-connection-per-server=5
# 最小文件分片大小, 添加时可指定, 取值范围1M -1024M, 默认:20M
# 假定size=10M, 文件为20MiB 则使用两个来源下载; 文件为15MiB 则使用一个来源下载
min-split-size=10M
# 单个任务最大线程数, 添加时可指定, 默认:5
split=20
# 整体下载速度限制, 运行时可修改, 默认:0
#max-overall-download-limit=0
# 单个任务下载速度限制, 默认:0
#max-download-limit=0
# 整体上传速度限制, 运行时可修改, 默认:0
max-overall-upload-limit=1M
# 单个任务上传速度限制, 默认:0
#max-upload-limit=1000
# 禁用IPv6, 默认:false
disable-ipv6=false

## 进度保存相关 ##

# 从会话文件中读取下载任务
input-file=${curl_dir}/.aria2/aria2.session
# 在Aria2退出时保存`错误/未完成`的下载任务到会话文件
save-session=${curl_dir}/.aria2/aria2.session
# 定时保存会话, 0为退出时才保存, 需1.16.1以上版本, 默认:0
#save-session-interval=60

## RPC相关设置 ##

# 启用RPC, 默认:false
enable-rpc=true
# 允许所有来源, 默认:false
rpc-allow-origin-all=true
# 允许非外部访问, 默认:false
rpc-listen-all=true
# 事件轮询方式, 取值:[epoll, kqueue, port, poll, select], 不同系统默认值不同
#event-poll=select
# RPC监听端口, 端口被占用时可以修改, 默认:6800
rpc-listen-port=6800
# 设置的RPC授权令牌, v1.18.4新增功能, 取代 --rpc-user 和 --rpc-passwd 选项
rpc-secret=${passwd}
# 设置的RPC访问用户名, 此选项新版已废弃, 建议改用 --rpc-secret 选项
#rpc-user=<USER>
# 设置的RPC访问密码, 此选项新版已废弃, 建议改用 --rpc-secret 选项
#rpc-passwd=<PASSWD>
# 是否启用 RPC 服务的 SSL/TLS 加密,
# 启用加密后 RPC 服务需要使用 https 或者 wss 协议连接
rpc-secure=true
# 在 RPC 服务中启用 SSL/TLS 加密时的证书文件(.pem/.crt)
rpc-certificate=/data/wwwroot/ssl/aria2ng.crt
# 在 RPC 服务中启用 SSL/TLS 加密时的私钥文件(.key)
rpc-private-key=/data/wwwroot/ssl/aria2ng.key

## BT/PT下载相关 ##

# 当下载的是一个种子(以.torrent结尾)时, 自动开始BT任务, 默认:true
follow-torrent=true
# BT监听端口, 当端口被屏蔽时使用, 默认:6881-6999
listen-port=51413
# 单个种子最大连接数, 默认:55
#bt-max-peers=55
# 打开DHT功能, PT需要禁用, 默认:true
enable-dht=true
# 打开IPv6 DHT功能, PT需要禁用
#enable-dht6=false
# DHT网络监听端口, 默认:6881-6999
#dht-listen-port=6881-6999
# 本地节点查找, PT需要禁用, 默认:false
#bt-enable-lpd=true
# 种子交换, PT需要禁用, 默认:true
enable-peer-exchange=true
# 每个种子限速, 对少种的PT很有用, 默认:50K
#bt-request-peer-speed-limit=50K
# 客户端伪装, PT需要
peer-id-prefix=-TR2770-
user-agent=Transmission/2.77
# 当种子的分享率达到这个数时, 自动停止做种, 0为一直做种, 默认:1.0
seed-ratio=0.001
#下载完成后不做种
seed-time=0
# 强制保存会话, 即使任务已经完成, 默认:false
# 较新的版本开启后会在任务完成后依然保留.aria2文件
#force-save=false
# BT校验相关, 默认:true
#bt-hash-check-seed=true
# 继续之前的BT任务时, 无需再次校验, 默认:false
bt-seed-unverified=true
# 保存磁力链接元数据为种子文件(.torrent文件), 默认:false
#bt-save-metadata=true

bt-tracker=udp://tracker.coppersurfer.tk:6969/announce,udp://tracker.open-internet.nl:6969/announce,udp://p4p.arenabg.com:1337/announce,udp://tracker.internetwarriors.net:1337/announce,udp://allesanddro.de:1337/announce,udp://9.rarbg.to:2710/announce,udp://tracker.skyts.net:6969/announce,udp://tracker.safe.moe:6969/announce,udp://tracker.piratepublic.com:1337/announce,udp://tracker.opentrackr.org:1337/announce,udp://tracker2.christianbro.pw:6969/announce,udp://tracker1.wasabii.com.tw:6969/announce,udp://tracker.zer0day.to:1337/announce,udp://public.popcorn-tracker.org:6969/announce,udp://tracker.xku.tv:6969/announce,udp://tracker.vanitycore.co:6969/announce,udp://inferno.demonoid.pw:3418/announce,udp://tracker.mg64.net:6969/announce,udp://open.facedatabg.net:6969/announce,udp://mgtracker.org:6969/announce
EOF
    #add system startup
    mv /etc/rc.local /etc/rc.local.bk
    cat > /etc/rc.local << EOF
#!/bin/sh -e
nohup aria2c -c ${cur_dir}/.aria2/aria2.conf > ${cur_dir}/.aria2/aria2.log 2>&1 &
exit 0
EOF
    chmod +x /etc/rc.local
    nohup aria2c -c ${cur_dir}/.aria2/aria2.conf > ${cur_dir}/.aria2/aria2.log 2>&1 &
}

installAria2NG(){
    echo -e "${green}[Info]:${plain} starting install aria2NG....."
    cd ${cur_dir}
    [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
    mkdir -p /data/wwwroot/aria2ng && cd /data/wwwroot/aria2ng && wget -N --no-check-certificate ${aria2ng_dl}
    unzip AriaNg-${aria2ng_ver}.zip
    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info]:${plain} AriaNg install successfully!"
        sleep 1
    else
        echo -e "${red}[Error]:${plain} AriaNg install failed!"
        exit 1
    fi
}

installH5ai(){
     echo -e "${green}[Info]:${plain} starting install H5ai....."
    cd ${cur_dir}
    [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
    mkdir -p /data/wwwroot/h5ai && cd /data/wwwroot/h5ai && wget ${h5ai_dl}
    unzip h5ai.zip && rm -rf h5ai.zip
    if [[ $? -eq 0 ]];then
        echo -e "${green}[Info]:${plain} AriaNg install successfully!"
        sleep 1
    else
        echo -e "${red}[Error]:${plain} AriaNg install failed!"
        exit 1
    fi   
}

checkDomain(){
    stty erase '^H' && read -p "请输入你的Aria2NG域名信息(如:dl.alphabrock.cn):" aria2ng_domain
    stty erase '^H' && read -p "请输入你的H5ai域名信息(如:pan.alphabrock.cn):" h5ai_domain
    stty erase '^H' && read -p "请输入你的Aria2密钥:" passwd
    aria2ng_domain_ip=`ping ${aria2ng_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    h5ai_domain_ip=`ping ${h5ai_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_ip=`curl http://whatismyip.akamai.com`
    echo -e "Aria2NG域名dns解析IP：${aria2ng_domain_ip}"
    echo -e "H5ai域名dns解析IP：${h5ai_domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${aria2ng_domain_ip}|tr '.' '+'|bc) ]] || [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${h5ai_domain_ip}|tr '.' '+'|bc) ]];then
        echo -e "${green}[Info]:${plain} 域名dns解析IP  与 本机IP 匹配 "
        sleep 2
    else
        echo -e "${red}[Error]:${plain} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${green}[Info]:${plain} 继续安装" 
            sleep 2
            ;;
        *)
            echo -e "${red}[Error]:${plain} 安装终止" 
            exit 2
            ;;
        esac
    fi
}

installWeb(){
    checkDomain
    installNginx
    installPHP7
    installAria2
    installAria2NG
    installH5ai
}
configSSL(){
    service nginx stop
    service php7.0-fpm stop

    port_exist_check 80
    port_exist_check 443  

    installSSL
    acme
    nginx_conf_ssl

    service nginx start
    service php7.0-fpm start     
}
main(){
    check_sys
	sleep 2
            installWeb
            configSSL
}

main