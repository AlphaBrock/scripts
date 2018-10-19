#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
#   Description: One click To Install DNS Tunnel SSR Softether    #
#   Author: AlphaBrock <jcciam@outlook.com>                       #
#   Thanks: @Teddysun <i@teddysun.com>                            #
#=================================================================#

clear

cur_dir=`pwd`

# Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

shadowsockprotocol="auth_aes128_md5"
shadowsockscipher="aes-128-ctr"
shadowsockobfs="http_simple"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

bbr_file="${cur_dir}/bbr.sh"

# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Check system
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
centosversion(){
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
deabianversion(){
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
# Get public IP address
get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# Pre-installation settings
pre_install(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        # Not support CentOS 5
        if centosversion 5; then
            echo -e "$[{red}Error${plain}] Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
            exit 1
        fi
    else
        echo -e "[${red}Error${plain}] Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    # Set ShadowsocksR config password
    echo "Please enter password for ShadowsocksR:"
    read -p "(Default password: 123456):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="123456"
    echo
    echo "---------------------------"
    echo -e "${green}password = ${shadowsockspwd}${plain}"
    echo "---------------------------"
    echo
    # Set ShadowsocksR config port
    while true
    do
        dport=$(shuf -i 9000-19999 -n 1)
        echo -e "Please enter a port for ShadowsocksR [1-65535]"
        read -p "(Default port: ${dport}):" shadowsocksport
        [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
        expr ${shadowsocksport} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo -e "${green}port = ${shadowsocksport}${plain}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
    done
    
    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
        elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install python python-dev python-setuptools openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
    fi
    cd ${cur_dir}
}

# Download files
download_files(){
    # Download ShadowsocksR file
    if ! wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url}; then
        echo -e "[${red}Error${plain}] Failed to download ShadowsocksR file!"
        exit 1
    fi
    # Download ShadowsocksR init script
    if check_sys packageManager yum; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
            echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
        elif check_sys packageManager apt; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
            echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    fi
}

# Firewall set
firewall_set(){
    echo -e "[${green}Info${plain}] firewall set start..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] port ${shadowsocksport} has been set up."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
        fi
        elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    fi
    echo -e "[${green}Info${plain}] firewall set completed..."
}

# Config ShadowsocksR
config_shadowsocks(){
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"[::]",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":120,
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":false,
    "workers":1
}
EOF
}

# Install ShadowsocksR
install_ssr(){
    ldconfig
    # Install ShadowsocksR
    cd ${cur_dir}
    tar zxf ${shadowsocks_r_file}.tar.gz
    mv ${shadowsocks_r_file}/shadowsocks /usr/local/
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x /etc/init.d/shadowsocks
        if check_sys packageManager yum; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
            elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks defaults
        fi
        /etc/init.d/shadowsocks start
        
        clear
        echo
        echo -e "Congratulations, ShadowsocksR server install completed!"
        echo -e "Your Server IP        : ${green} $(get_ip) ${plain}"
        echo -e "Your Server Port      : ${green} ${shadowsocksport} ${plain}"
        echo -e "Your Password         : ${green} ${shadowsockspwd} ${plain}"
        echo -e "Your Protocol         : ${green} ${shadowsockprotocol} ${plain}"
        echo -e "Your obfs             : ${green} ${shadowsockobfs} ${plain}"
        echo -e "Your Encryption Method: ${green} ${shadowsockscipher} ${plain}"
        echo
        echo "Enjoy it!"
        echo
    else
        echo "ShadowsocksR install failed"
        install_cleanup
        exit 1
    fi
}

# Install cleanup
install_cleanup(){
    cd ${cur_dir}
    rm -rf ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_file} ${libsodium_file}.tar.gz ${libsodium_file}
}


# Uninstall ShadowsocksR
uninstall_shadowsocksr(){
    printf "Are you sure uninstall ShadowsocksR? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        if check_sys packageManager yum; then
            chkconfig --del shadowsocks
            elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/shadowsocks.json
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR uninstall success!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

# Install ShadowsocksR
install_shadowsocksr(){
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
        firewall_set
    fi
    install_ssr
    install_cleanup
}

bbr_installation_status(){
    cd ${cur_dir}
    if [[ ! -e ${bbr_file} ]]; then
        echo -e "${red} Not Found bbr script，starting download...${plain}"
        if ! wget --no-check-certificate https://raw.githubusercontent.com/AlphaBrock/scripts/master/bbr.sh; then
            echo -e "${red} Download Failed !${plain}" && exit 1
        else
            echo -e "${green} Download Finshed !${plain}"
            chmod +x bbr.sh
        fi
    fi
}
# Install Google TCP BBR
install_bbr() {
    bbr_installation_status
    bash ${bbr_file}
}

# compiler hans
com_hans(){
    cd ${cur_dir}
    # if [ -d hans ];then
    #     echo -e "${green}hans has been existed${plain}"
    # rm -rf hans
    git clone https://github.com/friedrich/hans.git
    cd hans
    make
    # fi
}
# Install ip over icmp
install_hans(){
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y gcc gcc-c++ automake autoconf git wget net-tools
        elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install build-essential git wget net-tools
    fi
    
    com_hans
    #start hans
    clear
    read -e -p "Please input your password and Press enter to continue:" passwd
    echo -e "${green}your password is${plain}: ${passwd}"
    ./hans -s 10.1.2.0 -p ${passwd}
    
    echo
    echo "---------------- Information ----------------"
    echo "  hans has been started "
    echo "  run this command in your shell terminal"
    echo "---------------------------------------------"
    echo -e "${green}sudo ./hans -c $(get_ip) -p $(passwd) ${plain}"
    echo "---------------------------------------------"
    echo -e "${yellow}Make sure your computer has been also compile hans${plain}"
    echo
}

# compile softether vpn
com_softether(){
    cd ${cur_dir}
    wget https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.28-9669-beta/softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
    tar xzf softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
    rm -rf softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
    cd vpnserver

    clear
    # send info
    echo "------------------------ Information ------------------------"
    echo -e "${green}In this moment,please input the number 1 three time${plain}"
    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    echo "-------------------------------------------------------------"
    char=`get_char`
    make
}

config_system_start(){
    mv /etc/rc.local /etc/rc.local.bk 
    cat > /etc/rc.local<<-EOF
    #!/bin/sh -e
    #
    # rc.local
    #
    # This script is executed at the end of each multiuser runlevel.
    # Make sure that the script will "exit 0" on success or any other
    # value on error.
    #
    # In order to enable or disable this script just change the execution
    # bits.
    #
    # By default this script does nothing.
    /root/vpnserver/vpnserver start
    exit 0
EOF

    chmod +x /etc/rc.local
}

#add system start
sys_start(){
    if [[ x"${release}" == x"ubuntu" ]]; then
        config_system_start
    elif [[ x"${release}" == x"debian" ]]; then
        if deabianversion 8; then
            config_system_start
        elif deabianversion 9; then
            config_system_start
            systemctl start rc-local
        fi
    fi

}


#Install Softether VPN
install_softether(){
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y gcc gcc-c++ automake autoconf git wget
        elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install build-essential git wget
    fi
    
    com_softether
    sys_start
    
    clear
    #start vpn server
    ./vpnserver start
    echo -e "${green}SoftEther VPN Server has been start${plain}"
    
    sys_start

    # set password
    echo "------------------------ Information ------------------------"
    echo -e "${green}In this moment,please input onece number 1 and double enter ${plain}"
    echo -e "Then input command ${green}"ServerPasswordSet"${plain} to set password"
    echo "Press any key to start...or Press Ctrl+C to cancel"
    echo "-------------------------------------------------------------"
    char=`get_char`
    ./vpncmd
}

echo -e "  黑科技一键管理脚本
  ---- AlphaBrock | jcciam@outlook.com ----

  ${green}1.${plain} 安装 ShadowsocksR
  ${green}2.${plain} 卸载 ShadowsocksR
————————————
  ${green}3.${plain} 安装 BBR
  ${green}4.${plain} 安装 IP Over ICMP
  ${green}5.${plain} 安装 SoftEther VPN
"
echo && read -e -p "please input number [1-5]" num
case "$num" in
    1)
        install_shadowsocksr
    ;;
    2)
        uninstall_shadowsocksr
    ;;
    3)
        install_bbr
    ;;
    4)
        install_hans
    ;;
    5)
        install_softether
    ;;
    *)
        echo -e "${red} please input correct number [1-5]${plain}"
    ;;
esac
