#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
#   Description: One click Install ShadowsocksR Server            #
#   Author: Teddysun <i@teddysun.com>                             #
#   Thanks: @breakwa11 <https://twitter.com/breakwa11>            #
#   Intro:  https://shadowsocks.be/9.html                         #
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
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
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
    echo "password = ${shadowsockspwd}"
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
            echo "port = ${shadowsocksport}"
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
        echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
        echo -e "Your Server Port      : \033[41;37m ${shadowsocksport} \033[0m"
        echo -e "Your Password         : \033[41;37m ${shadowsockspwd} \033[0m"
        echo -e "Your Protocol         : \033[41;37m ${shadowsockprotocol} \033[0m"
        echo -e "Your obfs             : \033[41;37m ${shadowsockobfs} \033[0m"
        echo -e "Your Encryption Method: \033[41;37m ${shadowsockscipher} \033[0m"
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

# Pre_config for BBR
is_digit(){
    local input=${1}
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

get_valid_valname(){
    local val=${1}
    local new_val=$(eval echo $val | sed 's/[-.]/_/g')
    echo ${new_val}
}

get_hint(){
    local val=${1}
    local new_val=$(get_valid_valname $val)
    eval echo "\$hint_${new_val}"
}

#Display Memu
display_menu(){
    local soft=${1}
    local default=${2}
    eval local arr=(\${${soft}_arr[@]})
    local default_prompt
    if [[ "$default" != "" ]]; then
        if [[ "$default" == "last" ]]; then
            default=${#arr[@]}
        fi
        default_prompt="(default ${arr[$default-1]})"
    fi
    local pick
    local hint
    local vname
    local prompt="which ${soft} you'd select ${default_prompt}: "

    while :
    do
        echo -e "\n------------ ${soft} setting ------------\n"
        for ((i=1;i<=${#arr[@]};i++ )); do
            vname="$(get_valid_valname ${arr[$i-1]})"
            hint="$(get_hint $vname)"
            [[ "$hint" == "" ]] && hint="${arr[$i-1]}"
            echo -e "${green}${i}${plain}) $hint"
        done
        echo
        read -p "${prompt}" pick
        if [[ "$pick" == "" && "$default" != "" ]]; then
            pick=${default}
            break
        fi

        if ! is_digit "$pick"; then
            prompt="Input error, please input a number"
            continue
        fi

        if [[ "$pick" -lt 1 || "$pick" -gt ${#arr[@]} ]]; then
            prompt="Input error, please input a number between 1 and ${#arr[@]}: "
            continue
        fi

        break
    done

    eval ${soft}=${arr[$pick-1]}
    vname="$(get_valid_valname ${arr[$pick-1]})"
    hint="$(get_hint $vname)"
    [[ "$hint" == "" ]] && hint="${arr[$pick-1]}"
    echo -e "\nyour selection: $hint\n"
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

get_latest_version() {
    latest_version=($(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'\"v' '/v[4-9]./{print $2}' | cut -d/ -f1 | grep -v - | sort -V))

    [ ${#latest_version[@]} -eq 0 ] && echo -e "${red}Error:${plain} Get latest kernel version failed." && exit 1

    kernel_arr=()
    for i in ${latest_version[@]}; do
        if version_ge $i 4.14; then
            kernel_arr+=($i);
        fi
    done

    display_menu kernel last

    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-amd64.deb"
        modules_deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-amd64.deb"
    else
        deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-i386.deb"
        modules_deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-i386.deb"
    fi

    [ -z ${deb_name} ] && echo -e "${red}Error:${plain} Getting Linux kernel binary package name failed, maybe kernel build failed. Please choose other one and try again." && exit 1
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

opsy=$( get_opsy )
arch=$( uname -m )
lbit=$( getconf LONG_BIT )
kern=$( uname -r )

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ x"${param}" == x"bbr" ]]; then
        return 0
    else
        return 1
    fi
}

check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_ge ${kernel_version} 4.9; then
        return 0
    else
        return 1
    fi
}

install_elrepo() {

    if centosversion 5; then
        echo -e "${red}Error:${plain} not supported CentOS 5."
        exit 1
    fi

    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

    if centosversion 6; then
        rpm -Uvh http://www.elrepo.org/elrepo-release-6-8.el6.elrepo.noarch.rpm
    elif centosversion 7; then
        rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
    fi

    if [ ! -f /etc/yum.repos.d/elrepo.repo ]; then
        echo -e "${red}Error:${plain} Install elrepo failed, please check it."
        exit 1
    fi
}

sysctl_config() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
}

install_config() {
    if [[ x"${release}" == x"centos" ]]; then
        if centosversion 6; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${red}Error:${plain} /boot/grub/grub.conf not found, please check it."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif centosversion 7; then
            if [ ! -f "/boot/grub2/grub.cfg" ]; then
                echo -e "${red}Error:${plain} /boot/grub2/grub.cfg not found, please check it."
                exit 1
            fi
            grub2-set-default 0
        fi
    elif [[ x"${release}" == x"debian" || x"${release}" == x"ubuntu" ]]; then
        /usr/sbin/update-grub
    fi
}

# Install Google TCP BBR
install_bbr() {
    check_bbr_status
    if [ $? -eq 0 ]; then
        echo
        echo -e "${green}Info:${plain} TCP BBR has already been installed. nothing to do..."
        exit 0
    fi
    check_kernel_version
    if [ $? -eq 0 ]; then
        echo
        echo -e "${green}Info:${plain} Your kernel version is greater than 4.9, directly setting TCP BBR..."
        sysctl_config
        echo -e "${green}Info:${plain} Setting TCP BBR completed..."
        exit 0
    fi

    if [[ x"${release}" == x"centos" ]]; then
        install_elrepo
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum-config-manager elrepo-kernel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable elrepo-kernel > /dev/null 2>&1
        yum -y install kernel-ml kernel-ml-devel
        if [ $? -ne 0 ]; then
            echo -e "${red}Error:${plain} Install latest kernel failed, please check it."
            exit 1
        fi
    elif [[ x"${release}" == x"debian" ]]; then
        [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
        echo -e "${green}Info:${plain} Getting Latest kernel Version..."
        get_latest_version
        if [ -n ${modules_deb_name} ]; then
            wget -c -t3 -T60 -O ${deb_kernel_modules_name} ${deb_kernel_modules_url}
            if [ $? -ne 0 ]; then
                echo -e "${red}Error:${plain} Download ${deb_kernel_modules_name} failed, please check it."
                exit 1
            fi
        fi
        wget -c -t3 -T60 -O ${deb_kernel_name} ${deb_kernel_url}
        if [ $? -ne 0 ]; then
            echo -e "${red}Error:${plain} Download ${deb_kernel_name} failed, please check it."
            exit 1
        fi
        [ -f ${deb_kernel_modules_name} ] && dpkg -i ${deb_kernel_modules_name}
        dpkg -i ${deb_kernel_name}
        rm -f ${deb_kernel_name} ${deb_kernel_modules_name}

    # Add support for ubuntu os in aliyun machine
    elif [[ x"${release}" == x"ubuntu" ]]; then
        apt-get install linux-generic-hwe-16.04 -y

    else
        echo -e "${red}Error:${plain} OS is not be supported, please change to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi

    install_config
    sysctl_config
    reboot_os
}

function_bbr(){
  clear
  echo "---------- System Information ----------"
  echo " OS      : $opsy"
  echo " Arch    : $arch ($lbit Bit)"
  echo " Kernel  : $kern"
  echo "----------------------------------------"
  echo " Auto install latest kernel for TCP BBR"
  echo
  echo " URL: https://teddysun.com/489.html"
  echo "----------------------------------------"
  echo
  echo "Press any key to start...or Press Ctrl+C to cancel"
  char=`get_char`

  install_bbr 2>&1 | tee ${cur_dir}/install_bbr.log
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
        yum install -y gcc gcc-c++ automake autoconf git wget 
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install build-essential git wget 
    fi

    com_hans
    #start hans 
    clear
    read -p "Please input your password and press enter to continue:" passwd
    echo -e "${green}your password is${plain}: ${passwd}"
    ./hans -s 10.1.2.0 -p ${passwd}

    echo
    echo "---------------- Information ----------------"
    echo "  hans has been started "        
    echo "  run this command in your shell terminal"
    echo "---------------------------------------------"
    echo -e "${green}sudo ./hans -c server_address -p password${plain}"
    echo "---------------------------------------------"
    echo -e "${red}Make sure your computer has been also compiler hans${plain}"
    echo
}

# #Install Softether VPN
# install_softether(){

# }

	echo -e "  黑科技一键管理脚本
  ---- AlphaBrock | jcciam@outlook.com ----

  ${green}1.${plain} 安装 ShadowsocksR
  ${green}2.${plain} 卸载 ShadowsocksR
————————————
  ${green}3.${plain} 安装 BBR
  ${green}4.${plain} 安装 IP Over ICMP
  ${green}5.${plain} 安装 SoftEther VPN
 "
	echo && read -p "please input number [1-5]" num
case "$num" in
	1)
	install_shadowsocksr
	;;
	2)
	uninstall_shadowsocksr
	;;
	3)
	function_bbr
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