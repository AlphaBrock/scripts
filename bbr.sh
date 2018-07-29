#!/usr/bin/env bash
#
# Auto install latest kernel for TCP BBR
#
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Thanks: Teddysun <i@teddysun.com>
#
# URL: https://teddysun.com/489.html
#
# Author: AlphaBrock <jcciam@outlook.com>

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

[[ $EUID -ne 0 ]] && echo -e "${red}Error:${plain} This script must be run as root!" && exit 1

[[ -d "/proc/vz" ]] && echo -e "${red}Error:${plain} Your VPS is based on OpenVZ, which is not supported." && exit 1

if [ -f /etc/redhat-release ]; then
    release="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    release=""
fi

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

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
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

get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# getCentosVersion() {
#     if [[ -s /etc/redhat-release ]]; then
#         grep -oE  "[0-9.]+" /etc/redhat-release
#     else
#         grep -oE  "[0-9.]+" /etc/issue
#     fi
# }

# getUbuntuVersion(){
#     if [[ -s /etc/issue ]]; then
#        grep -oE  "[0-9.]+" /etc/issue 
#     fi
# }
getVersion(){
    if [ x"${release}" == x"centos" ]; then
        if [[ -s /etc/redhat-release ]]; then
            grep -oE "[0-9.]+" /etc/redhat-release
        else
            grep -oE "[0-9.]+" /etc/issue
        fi
    elif [[ x"${release}" == x"debian" || x"${release}" == x"ubuntu" ]]; then
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosVersion() {
    if [ x"${release}" == x"centos" ]; then
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

ubuntuVersion() {
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
    
    if centosVersion 5; then
        echo -e "${red}Error:${plain} not supported CentOS 5."
        exit 1
    fi
    
    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
    
    if centosVersion 6; then
        rpm -Uvh http://www.elrepo.org/elrepo-release-6-8.el6.elrepo.noarch.rpm
        elif centosVersion 7; then
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
        if centosVersion 6; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${red}Error:${plain} /boot/grub/grub.conf not found, please check it."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
            elif centosVersion 7; then
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

reboot_os() {
    echo
    echo -e "${green}Info:${plain} The system needs to reboot."
    read -p "Do you want to restart system? [y/n]" is_reboot
    if [[ ${is_reboot} == "y" || ${is_reboot} == "Y" ]]; then
        reboot
    else
        echo -e "${green}Info:${plain} Reboot has been canceled..."
        exit 0
    fi
}
#download ubuntu14.04 kernel
dl_kernel(){
    [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        mkdir x64_kernels && cd x64_kernels
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-headers-4.14.56-041456_4.14.56-041456.201807170758_all.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-headers-4.14.56-041456-generic_4.14.56-041456.201807170758_amd64.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-image-unsigned-4.14.56-041456-generic_4.14.56-041456.201807170758_amd64.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-modules-4.14.56-041456-generic_4.14.56-041456.201807170758_amd64.deb
    else
        mkdir x32_kernels && cd x32_kernels
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-headers-4.14.56-041456_4.14.56-041456.201807170758_all.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-headers-4.14.56-041456-generic_4.14.56-041456.201807170758_i386.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-image-4.14.56-041456-generic_4.14.56-041456.201807170758_i386.deb
        wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.14.56/linux-modules-4.14.56-041456-generic_4.14.56-041456.201n807170758_i386.deb
    fi
    cd ${cur_dir}
}
# prepair config kernel
pre_config_kernels(){
    [[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
    mkdir pre_deb && cd pre_deb
    wget http://security.ubuntu.com/ubuntu/pool/main/l/linux-base/linux-base_4.5ubuntu1~16.04.1_all.deb
    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
    else
        wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_i386.deb
    fi
    dpkg -i *.deb

    #cleanup
    cd ${cur_dir} && rm -rf pre_deb
}
# #unnstall kernel
# uninstall_keinel(){
#     apt-get install byobu bikeshed -y 
#     purge-old-kernels --keep 1 -q -y
# }

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
        if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
            echo -e "\ndeb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
            apt-get update -y
            apt -t jessie-backports install linux-image-amd64 -y
        else
            echo -e "\ndeb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
            apt-get update -y
            apt -t jessie-backports install linux-image-686 -y
        fi
    elif [[ x"${release}" == x"ubuntu" ]]; then
        if ubuntuVersion 12 ; then
            echo -e "${red}Error:${plain} not supported Ubuntu 12"
            exit 1
        elif ubuntuVersion 14 ; then
            dl_kernel
            pre_config_kernels
            if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
                cd x64_kernels
                dpkg -i *.deb

                #cleanup
                cd ${cur_dir} && rm -rf x64_kernels
            else
                cd x32_kernels
                dpkg -i *.deb
                
                #cleanup
                cd ${cur_dir} && rm -rf x32_kernels
            fi
            #uninstall old kernel
            # uninstall_keinel

        elif ubuntuVersion 16 ; then
            apt-get install linux-generic-hwe-16.04 -y
        fi
    else
        echo -e "${red}Error:${plain} OS is not be supported, please change to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    
    install_config
    sysctl_config
    reboot_os
}


clear
echo "---------- System Information ----------"
echo " OS      : $opsy"
echo " Arch    : $arch ($lbit Bit)"
echo " Kernel  : $kern"
echo "----------------------------------------"
echo " Auto install latest kernel for TCP BBR"
echo
echo " Thanks: Teddysun"
echo "----------------------------------------"
echo
echo "Press any key to start...or Press Ctrl+C to cancel"
char=`get_char`

install_bbr 2>&1 | tee ${cur_dir}/install_bbr.log