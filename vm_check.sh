#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  Debian7/8, Ubuntu14.04,centos6              #
#   Description: One click checkos virt                           #
#=================================================================#

clear
echo

echo



#  Make sure only root can run our script
function rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "Error:This script must be run as root!" 1>&2
       exit 1
    fi
}

# Check OS
function checkos(){
    if [ -f /etc/redhat-release ];then
        OS='CentOS'
    elif [ ! -z "`cat /etc/issue | grep bian`" ];then
        OS='Debian'
    elif [ ! -z "`cat /etc/issue | grep Ubuntu`" ];then
        OS='Ubuntu'
    else
        echo "Not support OS, Please reinstall OS and retry!"
        exit 1
    fi
}

# Get version
function getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else    
        grep -oE  "[0-9.]+" /etc/issue
    fi    
}

# CentOS version
function centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi        
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

# vm_check
function vm_check(){
    # Not support CentOS 5
    if centosversion 5; then
        echo "Not support CentOS 5, please change OS to CentOS 6+/Debian 7+/Ubuntu 12+ and retry."
        exit 1
    fi
    # Install necessary dependencies
    if [ "$OS" == 'CentOS' ]; then
    yum install -y gcc gcc-c++ gdb
    wget http://people.redhat.com/~rjones/virt-what/files/virt-what-1.12.tar.gz
    tar zxvf virt-what-1.12.tar.gz
    cd virt-what-1.12/
    ./configure
    make && make install
    virt-what
    else
    apt-get update
    apt-get install virt-what
    virt-what    
    fi
}


function install_vm_check(){
    Set_DNS
    rootness
    disable_selinux
    checkos
    vm_check	
}
# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
install)
    install_vm_check
    ;;
*)
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install}"
    ;;
esac
