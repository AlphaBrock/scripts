#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  Ubuntu16.04                                 #
#   Description: One click To Install EFB                         #
#   Author: AlphaBrock <jcciam@outlook.com>                       #
#=================================================================#

clear

cur_dir=`pwd`

# Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

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
  if check_sys sysRelease ubuntu; then
        grep -oE  "[0-9.]+" /etc/issue
  fi
}

# ubuntu version
ubuntuversion(){
  if check_sys sysRelease ubuntu; then
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

get_char(){
  SAVEDSTTY=`stty -g`
  stty -echo
  stty cbreak
  dd if=/dev/tty bs=1 count=1 2> /dev/null
  stty -raw
  stty echo
  stty $SAVEDSTTY
}

install_py3(){
  if check_sys sysRelease centos;then
    echo -e "${red}Error:${plain} Not supported CentOS/Debian, please change to Ubuntu 16 and try again."
    exit 1
  elif check_sys sysRelease debian;then
     echo -e "${red}Error:${plain} Not supported Debian, please change to Ubuntu 16 and try again."
    exit 1   
  elif check_sys sysRelease ubuntu;then
    if ubuntuversion 16;then
        sudo apt-get update -y
        sudo apt-get install build-essential python-dev python-setuptools python-pip python-smbus -y
        sudo apt-get install build-essential libncursesw5-dev libgdbm-dev libc6-dev -y
        sudo apt-get install zlib1g-dev libsqlite3-dev tk-dev -y
        sudo apt-get install libssl-dev openssl -y
        sudo apt-get install libffi-dev -y

        #install pyenv
        git clone git://github.com/yyuu/pyenv.git ~/.pyenv
        # wget https://github.com/pyenv/pyenv/archive/master.zip -O pyenv.zip
        # unzip pyenv.zip && mv pyenv-master ~/.pyenv
        echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
        echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
        echo 'eval "$(pyenv init -)"' >> ~/.bashrc
        # exec $SHELL -l
        source ~/.bashrc
        #install python3.6.5
        pyenv install 3.6.5 -v
        pyenv rehash
        pyenv global 3.6.5
    else
        echo -e "${red}Error:${plain} Not supported Ubuntu14/18, please change to Ubuntu 16 and try again."
        exit 1
    fi
  fi
}

setting_efb(){
  sudo apt update -y
  sudo apt-get install -y python3-gdbm python3-pip python-setuptools ffmpeg screen
  sudo apt-get install -y libtiff5-dev libjpeg8-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.5-dev tk8.5-dev libmagic-dev libtool
  pip3 install pillow
}

config_efb(){

  pip3 install ehforwarderbot 
  pip3 install efb-telegram-master
  pip3 install efb-wechat-slave

  mkdir -p ~/.ehforwarderbot/profiles/default
  mkdir -p ~/.ehforwarderbot/profiles/default/blueset.telegram

  clear
    # send info
    echo "------------------------ Information ------------------------"
    echo -e "${green}In this moment,please input your tgbot API and Chat ID ${plain}"
    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    echo "-------------------------------------------------------------"
    char=`get_char`
    read -e -p "please input your tgbot API:" tgbotAPI
     echo "-------------------------------------------------------------"
     read -e -p "please input your Chat ID:" chatid

     #
    echo "-------------------------------------------------------------"
    echo -e "${green}[Info]:${plain}writing config file"
    echo "-------------------------------------------------------------"

    cat > ~/.ehforwarderbot/profiles/default/config.yaml<<-EOF
token: "${tgbotAPI}"
admins: 
- ${chatid}

master_channel: "blueset.telegram" 
slave_channels: 
- "blueset.wechat"
EOF
    cat > ~/.ehforwarderbot/profiles/default/blueset.telegram/config.yaml<<-EOF
token: "${tgbotAPI}"
admins: 
- ${chatid}      
flags:
    option_one: 10
    option_two: false
    option_three: "foobar"
EOF
    chmod +x ~/.ehforwarderbot/profiles/default/config.yaml
    chmod +x ~/.ehforwarderbot/profiles/default/blueset.telegram/config.yaml
    echo -e "${green}[Info]:${plain}finished write"

    echo
    echo
    echo -e "${green}[Info]:${plain}Please run this command after installed EFB:${green}source ~/.bashrc${plain},then run again:${green}./tg-wechat.sh${plain} to start EFB!"
}

install_efb(){
  install_py3
  setting_efb
  config_efb
#   start_efb
}

update_efb(){
  pip3 install -U ehforwarderbot 
  pip3 install -U efb-telegram-master
  pip3 install -U efb-wechat-slave
}
start_efb(){
#   source ~/.bashrc
  ehforwarderbot
}
# startup_efb(){
#     mv /etc/rc.local /etc/rc.local.bk 
#     cat > /etc/rc.local<<-EOF
# #!/bin/sh -e
# python3 -m ehforwarderbot
# exit 0
# EOF
#     chmod +x /etc/rc.local
# }

echo -e "  EFB一键管理脚本
  ---- AlphaBrock | jcciam@outlook.com ----

  ${green}1.${plain} 安装 EFB
  ${green}2.${plain} 更新 EFB
————————————————————————————————————
  ${green}3.${plain} 启动 EFB
"
echo && read -e -p "please input number [1-3]" num
case "$num" in
    1)
        install_efb
    ;;
    2)
        update_efb
    ;;
    3)
        start_efb
    ;;
    *)
        echo -e "${red} please input correct number [1-3]${plain}"
    ;;
esac
