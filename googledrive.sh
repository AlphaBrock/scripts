#!/bin/bash
### BEGIN INIT INFO
# Provides:          rclone
# Required-Package   nload fuse 
# Description:       Enable rclone by daemon.
### END INIT INFO
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
 
REMOTE='Manjaro' #GoogleDrive中的文件夹名
NAME='GoogleDrive' #初始化配置填写的name
LOCAL='GoogleDrive' #本地挂载文件夹名,非路径,脚本位于哪则在同级目录下创建该文件夹
DEMO='rclone'
 
[ -n "$REMOTE" ] || exit 1;
[ -x "$(which fusermount)" ] || exit 1;
[ -x "$(which $DEMO)" ] || exit 1;
 
case "$1" in
start)
  ps -ef |grep -v grep |grep -q "$REMOTE"
  [ $? -eq '0' ] && {
    DEMOPID="$(ps -C $DEMO -o pid= |head -n1 |grep -o '[0-9]\{1,\}')"
    [ -n "$DEMOPID" ] && echo "$DEMO already in running.[$DEMOPID]";
    exit 1;
  }
  fusermount -zuq $LOCAL >/dev/null 2>&1
  #mkdir -p $LOCAL
  rclone mount $NAME:$REMOTE $LOCAL --copy-links --no-gzip-encoding --no-check-certificate --allow-other --allow-non-empty --umask 000 >/dev/null 2>&1 &
  sleep 3;
  DEMOPID="$(ps -C $DEMO -o pid=|head -n1 |grep -o '[0-9]\{1,\}')"
  [ -n "$DEMOPID" ] && {
    echo -ne "$DEMO start running.[$DEMOPID]\n$REMOTE --> $LOCAL\n\n"
    echo 'ok' >~/ok
    exit 0;
  } || {
    echo "$DEMO start fail! "
    exit 1;
  }
  ;;
stop)
  DEMOPID="$(ps -C $DEMO -o pid= |head -n1 |grep -o '[0-9]\{1,\}')"
  [ -z "$DEMOPID" ] && echo "$DEMO not running."
  [ -n "$DEMOPID" ] && kill -9 $DEMOPID >/dev/null 2>&1
  [ -n "$DEMOPID" ] && echo "$DEMO is stopped.[$DEMOPID]"
  fusermount -zuq $LOCAL >/dev/null 2>&1
  ;;
init)
  fusermount -zuq $LOCAL
  rm -rf $LOCAL;
  mkdir -p $LOCAL;
  chmod a+x $0;
  rclone config;
  ;;
esac
 
exit 0
