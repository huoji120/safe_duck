#!/bin/bash
# 该脚本可执行make编译safe_duck模块，然后将其移动到指定位置

# 设定变量
MODULE_NAME=safe_duck.ko
TARGET_DIR="/run/user/1000/gvfs/smb-share:server=192.168.1.3,share=dev_share/safe_duck.ko"

# 编译模块
if make; then

  # 移动模块文件至目标目录
  if mv ${MODULE_NAME} ${TARGET_DIR}; then
  
    echo "${MODULE_NAME} moved to ${TARGET_DIR}"
    
  else
    
    echo "Failed to move ${MODULE_NAME} to ${TARGET_DIR}"
    
  fi

else

  echo "Failed to build ${MODULE_NAME}"

fi
make clean
