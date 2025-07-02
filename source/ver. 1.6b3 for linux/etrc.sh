#!/bin/bash

# ETRC Linux 启动脚本
echo "启动 ETRC 远程终端控制软件 (Linux 版本)"
echo "--------------------------------------"

# 检查 Python 版本
if ! command -v python3 &> /dev/null
then
    echo "错误: 未找到 python3，请安装 Python 3.6 或更高版本"
    sudo apt update
    sudo apt install python3
    exit 1
fi

# 检查配置文件
CONFIG_FILE="config.info"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "检测到首次运行，将创建默认配置文件"
    echo '{"blacklist": [], "permanent_password": null}' > "$CONFIG_FILE"
fi

# 设置执行权限
chmod +x etrc.py

# 启动主程序
python3 etrc.py