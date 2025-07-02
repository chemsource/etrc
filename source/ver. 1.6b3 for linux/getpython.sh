#!/bin/bash
# 检查包管理器并安装Python3
if command -v apt &> /dev/null; then
    sudo apt update
    sudo apt install -y python3
elif command -v dnf &> /dev/null; then
    sudo dnf install -y python3
elif command -v pacman &> /dev/null; then
    sudo pacman -Syu --noconfirm python
elif command -v zypper &> /dev/null; then
    sudo zypper install -y python3
else
    echo "错误: 不支持的包管理器"
    exit 1
fi