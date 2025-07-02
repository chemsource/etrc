#!/bin/bash

# 定义目标目录和文件
TARGET_DIR="$HOME/etrc"
DESKTOP_DIR="$HOME/.local/share/applications"
FILES=("etrc.desktop" "config.info" "etrc.py" "getpython.sh" "etrc.sh" "setperm.sh")

# 创建目标目录
mkdir -p "$TARGET_DIR"
mkdir -p "$DESKTOP_DIR"

# 复制文件到目标目录（除了.desktop文件）
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        cp -v "$file" "$TARGET_DIR/"
    else
        echo "警告: 文件 $file 不存在，跳过复制"
    fi
done

# 特殊处理桌面文件
if [ -f "etrc.desktop" ]; then
    # 更新.desktop文件中的Exec路径
    sed -i "s|^Exec=.*|Exec=$TARGET_DIR/etrc.sh|" "etrc.desktop"
    cp -v "etrc.desktop" "$DESKTOP_DIR/"
    echo "桌面快捷方式已安装: $DESKTOP_DIR/etrc.desktop"
else
    echo "错误: etrc.desktop 文件缺失"
fi

# 设置权限
chmod +x "$TARGET_DIR/setperm.sh"
chmod +x "$TARGET_DIR/etrc.sh"
chmod +x "$TARGET_DIR/getpython.sh" 2>/dev/null

# 运行权限设置脚本
echo "正在设置文件权限..."
cd "$TARGET_DIR"
./setperm.sh

# 检查Python3并安装
if ! command -v python3 &> /dev/null; then
    echo "Python3未安装，正在尝试安装..."
    ./getpython.sh
else
    echo "Python3已安装: $(python3 --version)"
fi

echo "安装完成！"
echo "应用程序已安装到: $TARGET_DIR"