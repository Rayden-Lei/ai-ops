#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AI_LINK="/usr/local/bin/ai"

echo "=== AiOps 安装脚本 ==="

# 检查 Python 版本
python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null || {
    echo "错误: 需要 Python 3.10+，当前版本: $(python3 --version 2>&1)"
    exit 1
}

# 安装依赖
echo "安装 Python 依赖..."
pip install -q langchain langchain-openai langgraph rich

# 创建软链接
if [ -f "$SCRIPT_DIR/aiops.py" ]; then
    chmod +x "$SCRIPT_DIR/aiops.py"
    ln -sf "$SCRIPT_DIR/aiops.py" "$AI_LINK"
    echo "已创建命令: $AI_LINK -> $SCRIPT_DIR/aiops.py"
else
    echo "错误: 未找到 aiops.py"
    exit 1
fi

# 创建用户数据目录
USER_DIR="$HOME/.aiops"
mkdir -p "$USER_DIR/logs"
mkdir -p "$USER_DIR/conversations"

# 检查全局配置
GLOBAL_CONFIG="$SCRIPT_DIR/config.json"
if [ -f "$GLOBAL_CONFIG" ]; then
    chmod 600 "$GLOBAL_CONFIG"
    echo "已设置全局配置文件权限: chmod 600"
fi

# 检查 API Key
if [ -z "$DEEPSEEK_API_KEY" ]; then
    CONFIG_KEY=$(python3 -c "
import json
try:
    with open('$GLOBAL_CONFIG') as f:
        print(json.load(f).get('api_key', ''))
except: pass
" 2>/dev/null)

    if [ -z "$CONFIG_KEY" ]; then
        echo ""
        echo "提示: 未检测到 API Key，请通过以下方式配置:"
        echo "  export DEEPSEEK_API_KEY=sk-xxx"
        echo "  或编辑 $GLOBAL_CONFIG"
    fi
fi

echo ""
echo "安装完成！使用 'ai' 命令启动 AiOps"
