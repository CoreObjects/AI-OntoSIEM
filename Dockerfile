# AI-OntoSIEM Demo Image
# 单容器 Streamlit 入口（演化机制 + 评测看板 + 告警研判 + 本体演化）

FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 系统依赖（DuckDB / NetworkX / pyvis 都是纯 Python，但 watchdog 在 Linux 需要 inotify）
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖（缓存友好）
COPY requirements.txt ./
RUN pip install -r requirements.txt

# 拷代码
COPY . .

# Streamlit 端口
EXPOSE 8501

# 健康检查（Streamlit 自带 /_stcore/health 端点）
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD curl -fsS http://localhost:8501/_stcore/health || exit 1

# 默认入口：单页面三 tab Streamlit
CMD ["streamlit", "run", "ui/main.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
