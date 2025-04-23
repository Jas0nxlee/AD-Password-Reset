FROM python:3.9-slim

WORKDIR /app
COPY backend/ .

# 确保.env文件存在或提供环境变量
RUN if [ ! -f .env ]; then cp .env-template .env || echo "No .env template found"; fi

# 创建日志目录
RUN mkdir -p logs && chmod 777 logs

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5001
CMD ["python", "app.py"] 