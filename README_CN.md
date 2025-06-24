# AD-Password-Reset

一个基于 Flask 的 Active Directory 密码重置工具，支持通过邮件验证码重置密码。

[English](README.md) | 中文文档

## 功能特点

- 支持通过邮件验证码重置 AD 密码
- 支持多种用户名格式（用户名、邮箱、UPN等）
- 密码复杂度验证
- 详细的日志记录
- 支持 SSL/TLS 加密
- 支持多语言（中文/英文）

## 项目地址

[https://github.com/Jas0nxlee/AD-Password-Reset](https://github.com/Jas0nxlee/AD-Password-Reset)

## 系统要求

- Python 3.8+
- Active Directory 服务器
- SMTP 邮件服务器
- Node.js 14+ (用于前端开发)

## 安装方法

### 方法一：传统安装

1. 克隆项目：
```bash
git clone https://github.com/Jas0nxlee/AD-Password-Reset.git
cd AD-Password-Reset
```

2. 安装依赖：
```bash
cd backend
pip install -r requirements.txt
cp .env-template .env
```

3. 配置环境变量：
编辑`.env` 文件设置以下变量：
```env
# LDAP配置
LDAP_SERVER=your_ldap_server
LDAP_PORT=636
LDAP_BASE_DN=your_base_dn
LDAP_USER_DN=your_user_dn
LDAP_USER=your_admin_user
LDAP_DOMAIN=your_domain
LDAP_PASSWORD=your_password

# SMTP配置
SMTP_SERVER=your_smtp_server
SMTP_PORT=587
SMTP_USERNAME=your_smtp_username
SMTP_PASSWORD=your_smtp_password

# 服务器配置
SERVER_IP=0.0.0.0
PORT=5001
```


## 使用方法

1. 启动后端服务：
```bash
python backend/app.py
```

2. 启动前端服务：
```bash
cd frontend
npm install
npm run dev
```

3. 访问应用：
打开浏览器访问 `http://localhost:5173`



### 方法二：Docker Compose 安装

1. 克隆仓库：
```bash
git clone https://github.com/Jas0nxlee/AD-Password-Reset.git
cd AD-Password-Reset
```

2.  **准备环境文件**:
    *   进入 `backend` 目录:
        ```bash
        cd backend
        ```
    *   复制模板文件:
        ```bash
        cp .env-template .env
        ```
    *   编辑 `backend/.env` 文件，填入您的特定配置 (LDAP, SMTP 详细信息等)。
    *   **Docker Compose 重要提示**: 确保 `backend/.env` 文件中包含 `REDIS_HOST=redis`，以便后端服务能够连接到 Redis 容器。对于没有 Docker 的本地开发，您通常会使用 `REDIS_HOST=localhost`。根据需要设置其他变量，如 `FLASK_ENV=production` 或 `FLASK_ENV=development`。
    *   返回到项目根目录:
        ```bash
        cd ..
        ```

3.  **使用 Docker Compose 构建并启动服务**:
    `docker-compose.yml` 文件位于 `docker/` 目录中。请从**项目根目录**运行以下命令:
    ```bash
    docker-compose -f docker/docker-compose.yml up -d --build
    ```
    此命令会告知 Docker Compose 使用指定的 YAML 文件 (位于 `docker/` 目录)，并将构建镜像并启动服务 (后端、前端和 Redis)。`docker-compose.yml` 中的 `env_file` 路径是相对于 `docker-compose.yml` 文件本身，指向 `../backend/.env`。

5. 访问应用：
在浏览器中访问 `http://localhost:5173`


## 密码策略

密码必须满足以下要求：
- 长度至少为8个字符
- 包含至少一个大写字母
- 包含至少一个小写字母
- 包含至少一个数字
- 包含至少一个特殊字符
- 不能包含用户名
- 不能包含连续重复的字符
- 不能包含键盘序列或连续的数字序列
- 不能包含重复的字符模式
- 不能包含常见单词或组织名称

## 日志记录

日志文件保存在 `logs` 目录下，包含以下信息：
- 用户操作记录
- 错误信息
- 系统状态
- 安全事件

## 安全特性

- 使用 SSL/TLS 加密通信
- 密码传输加密
- 验证码有效期限制
- 详细的错误处理和日志记录
- 防止暴力破解


## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。

## 许可证

MIT License

Copyright (c) 2025 Jas0nxlee
