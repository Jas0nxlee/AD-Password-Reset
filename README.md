# AD 密码重置系统

这是一个用于 Active Directory 密码重置的 Web 应用程序，提供安全、便捷的密码重置功能。

## 功能特性

- 基于邮箱验证的密码重置流程
- 支持 LDAP 和 Active Directory 集成
- 密码复杂度验证
- 邮件验证码发送功能
- 完整的日志记录系统
- 跨域支持
- 响应式前端界面

## 系统要求

- Python 3.x
- Active Directory 服务器
- SMTP 邮件服务器

## 安装步骤

1. 克隆项目到本地：
```bash
git clone [项目地址]
cd AD-Reset
```

2. 安装后端依赖：
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

3. 配置环境变量：
   - 复制 `.env.example` 文件为 `.env`
   - 填写必要的配置信息（LDAP服务器、SMTP服务器等）

## 使用说明

1. 启动后端服务：
```bash
cd backend
python app.py
```

2. 打开前端页面：
   - 直接在浏览器中打开 `frontend/index.html` 文件
   - 或使用 Web 服务器托管前端文件

3. 使用流程：
   - 输入用户名
   - 接收验证码邮件
   - 输入验证码
   - 设置新密码

## 安全特性

- 密码复杂度要求验证
- 邮箱验证码双重认证
- 安全的密码传输
- 完整的操作日志记录

## 日志系统

系统会自动记录所有重要操作，日志文件位于：
- 后端日志：`backend/logs/password_reset.log`
- 日志文件自动轮转，每个文件最大 10MB，保留 5 个备份

## 注意事项

- 请确保正确配置 LDAP 服务器连接信息
- 确保 SMTP 服务器配置正确
- 定期检查日志文件
- 建议在生产环境中使用 HTTPS

## 许可证

[添加许可证信息]

## 联系方式

[添加联系方式] 