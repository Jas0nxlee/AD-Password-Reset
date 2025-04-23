from flask import Flask, request, jsonify
from flask_cors import CORS
import ldap3
import winrm
import secrets
import smtplib
from email.mime.text import MIMEText
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import json
import ssl
import base64

# 配置日志记录
def setup_logger():
    """配置日志记录器"""
    # 创建logs目录（如果不存在）
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # 创建日志记录器
    logger = logging.getLogger('password_reset')
    logger.setLevel(logging.INFO)
    
    # 创建文件处理器（每个文件最大10MB，保留5个备份文件）
    file_handler = RotatingFileHandler(
        'logs/password_reset.log',
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    
    # 设置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 创建Flask应用和日志记录器
app = Flask(__name__)
CORS(app)
logger = setup_logger()

# 存储验证码和过期时间
verification_codes = {}

# 从.env文件加载配置
from dotenv import load_dotenv
load_dotenv()

# LDAP配置
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_PORT = int(os.getenv('LDAP_PORT', 389))
# 处理LDAP基础DN
raw_base_dn = os.getenv('LDAP_BASE_DN')
if not raw_base_dn:
    LDAP_BASE_DN = ''
elif 'DC=' in raw_base_dn:
    LDAP_BASE_DN = raw_base_dn
else:
    LDAP_BASE_DN = ','.join([f'DC={x}' for x in raw_base_dn.split('.')])
LDAP_USER_DN = os.getenv('LDAP_USER_DN')
LDAP_USER = os.getenv('LDAP_USER')
LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')
LDAP_PASSWORD = os.getenv('LDAP_PASSWORD')

# 邮件服务器配置
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# 使用内存存储验证码
use_redis = False

# 定义LDAP连接类
class LDAPConnection:
    """LDAP连接上下文管理器"""
    def __init__(self):
        # 配置LDAP服务器连接
        logger.info(f"LDAP服务器配置: 服务器={LDAP_SERVER}, 端口=636, SSL=True")
        logger.info(f"LDAP域: {LDAP_DOMAIN}, 基础DN: {LDAP_BASE_DN}")
        
        # 使用简化TLS设置
        self.server = ldap3.Server(
            LDAP_SERVER,
            port=636,  # 固定使用636端口进行SSL连接
            use_ssl=True,  # 始终使用SSL
            connect_timeout=10,  # 增加连接超时时间
            get_info=ldap3.ALL  # 获取服务器信息
        )
        
        # 使用简单连接策略
        self.connection = ldap3.Connection(
            self.server,
            user=f'{LDAP_USER}@{LDAP_DOMAIN}',  # 使用UPN格式
            password=LDAP_PASSWORD,
            auto_bind=False  # 显式设置手动绑定
        )
        self.conn = None

    def __enter__(self):
        # 始终使用UPN格式 (username@domain)
        admin_user = f'{LDAP_USER}@{LDAP_DOMAIN}'
        logger.info(f"使用AD用户名(UPN格式): {admin_user}")
        
        # 添加重试机制
        max_retries = 3
        retry_count = 0
        retry_delay = 2  # 初始延迟2秒
        
        while retry_count < max_retries:
            try:
                self.conn = ldap3.Connection(
                    self.server,
                    user=admin_user,
                    password=LDAP_PASSWORD,
                    auto_bind=False
                )
                
                # 手动绑定并检查结果
                if self.conn.bind():
                    logger.info("LDAP连接绑定成功")
                    return self.conn
                else:
                    logger.error(f"LDAP绑定失败: {self.conn.result}")
                    logger.error(f"错误详情: {self.conn.last_error}")
                    
            except Exception as e:
                logger.error(f"LDAP连接异常: {str(e)}")
            
            # 重试逻辑
            retry_count += 1
            if retry_count < max_retries:
                logger.info(f"尝试第 {retry_count} 次重新连接LDAP，等待 {retry_delay} 秒")
                import time
                time.sleep(retry_delay)
                retry_delay *= 2  # 指数退避策略
            else:
                logger.error("LDAP连接重试次数已用尽")
                raise Exception(f"LDAP绑定失败，已重试 {max_retries} 次")
        
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.unbind()

def get_user_email_from_ad(username):
    """从Active Directory获取用户的邮箱地址"""
    try:
        logger.info(f"开始连接LDAP服务器: {LDAP_SERVER}:636")
        server = ldap3.Server(
            LDAP_SERVER,
            port=636,  # 固定使用636端口进行SSL连接
            use_ssl=True,  # 始终使用SSL
            connect_timeout=10,  # 增加连接超时时间
            get_info=ldap3.ALL  # 获取服务器信息
        )
        
        # 检查LDAP用户配置
        if not LDAP_USER:
            logger.error("LDAP_USER环境变量未配置")
            return None
            
        # 始终使用UPN格式 (username@domain)
        admin_user = f"{LDAP_USER}@{LDAP_DOMAIN}"
        logger.info(f"使用AD用户名(UPN格式): {admin_user}")
        
        conn = ldap3.Connection(
            server,
            user=admin_user,
            password=LDAP_PASSWORD,
            auto_bind=False  # 显式设置手动绑定
        )
        
        # 手动绑定并检查结果
        if not conn.bind():
            logger.error(f"LDAP绑定失败: {conn.result}")
            logger.error(f"错误详情: {conn.last_error}")
            return None
        
        # 尝试不同的用户名格式进行搜索
        # 1. 原始用户名
        # 2. 用户名@域名
        # 3. 域名\用户名
        # 4. 邮箱格式
        username_formats = [
            username,  # 原始用户名
            f"{username}@{LDAP_DOMAIN}",  # UPN格式
            f"{LDAP_DOMAIN}\\{username}",  # 域\用户名格式
            f"{username}@{LDAP_DOMAIN}",  # 邮箱格式
        ]
        
        # 构建更全面的搜索过滤器
        search_conditions = []
        for format in username_formats:
            search_conditions.append(f"(sAMAccountName={username})")
            search_conditions.append(f"(userPrincipalName={format})")
            search_conditions.append(f"(mail={format})")
            # 添加CN和displayName搜索
            search_conditions.append(f"(cn={username})")
            search_conditions.append(f"(displayName=*{username}*)")
        
        search_filter = f"(&(objectClass=user)(objectCategory=person)(|{' '.join(search_conditions)}))"        
        logger.info(f"搜索用户 {username}，过滤条件: {search_filter}")
        
        # 确保基础DN格式正确
        base_dn = LDAP_BASE_DN
        logger.info(f"搜索基础DN: {base_dn}")
        
        # 尝试在不同的OU中搜索
        search_bases = [
            base_dn,  # 主域
            f"CN=Users,{base_dn}",  # 用户容器
            f"OU=Domain Users,{base_dn}",  # 域用户OU
            f"OU=Staff,{base_dn}"  # 员工OU
        ]
        
        user_found = False
        for search_base in search_bases:
            try:
                logger.info(f"在 {search_base} 中搜索用户 {username}")
                success = conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=['mail', 'userPrincipalName', 'sAMAccountName', 'displayName', 'givenName', 'sn', 'cn']
                )
                
                if success and len(conn.entries) > 0:
                    user_found = True
                    logger.info(f"在 {search_base} 中找到用户 {username}")
                    break
            except ldap3.core.exceptions.LDAPNoSuchObjectResult:
                logger.warning(f"搜索基础DN不存在: {search_base}")
                continue
            except Exception as e:
                logger.warning(f"在 {search_base} 中搜索时出错: {str(e)}")
                continue
        
        if not user_found:
            logger.warning(f"在所有搜索基础DN中均未找到用户: {username}")
            logger.info(f"搜索结果为空: {conn.result}")
            # 记录更详细的诊断信息
            logger.info(f"LDAP服务器信息: {server.info}")
            return None
            
        logger.info(f"搜索结果: {conn.entries}")
            
        # 优先使用mail属性，如果不存在则使用userPrincipalName
        if hasattr(conn.entries[0], 'mail') and conn.entries[0].mail:
            user_email = conn.entries[0].mail.value
        elif hasattr(conn.entries[0], 'userPrincipalName') and conn.entries[0].userPrincipalName:
            user_email = conn.entries[0].userPrincipalName.value
        else:
            logger.error(f"用户 {username} 没有邮箱地址")
            return None
            
        logger.info(f"成功获取用户 {username} 的邮箱地址: {user_email}")
        return user_email
        
    except Exception as e:
        logger.error(f"获取用户邮箱地址时出错: {str(e)}")
        logger.error(f"异常类型: {type(e).__name__}")
        # 记录堆栈跟踪以便更好地诊断问题
        import traceback
        logger.error(f"堆栈跟踪: {traceback.format_exc()}")
        return None

def send_verification_code(email):
    """发送验证码到用户邮箱"""
    logger.info(f"开始为邮箱 {email} 发送验证码")
    code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expiration_time = datetime.now() + timedelta(minutes=5)
    
    msg = MIMEText(f'您的密码重置验证码是：{code}，有效期5分钟。', 'plain', 'utf-8')
    msg['Subject'] = '密码重置验证码'
    msg['From'] = f'密码重置服务 <{SMTP_USERNAME}>'
    msg['To'] = f'{email}'
    msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

    try:
        logger.info(f"正在连接SMTP服务器: {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=10)
        try:
            logger.info(f"已连接到SMTP服务器: {SMTP_SERVER}:{SMTP_PORT}")
            logger.info(f"正在登录SMTP服务器: {SMTP_USERNAME}")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            logger.info("SMTP登录成功")
            
            logger.info(f"正在发送邮件到: {email}")
            server.send_message(msg)
            
            # 开发环境下记录完整验证码
            logger.info(f"邮件发送成功: 收件人={email}, 主题=密码重置验证码, 验证码={code}")
            
            # 使用内存存储验证码
            verification_codes[email] = {'code': code, 'expiration': expiration_time}
            logger.info(f"验证码已存储到内存: 收件人={email}")
            return True
        finally:
            server.quit()
            
    except smtplib.SMTPException as e:
        logger.error(f"SMTP错误: {str(e)}")
        logger.error(f"SMTP错误详情: {e.smtp_error.decode() if hasattr(e, 'smtp_error') else '无详细错误信息'}")
        logger.error(f"SMTP错误代码: {e.smtp_code if hasattr(e, 'smtp_code') else '无错误代码'}")
        logger.error(f"邮件发送失败: 收件人={email}, 错误详情={str(e)}")
        return False
    except Exception as e:
        error_msg = f"发送验证码到 {email} 失败"
        logger.error(error_msg)
        logger.error(f"错误类型: {type(e).__name__}")
        logger.error(f"错误详情: {str(e)}")
        logger.error(f"邮件发送失败: 收件人={email}, 错误详情={str(e)}")
        return False

def verify_code(email, code):
    """验证用户输入的验证码"""
    logger.info(f"开始验证邮箱 {email} 的验证码")
    
    # 使用内存验证码
    if email not in verification_codes:
        logger.warning(f"邮箱 {email} 没有对应的验证码记录")
        return False
    
    stored_code = verification_codes[email]
    if datetime.now() > stored_code['expiration']:
        logger.warning(f"邮箱 {email} 的验证码已过期")
        del verification_codes[email]
        return False
    
    if stored_code['code'] != code:
        logger.warning(f"邮箱 {email} 提供的验证码不正确")
        return False
    
    logger.info(f"邮箱 {email} 的验证码验证成功")
    del verification_codes[email]
    return True

def validate_password_complexity(username, password):
    """验证密码是否符合AD复杂性要求"""
    errors = []
    
    if len(password) < 8:
        errors.append("密码长度至少为8个字符")
    
    if not any(c.isupper() for c in password):
        errors.append("密码必须包含至少一个大写字母")
    
    if not any(c.islower() for c in password):
        errors.append("密码必须包含至少一个小写字母")
    
    if not any(c.isdigit() for c in password):
        errors.append("密码必须包含至少一个数字")
    
    special_chars = '!@#$%^&*()_+-=[]{};:,.<>?/'
    if not any(c in special_chars for c in password):
        errors.append("密码必须包含至少一个特殊字符")
    
    if username.lower() in password.lower():
        errors.append("密码不能包含用户名")
    
    # 检查连续字符
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            errors.append("密码不能包含连续重复的字符")
            break
    
    # 检查键盘序列和常见数字序列
    keyboard_sequences = ['qwerty', 'asdfgh', '123456', '654321', '123', '321', '456', '789']
    password_lower = password.lower()
    for seq in keyboard_sequences:
        if seq in password_lower:
            errors.append("密码不能包含键盘序列或连续的数字序列")
            break
    
    # 检查重复模式
    for i in range(len(password)-3):
        pattern = password[i:i+2]
        if pattern in password[i+2:]:
            errors.append("密码不能包含重复的字符模式")
            break
            
    # 检查常见单词和组织名称
    common_words = ['ucas', 'admin', 'password', 'welcome', 'login', 'user']
    password_lower = password.lower()
    for word in common_words:
        if word in password_lower:
            errors.append("密码不能包含常见单词或组织名称（如ucas）")
            break
    
    if errors:
        return False, "\n".join(errors)
    
    return True, "密码符合复杂性要求"

def reset_ad_password(username, new_password):
    """重置Active Directory用户密码"""
    logger.info(f"开始重置用户 {username} 的密码")
    
    # 首先验证密码复杂性
    is_valid, message = validate_password_complexity(username, new_password)
    if not is_valid:
        logger.error(f"密码不符合复杂性要求: {message}")
        return False, f"密码不符合要求: {message}"
        
    try:
        # 使用LDAPConnection类进行连接
        with LDAPConnection() as conn:
            # 搜索用户 - 支持多种用户标识符
            search_filter = f'(&(objectClass=user)(|(userPrincipalName={username})(sAMAccountName={username})(mail={username})))'
            logger.info(f"搜索用户，过滤条件: {search_filter}")
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                attributes=['distinguishedName', 'pwdLastSet', 'lockoutTime', 'userPrincipalName', 'mail']
            )
            
            if not conn.entries:
                logger.error(f"未找到用户: {username}")
                return False, "未找到用户"

            # 增强空值校验和错误处理
            try:
                if len(conn.entries) == 0:
                    logger.error(f"LDAP查询返回空结果: {username}")
                    return False, "用户不存在"
                
                user_entry = conn.entries[0]
                if not hasattr(user_entry, 'entry_dn') or not user_entry.entry_dn:
                    logger.error(f"用户条目缺少entry_dn属性: {username}")
                    return False, "用户信息不完整"

            except IndexError as e:
                logger.error(f"LDAP查询结果索引异常: {str(e)}")
                return False, "系统错误：用户信息获取失败"
            except Exception as e:
                logger.error(f"处理LDAP结果时发生意外错误: {str(e)}")
                return False, "系统错误：用户信息处理异常"
                
            try:
                user_dn = user_entry.entry_dn
                logger.debug(f"获取到有效用户DN: {user_dn}")
                    
                logger.info(f"找到用户DN: {user_dn}")
            except Exception as e:
                logger.error(f"获取用户DN时出错: {str(e)}")
                return False, f"获取用户DN时出错: {str(e)}"
        
            # 检查账户锁定状态并尝试解锁
            if hasattr(conn.entries[0], 'lockoutTime'):
                lockout_time = conn.entries[0].lockoutTime.value
                if lockout_time:
                    # 确保lockoutTime是数值类型
                    if isinstance(lockout_time, datetime):
                        lockout_time = int(lockout_time.timestamp())
                    if int(lockout_time) > 0:
                        logger.info(f"尝试解锁用户账户: {username}")
                        # 使用AD专用的解锁方法
                        success = ldap3.extend.microsoft.unlockAccount.ad_unlock_account(conn, user_dn)
                        if not success:
                            logger.error(f"账户解锁失败: {username}")
                            return False, "账户解锁失败，请联系管理员"
                        logger.info(f"账户解锁成功: {username}")

            # 尝试重置密码
            try:
                # 修改密码和账户控制
                modify_attrs = {
                    'unicodePwd': [(ldap3.MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])],
                    'userPassword': [(ldap3.MODIFY_REPLACE, [new_password])],
                    'userAccountControl': [(ldap3.MODIFY_REPLACE, ['66080'])],  # 设置用户不可更改密码
                    'pwdLastSet': [(ldap3.MODIFY_REPLACE, ['-1'])]  # 密码立即生效
                }
                success = conn.modify(user_dn, modify_attrs)
                
                if not success:
                    error_msg = conn.result.get('description', '')
                    logger.error(f"密码修改失败: {username}, 错误: {error_msg}")
                    return False, "密码修改失败，请确保密码符合域策略要求"

                if success:
                    logger.info(f"密码重置成功: {username}")
                    return True, "密码重置成功"
                else:
                    error_msg = conn.result.get('description', '')
                    error_details = str(conn.result)
                    logger.error(f"密码重置失败: {username}, 错误详情: {error_details}")
                    
                    if 'WILL_NOT_PERFORM' in error_details:
                        if 'problem 5003' in error_details:
                            # 提供更详细的密码策略要求
                            policy_msg = (
                                "密码不符合域策略要求，请确保：\n"
                                "1. 密码长度至少为8个字符\n"
                                "2. 包含大写字母、小写字母、数字和特殊字符\n"
                                "3. 不能包含用户名或显示名称\n"
                                "4. 不能包含连续重复的字符（如aaa）\n"
                                "5. 不能包含常见的键盘序列（如qwerty）\n"
                                "6. 不能使用最近使用过的密码\n"
                                "7. 不能包含生日、电话等个人信息\n"
                                "如果仍然失败，请联系系统管理员获取完整的密码策略要求。"
                            )
                            logger.info(f"向用户 {username} 提供密码策略要求提示")
                            return False, policy_msg
                        else:
                            logger.error(f"密码重置被拒绝，可能是权限问题: {username}")
                            return False, "密码重置操作被拒绝，请联系系统管理员"
                    elif 'CONSTRAINT_VIOLATION' in error_details:
                        logger.info(f"用户 {username} 的密码不符合复杂度要求")
                        return False, "密码不符合域策略要求，请使用更复杂的密码，确保包含大小写字母、数字和特殊字符"
                    else:
                        logger.error(f"未知错误导致密码重置失败: {username}, {error_msg}")
                        return False, f"密码重置失败: {error_msg}"

            except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
                logger.error(f"密码重置失败(认证失败): {username}, {str(e)}")
                return False, "系统认证失败，请联系管理员检查配置"
            except ldap3.core.exceptions.LDAPOperationResult as e:
                logger.error(f"密码重置失败(LDAP操作错误): {username}, {str(e)}")
                error_details = str(e)
                if 'WILL_NOT_PERFORM' in error_details:
                    if 'problem 5003' in error_details:
                        return False, "密码不符合域策略要求，请检查密码是否满足：长度至少8位，包含大小写字母、数字和特殊字符"
                    else:
                        return False, "密码重置操作被拒绝，请联系系统管理员"
                elif 'CONSTRAINT_VIOLATION' in error_details:
                    return False, "密码不符合复杂度要求，请使用更复杂的密码"
                else:
                    return False, "密码重置操作失败，请稍后重试"
            except Exception as e:
                logger.error(f"密码重置过程中出错: {str(e)}")
                return False, "系统内部错误，请联系管理员"

    except Exception as e:
        logger.error(f"LDAP操作过程中出错: {str(e)}")
        return False, f"系统错误: {str(e)}"

@app.route('/api/send-code', methods=['POST'])
def send_code():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    
    if not email:
        logger.warning("收到发送验证码请求，但邮箱地址为空")
        return jsonify({'success': False, 'message': '邮箱地址不能为空'}), 400
    
    if not username:
        logger.warning("收到发送验证码请求，但用户名为空")
        return jsonify({'success': False, 'message': '用户名不能为空'}), 400
    
    logger.info(f"收到发送验证码请求: username={username}, email={email}")
    
    # 验证邮箱地址是否匹配
    ad_email = get_user_email_from_ad(username)
    if not ad_email:
        logger.warning(f"未找到用户 {username} 或无法获取用户信息")
        # 提供更详细的错误信息和建议
        error_message = (
            f'未找到用户 {username}，可能的原因：\n'
            '1. 用户名拼写错误\n'
            '2. 用户账户不存在或已禁用\n'
            '3. 用户可能在不同的组织单位(OU)中\n'
            '请检查用户名是否正确，或尝试使用完整的邮箱地址作为用户名'
        )
        # 记录更多诊断信息
        logger.info(f"LDAP服务器: {LDAP_SERVER}, 端口: 636, 基础DN: {LDAP_BASE_DN}")
        logger.info(f"尝试的用户名格式: {username}, {username}@{LDAP_DOMAIN}")
        return jsonify({'success': False, 'message': error_message}), 404
    
    # 邮箱地址比较时忽略大小写，并去除前后空格
    if email.lower().strip() != ad_email.lower().strip():
        logger.warning(f"用户提供的邮箱地址与域中的不匹配: provided={email}, actual={ad_email}")
        # 提供部分隐藏的正确邮箱地址作为提示
        masked_email = mask_email(ad_email)
        return jsonify({
            'success': False, 
            'message': f'提供的邮箱地址与用户在AD中的邮箱不匹配。正确的邮箱地址格式为: {masked_email}'
        }), 400
    
    try:
        if send_verification_code(email):
            logger.info(f"成功发送验证码到邮箱: {email}")
            return jsonify({'success': True, 'message': '验证码已发送，请检查您的邮箱'}), 200
        else:
            logger.error(f"验证码发送失败: email={email}")
            return jsonify({'success': False, 'message': '验证码发送失败，请检查邮箱地址是否正确或联系系统管理员'}), 500
    except Exception as e:
        logger.error(f"验证码发送异常: {str(e)}")
        logger.error(f"异常类型: {type(e).__name__}")
        # 记录堆栈跟踪
        import traceback
        logger.error(f"堆栈跟踪: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': '验证码发送失败，请稍后重试或联系系统管理员'}), 500

# 辅助函数：部分隐藏邮箱地址
def mask_email(email):
    """部分隐藏邮箱地址，只显示首字符、@符号和域名"""
    if not email or '@' not in email:
        return "***@***.***"
    
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    
    # 只显示用户名的第一个字符，其余用*代替
    if len(username) > 1:
        masked_username = username[0] + '*' * (len(username) - 1)
    else:
        masked_username = '*'
    
    return f"{masked_username}@{domain}"

@app.route('/api/get-config', methods=['GET'])
def get_config():
    """获取API配置信息"""
    logger.info("获取API配置")
    # 从环境变量获取服务器IP和端口
    server_ip = os.getenv('SERVER_IP', '127.0.0.1')
    port = os.getenv('PORT', 5001)
    
    # 构建API基础URL
    api_base_url = f"http://{server_ip}:{port}/api"
    logger.info(f"返回API基础URL: {api_base_url}")
    
    return jsonify({
        'success': True,
        'api_base_url': api_base_url
    })

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    code = data.get('code')
    new_password = data.get('new_password')
    
    logger.info(f"收到密码重置请求: 用户名={username}, 邮箱={email}")
    
    if not all([username, email, code, new_password]):
        logger.warning(f"密码重置请求缺少必要字段: username={username}, email={email}")
        return jsonify({'success': False, 'message': '所有字段都是必填的'}), 400
    
    # 再次验证邮箱地址是否匹配
    ad_email = get_user_email_from_ad(username)
    if not ad_email or email.lower() != ad_email.lower():
        logger.warning(f"密码重置时邮箱地址不匹配: provided={email}, actual={ad_email}")
        return jsonify({'success': False, 'message': '用户名或邮箱地址无效'}), 400

    if not verify_code(email, code):
        logger.warning(f"验证码验证失败: email={email}")
        return jsonify({'success': False, 'message': '验证码无效或已过期'}), 400
    
    success, message = reset_ad_password(username, new_password)
    if success:
        logger.info(f"密码重置成功: username={username}")
    else:
        logger.error(f"密码重置失败: username={username}, message={message}")
    return jsonify({'success': success, 'message': message}), 200 if success else 500

def main():
    """启动应用程序"""
    logger.info("密码重置服务启动")
    app.run(host='0.0.0.0', port=5001)

if __name__ == '__main__':
    main()