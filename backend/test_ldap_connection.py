#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LDAP连接和用户搜索测试脚本
用于诊断AD域连接和用户查找问题
"""

import os
import sys
import ldap3
import ssl
import logging
from dotenv import load_dotenv

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('ldap_test')

# 加载环境变量
load_dotenv()

# LDAP配置
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_PORT = int(os.getenv('LDAP_PORT', 636))
raw_base_dn = os.getenv('LDAP_BASE_DN')
if not raw_base_dn:
    LDAP_BASE_DN = ''
elif 'DC=' in raw_base_dn:
    LDAP_BASE_DN = raw_base_dn
else:
    LDAP_BASE_DN = ','.join([f'DC={x}' for x in raw_base_dn.split('.')])
LDAP_USER = os.getenv('LDAP_USER')
LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')
LDAP_PASSWORD = os.getenv('LDAP_PASSWORD')

def test_ldap_connection():
    """测试LDAP连接"""
    logger.info("=== 测试LDAP连接 ===")
    logger.info(f"LDAP服务器: {LDAP_SERVER}:{LDAP_PORT}")
    logger.info(f"LDAP域: {LDAP_DOMAIN}")
    logger.info(f"基础DN: {LDAP_BASE_DN}")
    
    # 简化TLS设置
    try:
        # 创建服务器对象 - 使用简单配置
        server = ldap3.Server(
            LDAP_SERVER,
            port=LDAP_PORT,
            use_ssl=True,
            connect_timeout=10,
            get_info=ldap3.ALL
        )
        
        # 使用UPN格式
        admin_user = f"{LDAP_USER}@{LDAP_DOMAIN}"
        logger.info(f"使用AD用户名(UPN格式): {admin_user}")
        
        # 创建连接
        conn = ldap3.Connection(
            server,
            user=admin_user,
            password=LDAP_PASSWORD,
            auto_bind=False
        )
        
        # 尝试绑定
        if conn.bind():
            logger.info("LDAP连接成功!")
            logger.info(f"服务器信息: {server.info}")
            return conn, server
        else:
            logger.error(f"LDAP绑定失败: {conn.result}")
            logger.error(f"错误详情: {conn.last_error}")
            return None, None
            
    except Exception as e:
        logger.error(f"LDAP连接异常: {str(e)}")
        logger.error(f"异常类型: {type(e).__name__}")
        return None, None

def search_user(conn, username):
    """搜索用户"""
    if not conn:
        logger.error("无法搜索用户: LDAP连接失败")
        return
        
    logger.info(f"\n=== 搜索用户: {username} ===")
    
    # 尝试不同的用户名格式
    username_formats = [
        username,  # 原始用户名
        f"{username}@{LDAP_DOMAIN}",  # UPN格式
        f"{LDAP_DOMAIN}\\{username}",  # 域\用户名格式
    ]
    
    # 构建搜索过滤器
    search_conditions = []
    for format in username_formats:
        search_conditions.append(f"(sAMAccountName={username})")
        search_conditions.append(f"(userPrincipalName={format})")
        search_conditions.append(f"(mail={format})")
        search_conditions.append(f"(cn={username})")
        search_conditions.append(f"(displayName=*{username}*)")
    
    search_filter = f"(&(objectClass=user)(objectCategory=person)(|{' '.join(search_conditions)}))"        
    logger.info(f"搜索过滤条件: {search_filter}")
    
    # 尝试在不同的OU中搜索
    search_bases = [
        LDAP_BASE_DN,  # 主域
        f"CN=Users,{LDAP_BASE_DN}",  # 用户容器
        f"OU=Domain Users,{LDAP_BASE_DN}",  # 域用户OU
        f"OU=Staff,{LDAP_BASE_DN}",  # 员工OU
        # 可以添加更多可能的OU
    ]
    
    user_found = False
    for search_base in search_bases:
        try:
            logger.info(f"在 {search_base} 中搜索")
            success = conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['mail', 'userPrincipalName', 'sAMAccountName', 'displayName', 'givenName', 'sn', 'cn']
            )
            
            if success and len(conn.entries) > 0:
                user_found = True
                logger.info(f"在 {search_base} 中找到用户!")
                logger.info(f"搜索结果: {conn.entries}")
                
                # 显示用户属性
                for entry in conn.entries:
                    logger.info("用户详细信息:")
                    logger.info(f"  DN: {entry.entry_dn}")
                    for attr in entry.entry_attributes:
                        logger.info(f"  {attr}: {entry[attr].value}")
                break
                
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            logger.warning(f"搜索基础DN不存在: {search_base}")
            continue
        except Exception as e:
            logger.warning(f"在 {search_base} 中搜索时出错: {str(e)}")
            continue
    
    if not user_found:
        logger.warning(f"在所有搜索基础DN中均未找到用户: {username}")
        logger.info(f"搜索结果: {conn.result}")

def list_all_users(conn, limit=10):
    """列出所有用户(有限数量)"""
    if not conn:
        logger.error("无法列出用户: LDAP连接失败")
        return
        
    logger.info(f"\n=== 列出前 {limit} 个用户 ===")
    
    try:
        # 搜索所有用户
        success = conn.search(
            search_base=LDAP_BASE_DN,
            search_filter='(&(objectClass=user)(objectCategory=person))',
            attributes=['mail', 'userPrincipalName', 'sAMAccountName'],
            size_limit=limit
        )
        
        if success:
            logger.info(f"找到 {len(conn.entries)} 个用户")
            for entry in conn.entries:
                sam_account = entry.sAMAccountName.value if hasattr(entry, 'sAMAccountName') else 'N/A'
                upn = entry.userPrincipalName.value if hasattr(entry, 'userPrincipalName') else 'N/A'
                mail = entry.mail.value if hasattr(entry, 'mail') else 'N/A'
                logger.info(f"用户: {sam_account}, UPN: {upn}, 邮箱: {mail}")
        else:
            logger.error(f"搜索失败: {conn.result}")
    except Exception as e:
        logger.error(f"列出用户时出错: {str(e)}")

def main():
    # 测试LDAP连接
    conn, server = test_ldap_connection()
    if not conn:
        logger.error("LDAP连接测试失败，无法继续")
        return 1
    
    # 如果提供了用户名参数，则搜索该用户
    if len(sys.argv) > 1:
        username = sys.argv[1]
        search_user(conn, username)
    else:
        # 否则列出一些用户
        list_all_users(conn)
        logger.info("\n要搜索特定用户，请提供用户名作为参数: python test_ldap_connection.py <username>")
    
    # 关闭连接
    if conn:
        conn.unbind()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())