import socket
import subprocess
import threading
import sys
import getpass
import os
import time
import json
import base64
import hashlib
import binascii

# 全局状态变量
SERVER_THREAD = None
SERVER_RUNNING = False
SERVER_PAUSED = False
BLACKLIST = set()
PERMANENT_PASSWORD = None
CONFIG_FILE = "config.info"
ENCRYPTION_KEY = b'etrc-secret-key-12345'  # 加密密钥

def simple_encrypt(data, key):
    """简单的XOR加密函数"""
    # 如果密钥为空，返回原始数据（但这种情况不应该发生）
    if not key:
        return data
    
    # 将数据编码为字节
    data_bytes = data.encode('utf-8')
    
    # 扩展密钥以匹配数据长度
    key_extended = key * (len(data_bytes) // len(key)) + key[:len(data_bytes) % len(key)]
    
    # 执行XOR加密
    encrypted = bytes([b ^ k for b, k in zip(data_bytes, key_extended)])
    
    # 返回Base64编码的加密数据
    return base64.b64encode(encrypted).decode('utf-8')

def simple_decrypt(encrypted_data, key):
    """简单的XOR解密函数"""
    # 如果密钥为空，返回原始数据
    if not key:
        return encrypted_data
    
    try:
        # 解码Base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # 扩展密钥以匹配数据长度
        key_extended = key * (len(encrypted_bytes) // len(key)) + key[:len(encrypted_bytes) % len(key)]
        
        # 执行XOR解密
        decrypted = bytes([b ^ k for b, k in zip(encrypted_bytes, key_extended)])
        
        # 返回解密后的字符串
        return decrypted.decode('utf-8')
    except:
        return None

def load_config():
    """加载配置文件"""
    global BLACKLIST, PERMANENT_PASSWORD
    
    if not os.path.exists(CONFIG_FILE):
        print(f"配置文件 {CONFIG_FILE} 不存在，将创建新配置")
        return
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            encrypted_data = f.read()
            if not encrypted_data.strip():
                print("配置文件为空，跳过加载")
                return
                
            # 解密配置文件
            decrypted_data = simple_decrypt(encrypted_data, ENCRYPTION_KEY)
            if decrypted_data is None:
                print("配置文件解密失败，可能是格式错误或密钥不匹配")
                return
                
            config = json.loads(decrypted_data)
            
            BLACKLIST = set(config.get('blacklist', []))
            PERMANENT_PASSWORD = config.get('permanent_password')
            
            print(f"已从 {CONFIG_FILE} 加载配置")
            print(f"黑名单命令: {', '.join(BLACKLIST) if BLACKLIST else '无'}")
            
    except json.JSONDecodeError as e:
        print(f"配置文件格式错误: {str(e)}")
        print("将使用默认配置")
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}")
        print("将使用默认配置")

def save_config():
    """保存配置文件"""
    config = {
        'blacklist': list(BLACKLIST),
        'permanent_password': PERMANENT_PASSWORD
    }
    
    try:
        # 加密配置数据
        config_json = json.dumps(config, indent=2)
        encrypted_data = simple_encrypt(config_json, ENCRYPTION_KEY)
        
        with open(CONFIG_FILE, 'w') as f:
            f.write(encrypted_data)
        print(f"配置已加密保存到 {CONFIG_FILE}")
    except Exception as e:
        print(f"保存配置文件失败: {str(e)}")
        # 打印详细错误信息以便调试
        import traceback
        traceback.print_exc()

# 其余代码保持不变（get_local_ip, execute_command, handle_client, server_thread_func, start_server_mode, start_client_mode, change_permanent_password, main）
def get_local_ip():
    """获取本机IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def execute_command(command, cwd):
    """执行命令并返回结果和新的工作目录"""
    try:
        # 使用PowerShell执行命令
        result = subprocess.check_output(
            ["powershell", "-Command", command], 
            stderr=subprocess.STDOUT,
            shell=True,
            text=True,
            cwd=cwd
        )
        new_cwd = cwd  # 命令执行后目录不变
        return result, new_cwd
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.output}", cwd

def handle_client(client_socket, control_password):
    """处理客户端连接"""
    global SERVER_PAUSED, BLACKLIST, PERMANENT_PASSWORD
    
    try:
        cwd = os.getcwd()  # 初始当前目录
        
        # 第一次验证：固定密钥
        auth = client_socket.recv(1024).decode()
        if auth != "SECRET_KEY":
            client_socket.send("Authentication failed".encode())
            return
        client_socket.send("AUTH_STEP1_SUCCESS".encode())
        
        # 第二次验证：动态密码或长期密码
        password_attempt = client_socket.recv(1024).decode()
        
        # 验证密码：优先动态密码，然后长期密码
        if password_attempt == control_password or \
           (PERMANENT_PASSWORD and password_attempt == PERMANENT_PASSWORD):
            client_socket.send("AUTH_SUCCESS".encode())
        else:
            client_socket.send("AUTH_FAILED".encode())
            return
        
        # 发送初始工作目录给客户端
        client_socket.send(cwd.encode())
        
        while True:
            # 检查服务器是否被暂停
            while SERVER_PAUSED:
                time.sleep(0.5)  # 暂停时等待
            
            command = client_socket.recv(4096).decode()
            
            # 检查命令是否在黑名单中
            if any(cmd in command.lower() for cmd in BLACKLIST):
                response = f"Command blocked by server: {command}"
                client_socket.send(response.encode())
                continue
                
            # 处理cd命令 - 修改服务器工作目录
            if command.lower().startswith("cd "):
                try:
                    new_dir = command[3:].strip()
                    # 处理特殊路径
                    if new_dir == "..":
                        new_path = os.path.dirname(cwd)
                    elif new_dir.startswith("./"):
                        new_path = os.path.join(cwd, new_dir[2:])
                    else:
                        new_path = new_dir
                    
                    # 验证路径是否存在
                    if os.path.exists(new_path) and os.path.isdir(new_path):
                        os.chdir(new_path)
                        cwd = os.getcwd()
                        client_socket.send(cwd.encode())
                    else:
                        client_socket.send(f"Directory not found: {new_path}".encode())
                except Exception as e:
                    client_socket.send(f"cd failed: {str(e)}".encode())
                continue
                
            if not command or command.lower() == "exit":
                break
            
            # 执行命令并获取结果和新目录
            result, cwd = execute_command(command, cwd)
            
            # 发送命令结果和新目录给客户端
            response = cwd + "|||" + result  # 使用分隔符
            client_socket.send(response.encode())
            
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        client_socket.close()

def server_thread_func(host, port, control_password):
    """被控端线程函数"""
    global SERVER_RUNNING, SERVER_PAUSED
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
        server.listen(5)
        print(f"[*] Listening on {host}:{port}")
        print(f"[*] 动态密码: {control_password} (One-time use)")
        if PERMANENT_PASSWORD:
            print(f"[*] 长期密码: {PERMANENT_PASSWORD}")
        print("Server is running. Type 'over' to stop server.")
        
        SERVER_RUNNING = True
        SERVER_PAUSED = False
        
        while SERVER_RUNNING:
            client_sock, addr = server.accept()
            print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_sock, control_password)
            )
            client_handler.daemon = True
            client_handler.start()
            
    except Exception as e:
        if SERVER_RUNNING:  # 仅在运行状态下报告错误
            print(f"Server error: {str(e)}")
    finally:
        server.close()
        SERVER_RUNNING = False
        print("Server stopped.")

def start_server_mode():
    """启动被控模式"""
    global SERVER_THREAD, BLACKLIST
    
    local_ip = get_local_ip()
    print(f"本机IP地址: {local_ip}")
    print("请输入监听IP地址 (回车使用本机IP):")
    host = input().strip() or local_ip
    print("请输入端口：")
    port = int(input())
    print("设置被控端动态密码（一次一密）:")
    control_password = getpass.getpass("密码: ")
    
    # 启动服务器线程
    SERVER_THREAD = threading.Thread(
        target=server_thread_func,
        args=(host, port, control_password)
    )
    SERVER_THREAD.daemon = True
    SERVER_THREAD.start()
    
    # 进入server子命令模式
    while True:
        cmd = input("server> ").strip().lower()
        
        if cmd == "over":
            global SERVER_RUNNING
            SERVER_RUNNING = False
            # 创建一个虚拟连接来解除accept阻塞
            try:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.connect((host, port))
                temp_socket.close()
            except:
                pass
            time.sleep(1)  # 给服务器关闭的时间
            print("Server terminated.")
            return
            
        elif cmd == "stop":
            SERVER_PAUSED = True
            print("Server paused. Type 'begin' to resume.")
            
        elif cmd == "begin":
            # 无参数时清空黑名单
            BLACKLIST = set()
            save_config()
            SERVER_PAUSED = False
            print("黑名单已清空，Server resumed.")
            
        elif cmd.startswith("begin "):
            # 有参数时从黑名单中移除指定命令
            cmd_to_remove = cmd[6:].strip().lower()
            if cmd_to_remove in BLACKLIST:
                BLACKLIST.remove(cmd_to_remove)
                save_config()
                print(f"命令 '{cmd_to_remove}' 已从黑名单中移除")
            else:
                print(f"命令 '{cmd_to_remove}' 不在黑名单中")
            SERVER_PAUSED = False
            print("Server resumed.")
            
        elif cmd.startswith("stop "):
            # 添加命令到黑名单
            blocked_cmd = cmd[5:].strip().lower()
            BLACKLIST.add(blocked_cmd)
            save_config()
            print(f"命令 '{blocked_cmd}' 已添加到黑名单")
            
        elif cmd == "list":
            # 列出黑名单
            if BLACKLIST:
                print("黑名单命令:")
                for i, cmd in enumerate(BLACKLIST, 1):
                    print(f"  {i}. {cmd}")
            else:
                print("黑名单为空")
                
        elif cmd == "help":
            print("可用命令:")
            print("  over          - 停止服务器并返回就绪模式")
            print("  stop          - 暂停服务器")
            print("  begin         - 清空黑名单并恢复服务器")
            print("  begin [命令]  - 从黑名单移除指定命令并恢复服务器")
            print("  stop [命令]   - 添加命令到黑名单")
            print("  list          - 列出所有黑名单命令")
            print("  help          - 显示帮助信息")
            
        else:
            print("未知命令。输入 'help' 查看可用命令。")

def start_client_mode():
    """启动主控模式"""
    print("请输入被控端ip地址：")
    server_ip = input()
    print("请输入被控端端口：")
    port = int(input())
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_ip = get_local_ip()  # 获取主控端IP
    
    try:
        client.connect((server_ip, port))
        # 第一阶段验证：固定密钥
        client.send("SECRET_KEY".encode())
        
        auth_response = client.recv(1024).decode()
        if auth_response != "AUTH_STEP1_SUCCESS":
            print("Authentication failed (invalid server key)")
            return
        
        # 第二阶段验证：输入密码
        otp = getpass.getpass("请输入被控端密码 (动态或长期密码): ")
        client.send(otp.encode())
        
        final_auth = client.recv(1024).decode()
        if final_auth != "AUTH_SUCCESS":
            print("密码错误，连接被拒绝")
            return
        
        # 接收初始工作目录
        cwd = client.recv(4096).decode()
        
        print("认证成功！输入命令开始控制（输入exit退出）")
        while True:
            # 创建提示符: [主控IP]@[被控IP:端口] $ [被控目录] >
            prompt = f"[{local_ip}]@{server_ip}:{port} $ {cwd} > "
            command = input(prompt)
            
            if not command:
                continue
            if command.lower() == "exit":
                client.send(command.encode())
                break
                
            client.send(command.encode())
            
            # 接收响应 (包含目录和结果)
            response = client.recv(4096).decode()
            
            # 分割目录和命令结果
            if "|||" in response:
                cwd, result = response.split("|||", 1)
                print(result)
            else:
                # 处理没有分隔符的情况 (可能是错误消息)
                print(response)
                cwd = response  # 假设整个响应是目录更新
            
    except Exception as e:
        print(f"Connection error: {str(e)}")
    finally:
        client.close()
        print("Connection closed")

def change_permanent_password():
    """修改长期密码"""
    global PERMANENT_PASSWORD
    
    if PERMANENT_PASSWORD:
        # 如果已有密码，需要验证旧密码
        old_password = getpass.getpass("请输入原长期密码: ")
        if old_password != PERMANENT_PASSWORD:
            print("原密码错误，修改失败")
            return
    
    new_password = getpass.getpass("请输入新长期密码: ")
    confirm_password = getpass.getpass("请再次输入新长期密码: ")
    
    if new_password != confirm_password:
        print("两次输入的密码不一致，修改失败")
        return
    
    PERMANENT_PASSWORD = new_password
    save_config()
    print("长期密码修改成功")

# ... [其余函数保持不变] ...

def main():
    """主程序入口"""
    global PERMANENT_PASSWORD
    
    # 加载配置
    load_config()
    
    print("""
    ####################################################
    #               ETRC - Remote Terminal             #
    #      Enhanced Terminal Remote Control v2.0       #
    ####################################################
    """)
    
    # 如果没有长期密码，提示用户创建
    if PERMANENT_PASSWORD is None:
        print("检测到尚未设置长期密码，请设置一个长期密码")
        new_password = getpass.getpass("请输入新长期密码: ")
        confirm_password = getpass.getpass("请再次输入新长期密码: ")
        
        if new_password != confirm_password:
            print("两次输入的密码不一致，设置失败")
        else:
            PERMANENT_PASSWORD = new_password
            try:
                save_config()
                print("长期密码设置成功")
            except Exception as e:
                print(f"保存密码失败: {str(e)}")
                print("密码设置成功，但保存到配置文件失败")
    
    # 就绪模式循环
    while True:
        cmd = input("remote> ").strip().lower()
        
        if cmd == "server":
            start_server_mode()
            
        elif cmd == "client":
            start_client_mode()
            
        elif cmd == "change":
            change_permanent_password()
            
        elif cmd == "exit":
            # 如果服务器正在运行，先停止它
            global SERVER_RUNNING
            if SERVER_RUNNING:
                SERVER_RUNNING = False
                print("正在停止服务器...")
                time.sleep(1)
            print("退出 ETRC")
            sys.exit(0)
            
        elif cmd == "help":
            print("可用命令:")
            print("  server   - 进入被控模式")
            print("  client   - 进入主控模式")
            print("  change   - 修改长期密码")
            print("  exit     - 退出程序")
            print("  help     - 显示帮助信息")
            
        else:
            print("未知命令。输入 'help' 查看可用命令。")

if __name__ == "__main__":
    main()