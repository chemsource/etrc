import socket
import subprocess
import threading
import sys
import getpass
import os
import time

# 全局状态变量
SERVER_THREAD = None
SERVER_RUNNING = False
SERVER_PAUSED = False
BLACKLIST = set()

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
    global SERVER_PAUSED, BLACKLIST
    
    try:
        cwd = os.getcwd()  # 初始当前目录
        
        # 第一次验证：固定密钥
        auth = client_socket.recv(1024).decode()
        if auth != "SECRET_KEY":
            client_socket.send("Authentication failed".encode())
            return
        client_socket.send("AUTH_STEP1_SUCCESS".encode())
        
        # 第二次验证：动态密码
        otp_attempt = client_socket.recv(1024).decode()
        if otp_attempt != control_password:
            client_socket.send("OTP_FAILED".encode())
            return
        client_socket.send("AUTH_SUCCESS".encode())
        
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
        print(f"[*] Control password: {control_password} (One-time use)")
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
    print("设置被控端密码（一次一密）:")
    control_password = getpass.getpass("密码: ")
    
    # 重置黑名单
    BLACKLIST = set()
    
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
            SERVER_PAUSED = False
            print("Server resumed.")
            
        elif cmd.startswith("stop "):
            # 添加命令到黑名单
            blocked_cmd = cmd[5:].strip()
            BLACKLIST.add(blocked_cmd.lower())
            print(f"Command '{blocked_cmd}' added to blacklist.")
            
        else:
            print("Unknown server command. Available: over, stop, begin, stop [command]")

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
        
        # 第二阶段验证：动态密码
        otp = getpass.getpass("请输入被控端密码: ")
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

def main():
    """主程序入口"""
    print("""
    ####################################################
    #               ETRC - Remote Terminal             #
    #      Enhanced Terminal Remote Control v1.0       #
    ####################################################
    """)
    
    # 就绪模式循环
    while True:
        cmd = input("remote> ").strip().lower()
        
        if cmd == "server":
            start_server_mode()
            
        elif cmd == "client":
            start_client_mode()
            
        elif cmd == "exit":
            # 如果服务器正在运行，先停止它
            global SERVER_RUNNING
            if SERVER_RUNNING:
                SERVER_RUNNING = False
                print("Stopping server...")
                time.sleep(1)
            print("Exiting ETRC.")
            sys.exit(0)
            
        elif cmd == "help":
            print("Available commands:")
            print("  server   - Start in server mode")
            print("  client   - Start in client mode")
            print("  exit     - Exit the program")
            print("  help     - Show this help message")
            
        else:
            print("Unknown command. Type 'help' for available commands.")

if __name__ == "__main__":
    main()