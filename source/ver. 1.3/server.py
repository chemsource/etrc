import socket
import subprocess
import threading
import sys
import getpass
import os  # 新增：用于目录操作

def execute_command(command, cwd):
    """执行命令并返回结果和新的工作目录"""
    try:
        result = subprocess.check_output(
            ["..\.etrc\powershell\powershell.exe", "-Command", command], 
            stderr=subprocess.STDOUT,
            shell=True,
            text=True,
            cwd=cwd  # 新增：在指定目录执行命令
        )
        new_cwd = cwd  # 命令执行后目录不变
        return result, new_cwd
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.output}", cwd

def handle_client(client_socket, control_password):
    """处理客户端连接"""
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
            command = client_socket.recv(4096).decode()
            
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

def start_server(host, port, control_password):
    """启动服务器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Listening on {host}:{port}")
    print(f"[*] Control password: {control_password} (One-time use)")
    
    try:
        while True:
            client_sock, addr = server.accept()
            print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_sock, control_password)
            )
            client_handler.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
        server.close()
        sys.exit(0)

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

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"本机IP地址: {local_ip}")
    print("请输入监听IP地址 (回车使用本机IP):")
    host = input().strip() or local_ip
    print("请输入端口：")
    port = int(input())
    print("设置被控端密码（一次一密）:")
    control_password = getpass.getpass("密码: ")
    start_server(host, port, control_password)