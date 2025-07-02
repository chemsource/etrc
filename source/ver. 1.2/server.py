import socket
import subprocess
import threading
import sys
import getpass  # 安全输入密码

def execute_command(command):
    """执行命令并返回结果"""
    try:
        result = subprocess.check_output(
            ["powershell", "-Command", command], 
            stderr=subprocess.STDOUT,
            shell=True,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.output}"

def handle_client(client_socket, control_password):
    """处理客户端连接"""
    try:
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
        
        while True:
            command = client_socket.recv(4096).decode()
            if command.lower().startswith("cd "):
                client_socket.send("Error: 'cd' is not supported in remote terminal.".encode())
                continue
            if not command or command.lower() == "exit":
                break
            
            result = execute_command(command)
            client_socket.send(result.encode())
            
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

if __name__ == "__main__":
    print("请输入内网IP地址（通过设置或ipconfig查看）:")
    host = input()
    print("请输入端口：")
    port = int(input())
    print("设置被控端密码（一次一密）:")
    control_password = getpass.getpass("密码: ")
    start_server(host, port, control_password)