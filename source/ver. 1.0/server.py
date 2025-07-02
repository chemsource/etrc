import socket
import subprocess
import threading
import sys

def execute_command(command):
    """执行命令并返回结果"""
    try:
        # 使用Powershell确保命令正确执行（Windows系统）
        result = subprocess.check_output(
            [".etrc\powershell\powershell", "-Command", command], 
            stderr=subprocess.STDOUT,
            shell=True,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.output}"

def handle_client(client_socket):
    """处理客户端连接"""
    try:
        # 简单身份验证（可选）
        auth = client_socket.recv(1024).decode()
        if auth != "SECRET_KEY":  # 设置你的密钥
            client_socket.send("Authentication failed".encode())
            return
        
        client_socket.send("AUTH_SUCCESS".encode())
        
        while True:
            # 接收命令
            command = client_socket.recv(4096).decode()
            if command.lower().startswith("cd "):
                client_socket.send("Error: 'cd' is not supported in remote terminal.".encode())
                continue
            if not command or command.lower() == "exit":
                break
            
            # 执行命令并返回结果
            result = execute_command(command)
            client_socket.send(result.encode())
            
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        client_socket.close()
#='192.168.2.12' =5555
def start_server(host, port):
    """启动服务器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Listening on {host}:{port}")
    
    try:
        while True:
            client_sock, addr = server.accept()
            print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_sock,)
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
    start_server(host,port)