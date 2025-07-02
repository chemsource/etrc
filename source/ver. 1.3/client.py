import socket
import getpass

def start_client(server_ip, port):
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
    print("请输入被控端ip地址：")
    TARGET_IP = input()
    print("请输入被控端端口：")
    PORT = int(input())
    start_client(TARGET_IP, PORT)