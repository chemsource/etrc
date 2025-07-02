import socket
import getpass

def start_client(server_ip, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
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
        
        print("认证成功！输入命令开始控制（输入exit退出）")
        while True:
            command = input("$> ")
            if not command:
                continue
            if command.lower() == "exit":
                client.send(command.encode())
                break
                
            client.send(command.encode())
            response = client.recv(4096).decode()
            print(response)
            
    except Exception as e:
        print(f"Connection error: {str(e)}")
    finally:
        client.close()
        print("Connection closed")

if __name__ == "__main__":
    print("请输入被控端ip地址：")
    TARGET_IP = input()
    print("请输入被控端端口：")
    PORT = int(input())
    start_client(TARGET_IP, PORT)