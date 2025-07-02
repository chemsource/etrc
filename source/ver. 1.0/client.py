import socket

def start_client(server_ip, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((server_ip, port))
        # 发送身份验证
        client.send("SECRET_KEY".encode())  # 与服务器相同的密钥
        
        auth_response = client.recv(1024).decode()
        if auth_response != "AUTH_SUCCESS":
            print("Authentication failed")
            return
        
        print("Connected to remote terminal. Type 'exit' to quit.")
        while True:
            command = input("$> ")
            if not command:
                continue
            if command.lower() == "exit":
                client.send(command.encode())
                break
                
            client.send(command.encode())
            # 接收响应
            response = client.recv(4096).decode()
            print(response)
            
    except Exception as e:
        print(f"Connection error: {str(e)}")
    finally:
        client.close()
        print("Connection closed")

if __name__ == "__main__":
    #TARGET_IP = "192.168.2.12"   修改为被控端IP
    print("请输入被控端ip地址：")
    TARGET_IP = input()
    print("请输入被控端端口：")
    PORT = int(input())
    start_client(TARGET_IP,PORT)