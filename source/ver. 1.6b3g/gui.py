import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import threading
import sys
import os
import time
from core import *  # 导入核心功能

class ETRCGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ETRC - 增强型远程终端控制 v2.0")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # 初始化核心功能
        self.core = ETRCCore()
        
        # 创建主界面
        self.create_widgets()
        
        # 状态变量
        self.server_running = False
        self.client_connected = False
        
    def create_widgets(self):
        # 创建标签页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 控制台标签页
        self.console_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.console_tab, text="控制台")
        self.create_console_tab()
        
        # 被控模式标签页
        self.server_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.server_tab, text="被控模式")
        self.create_server_tab()
        
        # 主控模式标签页
        self.client_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.client_tab, text="主控模式")
        self.create_client_tab()
        
        # 配置标签页
        self.config_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="配置管理")
        self.create_config_tab()
        
        # 状态栏
        self.status_bar = tk.Label(self.root, text="就绪", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_console_tab(self):
        frame = ttk.LabelFrame(self.console_tab, text="系统信息")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 系统信息显示
        info_text = f"""ETRC - 增强型远程终端控制 v2.0

激活状态: {'已激活' if self.core.ACTIVATED else '未激活'}
激活原码: {self.core.ACTIVATION_CODE or '未生成'}
长期密码: {'已设置' if self.core.PERMANENT_PASSWORD else '未设置'}
黑名单命令数: {len(self.core.BLACKLIST)}
配置文件: {self.core.CONFIG_FILE}
"""
        self.info_label = tk.Label(frame, text=info_text, justify=tk.LEFT)
        self.info_label.pack(padx=10, pady=10, anchor=tk.NW)
        
        # 控制按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="激活程序", command=self.activate_program_gui).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="启动被控模式", command=self.start_server_gui).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="启动主控模式", command=self.start_client_gui).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="修改长期密码", command=self.change_password_gui).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="退出程序", command=self.on_close).pack(side=tk.RIGHT, padx=5)
    
    def create_server_tab(self):
        # 服务器设置
        settings_frame = ttk.LabelFrame(self.server_tab, text="服务器设置")
        settings_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # IP地址
        ip_frame = ttk.Frame(settings_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(ip_frame, text="监听IP:").pack(side=tk.LEFT)
        self.server_ip_var = tk.StringVar(value=self.core.get_local_ip())
        tk.Entry(ip_frame, textvariable=self.server_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        # 端口
        port_frame = ttk.Frame(settings_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(port_frame, text="端口:").pack(side=tk.LEFT)
        self.server_port_var = tk.StringVar(value="8888")
        tk.Entry(port_frame, textvariable=self.server_port_var, width=8).pack(side=tk.LEFT, padx=5)
        
        # 密码
        pass_frame = ttk.Frame(settings_frame)
        pass_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(pass_frame, text="动态密码:").pack(side=tk.LEFT)
        self.server_pass_var = tk.StringVar()
        tk.Entry(pass_frame, textvariable=self.server_pass_var, show="*", width=15).pack(side=tk.LEFT, padx=5)
        
        # 服务器控制按钮
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.start_server_btn = tk.Button(btn_frame, text="启动服务器", command=self.toggle_server)
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        # 服务器状态
        status_frame = ttk.LabelFrame(self.server_tab, text="服务器状态")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.server_status_var = tk.StringVar(value="状态: 已停止")
        tk.Label(status_frame, textvariable=self.server_status_var).pack(padx=5, pady=5, anchor=tk.W)
        
        # 黑名单管理
        blacklist_frame = ttk.LabelFrame(self.server_tab, text="黑名单管理")
        blacklist_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        # 黑名单列表
        list_frame = ttk.Frame(blacklist_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.blacklist_listbox = tk.Listbox(list_frame)
        self.blacklist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        scrollbar = tk.Scrollbar(list_frame, command=self.blacklist_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.blacklist_listbox.config(yscrollcommand=scrollbar.set)
        
        # 黑名单控制
        control_frame = ttk.Frame(blacklist_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.cmd_entry_var = tk.StringVar()
        tk.Entry(control_frame, textvariable=self.cmd_entry_var, width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="添加到黑名单", command=self.add_to_blacklist).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="从黑名单移除", command=self.remove_from_blacklist).pack(side=tk.LEFT, padx=5)
        
        # 服务器命令
        cmd_frame = ttk.Frame(blacklist_frame)
        cmd_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(cmd_frame, text="暂停服务器", command=lambda: self.server_command("stop")).pack(side=tk.LEFT, padx=5)
        tk.Button(cmd_frame, text="恢复服务器", command=lambda: self.server_command("begin")).pack(side=tk.LEFT, padx=5)
        tk.Button(cmd_frame, text="停止服务器", command=lambda: self.server_command("over")).pack(side=tk.LEFT, padx=5)
        
        # 日志区域
        log_frame = ttk.LabelFrame(self.server_tab, text="服务器日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        self.server_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8)
        self.server_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.server_log.config(state=tk.DISABLED)
    
    def create_client_tab(self):
        # 连接设置
        settings_frame = ttk.LabelFrame(self.client_tab, text="连接设置")
        settings_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # 目标IP
        ip_frame = ttk.Frame(settings_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(ip_frame, text="目标IP:").pack(side=tk.LEFT)
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(ip_frame, textvariable=self.target_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        # 端口
        port_frame = ttk.Frame(settings_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(port_frame, text="端口:").pack(side=tk.LEFT)
        self.target_port_var = tk.StringVar(value="8888")
        tk.Entry(port_frame, textvariable=self.target_port_var, width=8).pack(side=tk.LEFT, padx=5)
        
        # 连接按钮
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.connect_btn = tk.Button(btn_frame, text="连接", command=self.toggle_client_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        # 连接状态
        status_frame = ttk.LabelFrame(self.client_tab, text="连接状态")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.client_status_var = tk.StringVar(value="状态: 未连接")
        tk.Label(status_frame, textvariable=self.client_status_var).pack(padx=5, pady=5, anchor=tk.W)
        
        # 命令输入
        cmd_frame = ttk.LabelFrame(self.client_tab, text="命令执行")
        cmd_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.cmd_history = scrolledtext.ScrolledText(cmd_frame, wrap=tk.WORD, height=12)
        self.cmd_history.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.cmd_history.config(state=tk.DISABLED)
        
        input_frame = ttk.Frame(cmd_frame)
        input_frame.pack(fill=tk.X, pady=(0, 5), padx=5)
        
        self.cmd_input_var = tk.StringVar()
        self.cmd_entry = tk.Entry(input_frame, textvariable=self.cmd_input_var)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.cmd_entry.bind("<Return>", self.send_command)
        self.cmd_entry.config(state=tk.DISABLED)
        
        tk.Button(input_frame, text="发送", command=self.send_command).pack(side=tk.RIGHT)
    
    def create_config_tab(self):
        # 配置信息
        info_frame = ttk.LabelFrame(self.config_tab, text="配置信息")
        info_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        config_text = f"""配置文件: {self.core.CONFIG_FILE}
激活状态: {'已激活' if self.core.ACTIVATED else '未激活'}
激活原码: {self.core.ACTIVATION_CODE or '未生成'}
长期密码: {'已设置' if self.core.PERMANENT_PASSWORD else '未设置'}
黑名单命令数: {len(self.core.BLACKLIST)}
"""
        tk.Label(info_frame, text=config_text, justify=tk.LEFT).pack(padx=10, pady=10, anchor=tk.NW)
        
        # 配置操作
        action_frame = ttk.LabelFrame(self.config_tab, text="配置操作")
        action_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        btn_frame = ttk.Frame(action_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="生成激活密钥", command=self.generate_activation_key).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="修改激活状态", command=self.change_activation_status).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="修改配置文件路径", command=self.change_config_path).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="清空黑名单", command=self.clear_blacklist).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="保存配置", command=self.core.save_config).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="重新加载配置", command=self.reload_config).pack(side=tk.LEFT, padx=5)
    
    def update_status(self, message):
        self.status_bar.config(text=message)
        self.root.update_idletasks()
    
    def log_server_message(self, message):
        self.server_log.config(state=tk.NORMAL)
        self.server_log.insert(tk.END, message + "\n")
        self.server_log.see(tk.END)
        self.server_log.config(state=tk.DISABLED)
    
    def log_client_message(self, message):
        self.cmd_history.config(state=tk.NORMAL)
        self.cmd_history.insert(tk.END, message + "\n")
        self.cmd_history.see(tk.END)
        self.cmd_history.config(state=tk.DISABLED)
    
    def activate_program_gui(self):
        if self.core.ACTIVATED:
            messagebox.showinfo("激活状态", "程序已激活")
            return
        
        if not self.core.ACTIVATION_CODE:
            self.core.ACTIVATION_CODE = self.core.generate_activation_code()
        
        activation_window = tk.Toplevel(self.root)
        activation_window.title("程序激活")
        activation_window.geometry("500x300")
        activation_window.transient(self.root)
        activation_window.grab_set()
        
        tk.Label(activation_window, text="程序未激活，需要激活才能使用", font=("Arial", 12, "bold")).pack(pady=10)
        
        tk.Label(activation_window, text="您的激活原码:").pack(pady=(10, 0))
        tk.Label(activation_window, text=self.core.ACTIVATION_CODE, font=("Arial", 14, "bold")).pack()
        
        tk.Label(activation_window, text="请联系开发者获取激活密钥").pack(pady=5)
        
        tk.Label(activation_window, text="请输入激活密钥:").pack(pady=(20, 5))
        key_var = tk.StringVar()
        tk.Entry(activation_window, textvariable=key_var, width=20, show="*").pack()
        
        def attempt_activation():
            key = key_var.get()
            if self.core.check_activation_key(self.core.ACTIVATION_CODE, key):
                self.core.ACTIVATED = True
                self.core.save_config()
                messagebox.showinfo("激活成功", "程序已成功激活！")
                activation_window.destroy()
                self.update_info()
            else:
                messagebox.showerror("激活失败", "激活密钥错误！")
        
        tk.Button(activation_window, text="激活", command=attempt_activation).pack(pady=20)
    
    def start_server_gui(self):
        self.notebook.select(self.server_tab)
    
    def start_client_gui(self):
        self.notebook.select(self.client_tab)
    
    def toggle_server(self):
        if self.server_running:
            self.stop_server()
        else:
            self.start_server()
    
    def start_server(self):
        try:
            host = self.server_ip_var.get()
            port = int(self.server_port_var.get())
            password = self.server_pass_var.get()
            
            if not password:
                messagebox.showerror("错误", "请输入动态密码")
                return
            
            # 启动服务器线程
            self.server_thread = threading.Thread(
                target=self.core.server_thread_func,
                args=(host, port, password),
                daemon=True
            )
            self.server_thread.start()
            
            self.server_running = True
            self.start_server_btn.config(text="停止服务器")
            self.server_status_var.set(f"状态: 运行中 - {host}:{port}")
            self.log_server_message(f"[*] 服务器启动于 {host}:{port}")
            self.log_server_message(f"[*] 动态密码: {password}")
            if self.core.PERMANENT_PASSWORD:
                self.log_server_message(f"[*] 长期密码: {self.core.PERMANENT_PASSWORD}")
            
            self.update_status("服务器已启动")
        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {str(e)}")
    
    def stop_server(self):
        self.core.SERVER_RUNNING = False
        try:
            # 创建一个虚拟连接来解除accept阻塞
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((self.server_ip_var.get(), int(self.server_port_var.get())))
            temp_socket.close()
        except:
            pass
        
        time.sleep(1)
        self.server_running = False
        self.start_server_btn.config(text="启动服务器")
        self.server_status_var.set("状态: 已停止")
        self.log_server_message("[*] 服务器已停止")
        self.update_status("服务器已停止")
    
    def server_command(self, cmd):
        if not self.server_running:
            messagebox.showwarning("警告", "服务器未运行")
            return
        
        if cmd == "stop":
            self.core.SERVER_PAUSED = True
            self.log_server_message("[*] 服务器已暂停")
        elif cmd == "begin":
            self.core.BLACKLIST = set()
            self.core.save_config()
            self.core.SERVER_PAUSED = False
            self.log_server_message("[*] 黑名单已清空，服务器已恢复")
            self.update_blacklist()
        elif cmd == "over":
            self.stop_server()
    
    def toggle_client_connection(self):
        if self.client_connected:
            self.disconnect_client()
        else:
            self.connect_client()
    
    def connect_client(self):
        try:
            server_ip = self.target_ip_var.get()
            port = int(self.target_port_var.get())
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, port))
            
            # 第一阶段验证：固定密钥
            self.client_socket.send("SECRET_KEY".encode())
            
            auth_response = self.client_socket.recv(1024).decode()
            if auth_response != "AUTH_STEP1_SUCCESS":
                messagebox.showerror("认证失败", "无效的服务器密钥")
                self.client_socket.close()
                return
            
            # 密码输入对话框
            password = simpledialog.askstring("密码验证", "请输入被控端密码 (动态或长期密码):", show='*')
            if password is None:  # 用户取消
                self.client_socket.close()
                return
                
            self.client_socket.send(password.encode())
            
            final_auth = self.client_socket.recv(1024).decode()
            if final_auth != "AUTH_SUCCESS":
                messagebox.showerror("认证失败", "密码错误，连接被拒绝")
                self.client_socket.close()
                return
            
            # 接收初始工作目录
            self.current_cwd = self.client_socket.recv(4096).decode()
            
            self.client_connected = True
            self.connect_btn.config(text="断开连接")
            self.client_status_var.set(f"状态: 已连接 - {server_ip}:{port}")
            self.cmd_entry.config(state=tk.NORMAL)
            self.log_client_message("认证成功！输入命令开始控制（输入exit退出）")
            self.update_status(f"已连接到 {server_ip}:{port}")
        except Exception as e:
            messagebox.showerror("连接错误", f"连接失败: {str(e)}")
    
    def disconnect_client(self):
        try:
            self.client_socket.send("exit".encode())
            self.client_socket.close()
        except:
            pass
        
        self.client_connected = False
        self.connect_btn.config(text="连接")
        self.client_status_var.set("状态: 未连接")
        self.cmd_entry.config(state=tk.DISABLED)
        self.log_client_message("连接已关闭")
        self.update_status("连接已关闭")
    
    def send_command(self, event=None):
        if not self.client_connected:
            return
        
        command = self.cmd_input_var.get()
        if not command:
            return
        
        try:
            self.client_socket.send(command.encode())
            
            # 接收响应
            response = self.client_socket.recv(4096).decode()
            
            if "|||" in response:
                self.current_cwd, result = response.split("|||", 1)
                self.log_client_message(result)
            else:
                self.log_client_message(response)
                self.current_cwd = response
            
            # 更新提示符
            self.cmd_history.config(state=tk.NORMAL)
            self.cmd_history.insert(tk.END, f"{self.current_cwd} > ")
            self.cmd_history.see(tk.END)
            self.cmd_history.config(state=tk.DISABLED)
            
            self.cmd_input_var.set("")
        except Exception as e:
            self.log_client_message(f"命令执行错误: {str(e)}")
            self.disconnect_client()
    
    def change_password_gui(self):
        if not self.core.ACTIVATED:
            messagebox.showerror("错误", "程序未激活，无法修改密码")
            return
            
        old_password = ""
        if self.core.PERMANENT_PASSWORD:
            old_password = simpledialog.askstring("原密码", "请输入原长期密码:", show='*')
            if old_password is None:  # 用户取消
                return
            if old_password != self.core.PERMANENT_PASSWORD:
                messagebox.showerror("错误", "原密码错误")
                return
        
        new_password = simpledialog.askstring("新密码", "请输入新长期密码:", show='*')
        if new_password is None:  # 用户取消
            return
        
        confirm_password = simpledialog.askstring("确认密码", "请再次输入新长期密码:", show='*')
        if confirm_password is None:  # 用户取消
            return
        
        if new_password != confirm_password:
            messagebox.showerror("错误", "两次输入的密码不一致")
            return
        
        self.core.PERMANENT_PASSWORD = new_password
        self.core.save_config()
        messagebox.showinfo("成功", "长期密码修改成功")
        self.update_info()
    
    def generate_activation_key(self):
        if not self.core.ACTIVATION_CODE:
            self.core.ACTIVATION_CODE = self.core.generate_activation_code()
        
        key = self.core.calculate_activation_key(self.core.ACTIVATION_CODE)
        messagebox.showinfo("激活密钥", 
                          f"激活原码: {self.core.ACTIVATION_CODE}\n\n激活密钥: {key}")
    
    def change_activation_status(self):
        choice = messagebox.askyesno("激活状态", "是否将程序设置为已激活状态?")
        self.core.ACTIVATED = choice
        self.core.save_config()
        status = "已激活" if choice else "未激活"
        messagebox.showinfo("成功", f"激活状态已设置为: {status}")
        self.update_info()
    
    def change_config_path(self):
        new_path = simpledialog.askstring("配置文件路径", "请输入新的配置文件路径:")
        if new_path:
            self.core.CONFIG_FILE = new_path
            self.core.load_config()
            messagebox.showinfo("成功", f"配置文件路径已更改为: {new_path}")
            self.update_info()
    
    def clear_blacklist(self):
        self.core.BLACKLIST = set()
        self.core.save_config()
        self.update_blacklist()
        messagebox.showinfo("成功", "黑名单已清空")
    
    def add_to_blacklist(self):
        cmd = self.cmd_entry_var.get().strip().lower()
        if not cmd:
            messagebox.showwarning("警告", "请输入要添加到黑名单的命令")
            return
        
        self.core.BLACKLIST.add(cmd)
        self.core.save_config()
        self.update_blacklist()
        messagebox.showinfo("成功", f"命令 '{cmd}' 已添加到黑名单")
    
    def remove_from_blacklist(self):
        selected = self.blacklist_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请选择要移除的命令")
            return
        
        cmd = self.blacklist_listbox.get(selected[0])
        if cmd in self.core.BLACKLIST:
            self.core.BLACKLIST.remove(cmd)
            self.core.save_config()
            self.update_blacklist()
            messagebox.showinfo("成功", f"命令 '{cmd}' 已从黑名单移除")
    
    def reload_config(self):
        self.core.load_config()
        self.update_info()
        messagebox.showinfo("成功", "配置已重新加载")
    
    def update_info(self):
        info_text = f"""ETRC - 增强型远程终端控制 v2.0

激活状态: {'已激活' if self.core.ACTIVATED else '未激活'}
激活原码: {self.core.ACTIVATION_CODE or '未生成'}
长期密码: {'已设置' if self.core.PERMANENT_PASSWORD else '未设置'}
黑名单命令数: {len(self.core.BLACKLIST)}
配置文件: {self.core.CONFIG_FILE}
"""
        self.info_label.config(text=info_text)
    
    def update_blacklist(self):
        self.blacklist_listbox.delete(0, tk.END)
        for cmd in self.core.BLACKLIST:
            self.blacklist_listbox.insert(tk.END, cmd)
    
    def on_close(self):
        if self.server_running:
            self.stop_server()
        
        if self.client_connected:
            self.disconnect_client()
        
        self.root.destroy()
        sys.exit(0)

class ETRCCore:
    """封装ETRC核心功能"""
    def __init__(self):
        # 初始化全局变量
        self.SERVER_THREAD = None
        self.SERVER_RUNNING = False
        self.SERVER_PAUSED = False
        self.BLACKLIST = set()
        self.PERMANENT_PASSWORD = None
        self.ACTIVATED = False
        self.ACTIVATION_CODE = None
        self.CONFIG_FILE = "config.info"
        self.ENCRYPTION_KEY = b'etrc-secret-key-12345'
        
        # 加载配置
        self.load_config()
    
    # 以下方法复制自etrc.py，稍作修改以适合类结构
    def generate_activation_code(self):
        """生成16位随机激活原码"""
        import random
        import string
        chars = string.ascii_uppercase + string.digits
        return ''.join(random.choice(chars) for _ in range(16))
    
    def calculate_activation_key(self, activation_code):
        """根据激活原码计算激活密钥"""
        salt = "ETRC_ACTIVATION_SALT_2023!@#"
        combined = activation_code + salt
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        hash_bytes = hash_obj.digest()
        encoded = base64.b64encode(hash_bytes).decode('utf-8')
        key = encoded[:16].upper()
        return f"{key[:4]}-{key[4:8]}-{key[8:12]}-{key[12:16]}"
    
    def check_activation_key(self, activation_code, key):
        """检查激活密钥是否正确"""
        try:
            correct_key = self.calculate_activation_key(activation_code)
            return key == correct_key
        except:
            return False
    
    def simple_encrypt(self, data, key):
        """简单的XOR加密函数"""
        if not key:
            return data
        data_bytes = data.encode('utf-8')
        key_extended = key * (len(data_bytes) // len(key)) + key[:len(data_bytes) % len(key)]
        encrypted = bytes([b ^ k for b, k in zip(data_bytes, key_extended)])
        return base64.b64encode(encrypted).decode('utf-8')
    
    def simple_decrypt(self, encrypted_data, key):
        """简单的XOR解密函数"""
        if not key:
            return encrypted_data
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            key_extended = key * (len(encrypted_bytes) // len(key)) + key[:len(encrypted_bytes) % len(key)]
            decrypted = bytes([b ^ k for b, k in zip(encrypted_bytes, key_extended)])
            return decrypted.decode('utf-8')
        except:
            return None
    
    def load_config(self):
        """加载配置文件"""
        if not os.path.exists(self.CONFIG_FILE):
            print(f"配置文件 {self.CONFIG_FILE} 不存在，将创建新配置")
            return
        
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                encrypted_data = f.read()
                if not encrypted_data.strip():
                    print("配置文件为空，跳过加载")
                    return
                    
                decrypted_data = self.simple_decrypt(encrypted_data, self.ENCRYPTION_KEY)
                if decrypted_data is None:
                    print("配置文件解密失败，可能是格式错误或密钥不匹配")
                    return
                    
                config = json.loads(decrypted_data)
                
                self.BLACKLIST = set(config.get('blacklist', []))
                self.PERMANENT_PASSWORD = config.get('permanent_password')
                self.ACTIVATED = config.get('activated', False)
                self.ACTIVATION_CODE = config.get('activation_code', None)
                
                print(f"已从 {self.CONFIG_FILE} 加载配置")
        except json.JSONDecodeError as e:
            print(f"配置文件格式错误: {str(e)}")
        except Exception as e:
            print(f"加载配置文件失败: {str(e)}")
    
    def save_config(self):
        """保存配置文件"""
        config = {
            'blacklist': list(self.BLACKLIST),
            'permanent_password': self.PERMANENT_PASSWORD,
            'activated': self.ACTIVATED,
            'activation_code': self.ACTIVATION_CODE
        }
        
        try:
            config_json = json.dumps(config, indent=2)
            encrypted_data = self.simple_encrypt(config_json, self.ENCRYPTION_KEY)
            
            with open(self.CONFIG_FILE, 'w') as f:
                f.write(encrypted_data)
            print(f"配置已加密保存到 {self.CONFIG_FILE}")
            return True
        except Exception as e:
            print(f"保存配置文件失败: {str(e)}")
            return False
    
    def get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def server_thread_func(self, host, port, control_password):
        """被控端线程函数"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((host, port))
            server.listen(5)
            print(f"[*] Listening on {host}:{port}")
            print(f"[*] 动态密码: {control_password} (One-time use)")
            if self.PERMANENT_PASSWORD:
                print(f"[*] 长期密码: {self.PERMANENT_PASSWORD}")
            
            self.SERVER_RUNNING = True
            self.SERVER_PAUSED = False
            
            while self.SERVER_RUNNING:
                client_sock, addr = server.accept()
                print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, control_password)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            if self.SERVER_RUNNING:
                print(f"Server error: {str(e)}")
        finally:
            server.close()
            self.SERVER_RUNNING = False
            print("Server stopped.")
    
    def handle_client(self, client_socket, control_password):
        """处理客户端连接"""
        try:
            cwd = os.getcwd()
            
            auth = client_socket.recv(1024).decode()
            if auth != "SECRET_KEY":
                client_socket.send("Authentication failed".encode())
                return
            client_socket.send("AUTH_STEP1_SUCCESS".encode())
            
            password_attempt = client_socket.recv(1024).decode()
            
            if password_attempt == control_password or \
               (self.PERMANENT_PASSWORD and password_attempt == self.PERMANENT_PASSWORD):
                client_socket.send("AUTH_SUCCESS".encode())
            else:
                client_socket.send("AUTH_FAILED".encode())
                return
            
            client_socket.send(cwd.encode())
            
            while True:
                while self.SERVER_PAUSED:
                    time.sleep(0.5)
                
                command = client_socket.recv(4096).decode()
                
                if any(cmd in command.lower() for cmd in self.BLACKLIST):
                    response = f"Command blocked by server: {command}"
                    client_socket.send(response.encode())
                    continue
                    
                if command.lower().startswith("cd "):
                    try:
                        new_dir = command[3:].strip()
                        if new_dir == "..":
                            new_path = os.path.dirname(cwd)
                        elif new_dir.startswith("./"):
                            new_path = os.path.join(cwd, new_dir[2:])
                        else:
                            new_path = new_dir
                        
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
                
                result, cwd = self.execute_command(command, cwd)
                response = cwd + "|||" + result
                client_socket.send(response.encode())
                
        except Exception as e:
            print(f"Error: {str(e)}")
        finally:
            client_socket.close()
    
    def execute_command(self, command, cwd):
        """执行命令并返回结果和新的工作目录"""
        try:
            result = subprocess.check_output(
                ["powershell", "-Command", command], 
                stderr=subprocess.STDOUT,
                shell=True,
                text=True,
                cwd=cwd
            )
            new_cwd = cwd
            return result, new_cwd
        except subprocess.CalledProcessError as e:
            return f"Command execution failed: {e.output}", cwd

if __name__ == "__main__":
    root = tk.Tk()
    app = ETRCGUI(root)
    root.mainloop()