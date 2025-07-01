# client.py

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
import socket
import threading
import json
import base64
import io
import os
from PIL import Image, ImageTk
import sys
import time

# 导入我们的加密和信息隐藏工具
import crypto_utils as c_utils

SERVER_HOST = '127.0.0.1'  # 如果服务器在另一台机器上，请更改此IP
SERVER_PORT = 8888

# 全局变量，用于存储临时图片文件
TEMP_IMAGE_PATH = "temp_chat_image.png"


class ChatClient(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("安全即时通讯")
        self.geometry("1000x700")  # 增加窗口大小以容纳好友管理功能

        self.username = None
        self.private_key = None
        self.public_key = None
        self.sock = None
        self.connected = False

        # 存储会话密钥 { 'friend_username': b'aes_key' }
        self.session_keys = {}
        # 存储好友的公钥 { 'friend_username': public_key_object }
        self.friend_public_keys = {}

        self.current_chat_partner = None
        self.friends = []  # 存储好友列表
        self.unread_messages = {}  # 存储未读消息 {发送者: [消息列表]}
        self.message_indicators = {}  # 存储好友列表中的消息提示标签

        # 初始化UI控件属性
        self.login_frame = None
        self.chat_frame = None
        self.friends_list = None
        self.online_list = None
        self.chat_partner_label = None
        self.chat_box = None
        self.msg_entry = None
        self.send_button = None
        self.steg_button = None
        self.username_entry = None
        self.password_entry = None
        self.friend_entry = None
        self.add_friend_button = None
        self.remove_friend_button = None

        # 用于存储图片引用，防止被垃圾回收
        self.image_references = []

        self.show_login_frame()

        print("客户端初始化完成")

        # 将 protocol 调用移到 on_closing 方法定义之后
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_chat_ui(self):
        """登录成功后，创建主聊天界面"""
        print("正在创建聊天界面...")
        if self.login_frame:
            self.login_frame.destroy()
            print("登录界面已销毁")

        self.chat_frame = tk.Frame(self)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        print("创建了聊天框架")

        # 左侧面板：好友和在线用户
        left_panel = tk.Frame(self.chat_frame, width=200)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # 好友管理区域
        friend_management_frame = tk.Frame(left_panel)
        friend_management_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(friend_management_frame, text="好友管理").pack(anchor=tk.W)

        self.friend_entry = tk.Entry(friend_management_frame)
        self.friend_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.add_friend_button = tk.Button(friend_management_frame, text="添加", command=self.add_friend)
        self.add_friend_button.pack(side=tk.LEFT, padx=(0, 5))

        self.remove_friend_button = tk.Button(friend_management_frame, text="移除", command=self.remove_friend)
        self.remove_friend_button.pack(side=tk.LEFT)

        # 好友列表
        tk.Label(left_panel, text="好友列表").pack(anchor=tk.W)
        self.friends_list = tk.Listbox(left_panel, width=25)
        self.friends_list.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.friends_list.bind('<<ListboxSelect>>', self.on_friend_select)

        # 在线用户列表
        tk.Label(left_panel, text="在线用户").pack(anchor=tk.W)
        self.online_list = tk.Listbox(left_panel, width=25)
        self.online_list.pack(fill=tk.BOTH, expand=True)
        self.online_list.bind('<<ListboxSelect>>', self.on_online_user_select)

        # 聊天区域
        chat_area_frame = tk.Frame(self.chat_frame)
        chat_area_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        print("创建了聊天区域框架")

        self.chat_partner_label = tk.Label(chat_area_frame, text="请选择一个好友开始聊天", font=("Arial", 14))
        self.chat_partner_label.pack(pady=5)
        print("创建了聊天伙伴标签")

        self.chat_box = scrolledtext.ScrolledText(chat_area_frame, state='disabled', wrap=tk.WORD)
        self.chat_box.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        print("创建了聊天框")

        # 消息输入区
        input_frame = tk.Frame(chat_area_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        print("创建了输入框架")

        self.msg_entry = tk.Entry(input_frame, font=("Arial", 12))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)
        print("创建了消息输入框")

        self.send_button = tk.Button(input_frame, text="发送", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        print("创建了发送按钮")

        self.steg_button = tk.Button(input_frame, text="发送藏图", command=self.send_steganography_image)
        self.steg_button.pack(side=tk.RIGHT)
        print("创建了藏图按钮")

        print("聊天界面创建完成")
        self.update()  # 强制更新界面
        print("界面更新完成")

        # 登录成功后立即请求在线用户列表
        req = {"action": "get_online_list"}
        self.send_to_server(req)
        print("已发送获取在线列表请求")

    def show_login_frame(self):
        """显示登录/注册界面"""
        print("显示登录界面")
        self.login_frame = tk.Frame(self)
        self.login_frame.pack(padx=20, pady=20)

        tk.Label(self.login_frame, text="用户名:").grid(row=0, column=0, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, pady=5)

        tk.Label(self.login_frame, text="密码:").grid(row=1, column=0, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)

        tk.Button(self.login_frame, text="登录", command=self.login).grid(row=2, column=0, pady=10)
        tk.Button(self.login_frame, text="注册", command=self.register).grid(row=2, column=1, pady=10)
        print("登录界面创建完成")

    def connect_to_server(self):
        """建立与服务器的连接"""
        try:
            print(f"尝试连接到服务器 {SERVER_HOST}:{SERVER_PORT}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            self.connected = True
            print("服务器连接成功")
            # 启动一个线程来监听来自服务器的消息
            listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
            listen_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("连接错误", f"无法连接到服务器: {e}")
            print(f"连接错误: {e}")
            return False

    def send_to_server(self, data):
        """将JSON数据发送到服务器"""
        if self.connected:
            try:
                message = json.dumps(data) + '\n'
                print(f"发送到服务器: {message}")
                self.sock.sendall(message.encode('utf-8'))
            except Exception as e:
                messagebox.showerror("发送错误", f"与服务器断开连接: {e}")
                print(f"发送错误: {e}")
                self.on_closing()

    def login(self):
        """处理登录逻辑"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("输入错误", "用户名和密码不能为空")
            return

        print(f"用户尝试登录: {username}")

        # 尝试加载用户的密钥，如果不存在则提示
        try:
            print(f"尝试加载用户密钥: {username}")
            with open(f"{username}_private.pem", "r") as f:
                self.private_key = c_utils.load_private_key(f.read())
            with open(f"{username}_public.pem", "r") as f:
                self.public_key = c_utils.load_public_key(f.read())
            print("密钥加载成功")
        except FileNotFoundError:
            messagebox.showerror("密钥错误", f"找不到用户'{username}'的密钥文件。请先注册。")
            print("密钥文件未找到")
            return
        except Exception as e:
            messagebox.showerror("密钥错误", f"加载密钥时出错: {e}")
            print(f"密钥加载错误: {e}")
            return

        if self.connect_to_server():
            self.username = username
            req = {"action": "login", "payload": {"username": username, "password": password}}
            print(f"发送登录请求: {req}")
            self.send_to_server(req)

    def register(self):
        """处理注册逻辑"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("输入错误", "用户名和密码不能为空")
            return

        print(f"用户尝试注册: {username}")

        email = simpledialog.askstring("邮箱", "请输入您的邮箱:", parent=self)
        if not email:
            print("注册取消: 未提供邮箱")
            return

        # 生成并保存密钥对
        try:
            print("生成RSA密钥对...")
            private_key, public_key = c_utils.generate_rsa_keys()
            with open(f"{username}_private.pem", "w") as f:
                f.write(c_utils.serialize_private_key(private_key))
            with open(f"{username}_public.pem", "w") as f:
                f.write(c_utils.serialize_public_key(public_key))
            print("密钥对生成并保存成功")

            public_key_str = c_utils.serialize_public_key(public_key)

            if self.connect_to_server():
                req = {
                    "action": "register",
                    "payload": {
                        "username": username,
                        "password": password,
                        "email": email,
                        "public_key": public_key_str
                    }
                }
                print(f"发送注册请求: {req}")
                self.send_to_server(req)
        except Exception as e:
            messagebox.showerror("注册错误", f"注册过程中出错: {e}")
            print(f"注册错误: {e}")

    def listen_for_messages(self):
        """在后台线程中持续监听服务器消息"""
        print("开始监听服务器消息...")
        try:
            server_file = self.sock.makefile('r')
            for line in server_file:
                try:
                    response = json.loads(line)
                    print(f"收到原始服务器消息: {line.strip()}")
                    print(f"解析后的服务器响应: {response}")
                    self.after(0, self.handle_server_response, response)  # 在主线程中处理UI更新
                except json.JSONDecodeError as e:
                    print(f"JSON解析错误: {e}, 原始数据: {line}")
                except Exception as e:
                    print(f"处理消息时出错: {e}")
        except Exception as e:
            if self.connected:
                print(f"监听线程错误: {e}")
                self.after(0, lambda: messagebox.showerror("连接丢失", "与服务器的连接已断开。"))
                self.after(0, self.on_closing)
        print("监听线程结束")

    def handle_server_response(self, response):
        """根据服务器的响应类型执行相应操作"""
        print(f"处理服务器响应: {response}")

        action = response.get("action")
        status = response.get("status")
        message = response.get("message")
        payload = response.get("payload")

        # --- 处理登录/注册响应 ---
        if (action in ["register", "login"]) or (status and message and not action):
            print(f"处理登录/注册响应: status={status}, message={message}")
            if status == "ok":
                if action == "login" or (not action and "登录成功" in message):
                    print("登录成功，正在创建聊天界面...")
                    self.setup_chat_ui()

                    # 更新好友列表
                    if "friends" in response:
                        self.friends = response["friends"]
                        self.update_friends_list()
            else:
                print(f"操作失败: {message}")
                messagebox.showerror("操作失败", message)
                self.on_closing()

        # --- 更新在线用户列表 ---
        elif action == "update_online_list":
            print(f"更新在线列表: {payload}")
            # 确保聊天界面已经创建
            if hasattr(self, 'online_list') and self.online_list:
                self.online_list.delete(0, tk.END)
                online_users = payload
                for user in sorted(online_users):
                    if user != self.username:
                        self.online_list.insert(tk.END, user)
            else:
                print("警告: 尝试更新在线列表但online_list未初始化")

        # --- 收到好友公钥 ---
        elif status == "ok" and "public_key" in response:
            friend_name = response.get("username")
            public_key_str = response.get("public_key")
            print(f"收到 {friend_name} 的公钥")

            # 加载并存储好友的公钥对象
            try:
                friend_public_key = c_utils.load_public_key(public_key_str)
                self.friend_public_keys[friend_name] = friend_public_key

                # 生成、加密并发送会话密钥
                session_key = c_utils.generate_aes_key()
                self.session_keys[friend_name] = session_key  # 存储会话密钥

                encrypted_session_key = c_utils.rsa_encrypt(friend_public_key, session_key)
                # Base64编码以便在JSON中传输
                encrypted_session_key_b64 = base64.b64encode(encrypted_session_key).decode('utf-8')

                req = {
                    "action": "forward_message",
                    "payload": {
                        "to": friend_name,
                        "type": "key_exchange",
                        "key": encrypted_session_key_b64
                    }
                }
                self.send_to_server(req)
                self.display_message("System", f"已与 {friend_name} 建立安全通道。")
            except Exception as e:
                print(f"处理公钥时出错: {e}")

        # --- 收到消息 ---
        elif action == "receive_message":
            from_user = payload.get("from")
            msg_type = payload.get("type")
            print(f"收到来自 {from_user} 的消息, 类型: {msg_type}")

            # 如果是密钥交换请求
            if msg_type == "key_exchange":
                encrypted_key_b64 = payload.get("key")
                encrypted_key = base64.b64decode(encrypted_key_b64)

                # 用自己的私钥解密得到会话密钥
                try:
                    session_key = c_utils.rsa_decrypt(self.private_key, encrypted_key)
                    self.session_keys[from_user] = session_key
                    self.display_message("System", f"已与 {from_user} 建立安全通道。")
                except Exception as e:
                    print(f"解密会话密钥时出错: {e}")

            # 如果是加密的文本消息
            elif msg_type == "text":
                encrypted_msg_b64 = payload.get("content")
                encrypted_msg = base64.b64decode(encrypted_msg_b64)

                session_key = self.session_keys.get(from_user)
                if session_key:
                    try:
                        decrypted_msg = c_utils.aes_decrypt(session_key, encrypted_msg).decode('utf-8')

                        # 如果当前聊天对象是消息发送者，直接显示消息
                        if self.current_chat_partner == from_user:
                            self.display_message(from_user, decrypted_msg)
                        else:
                            # 否则存储为未读消息并更新提示
                            self.add_unread_message(from_user, decrypted_msg)

                    except Exception as e:
                        print(f"解密文本消息时出错: {e}")
                else:
                    self.display_message("System", f"收到来自{from_user}的加密消息，但没有会话密钥。")

            # 如果是加密的图片消息
            elif msg_type == "steganography":
                encrypted_img_data_b64 = payload.get("content")
                encrypted_img_data = base64.b64decode(encrypted_img_data_b64)

                session_key = self.session_keys.get(from_user)
                if session_key:
                    try:
                        decrypted_img_data = c_utils.aes_decrypt(session_key, encrypted_img_data)

                        # 方法1：直接从字节数据创建图片对象
                        try:
                            img = Image.open(io.BytesIO(decrypted_img_data))
                            hidden_message = c_utils.extract_message_from_image(img)

                            # 如果当前聊天对象是消息发送者，直接显示图片
                            if self.current_chat_partner == from_user:
                                self.display_image_message(from_user, img, f"隐藏消息: {hidden_message}")
                            else:
                                # 否则存储为未读消息并更新提示
                                self.add_unread_image(from_user, img, hidden_message)

                        except Exception as img_error:
                            print(f"直接处理图片数据失败: {img_error}, 尝试保存到文件")

                            # 方法2：保存到文件再处理
                            try:
                                with open(TEMP_IMAGE_PATH, "wb") as f:
                                    f.write(decrypted_img_data)
                                    f.flush()  # 确保数据写入磁盘
                                    os.fsync(f.fileno())  # 强制同步到磁盘

                                # 验证文件是否有效
                                if os.path.exists(TEMP_IMAGE_PATH) and os.path.getsize(TEMP_IMAGE_PATH) > 0:
                                    hidden_message = c_utils.extract_message_from_image(TEMP_IMAGE_PATH)

                                    # 如果当前聊天对象是消息发送者，直接显示图片
                                    if self.current_chat_partner == from_user:
                                        self.display_image_message(from_user, TEMP_IMAGE_PATH,
                                                                   f"隐藏消息: {hidden_message}")
                                    else:
                                        # 否则存储为未读消息并更新提示
                                        self.add_unread_image(from_user, TEMP_IMAGE_PATH, hidden_message)
                                else:
                                    print("临时文件创建失败或为空")
                                    self.display_message(from_user, f"收到图片但无法显示 (文件创建失败)")
                            except Exception as file_error:
                                print(f"处理图片文件时出错: {file_error}")
                                self.display_message(from_user, f"收到图片但无法显示: {file_error}")
                    except Exception as e:
                        print(f"处理图片消息时出错: {e}")
                        self.display_message("System", f"处理图片消息时出错: {e}")

        # --- 好友列表更新 ---
        elif action == "friend_update":
            friend = payload.get("friend")
            action_type = payload.get("action")

            if action_type == "add":
                if friend not in self.friends:
                    self.friends.append(friend)
                    self.update_friends_list()
                    self.display_message("System", f"已添加 '{friend}' 为好友")
            elif action_type == "remove":
                if friend in self.friends:
                    self.friends.remove(friend)
                    self.update_friends_list()
                    self.display_message("System", f"已移除好友 '{friend}'")

        # --- 好友请求通知 ---
        elif action == "friend_request":
            sender = payload.get("sender")
            action_type = payload.get("action")
            status = payload.get("status")

            if action_type == "request" and status == "pending":
                # 弹出确认对话框
                answer = messagebox.askyesno(
                    "好友请求",
                    f"用户 '{sender}' 请求添加您为好友。\n是否同意？",
                    parent=self
                )

                # 发送响应给服务器
                req = {
                    "action": "respond_friend_request",
                    "payload": {
                        "sender": sender,
                        "accept": answer
                    }
                }
                self.send_to_server(req)

            elif action_type == "request" and status == "accepted":
                # 请求被接受
                self.display_message("System", f"用户 '{sender}' 接受了您的好友请求")

            elif action_type == "request" and status == "rejected":
                # 请求被拒绝
                messagebox.showinfo("好友请求", f"用户 '{sender}' 拒绝了您的好友请求。", parent=self)

            elif action_type == "add" and status == "accepted":
                # 双方已添加为好友
                self.display_message("System", f"您和 '{sender}' 已成为好友")

            elif action_type == "remove" and status == "removed":
                # 被移除好友
                messagebox.showinfo("好友关系", f"您已被 '{sender}' 从好友列表中移除", parent=self)
                if sender in self.friends:
                    self.friends.remove(sender)
                    self.update_friends_list()

    def add_unread_message(self, sender, message):
        """添加未读文本消息"""
        if sender not in self.unread_messages:
            self.unread_messages[sender] = []

        self.unread_messages[sender].append({
            "type": "text",
            "content": message,
            "timestamp": time.time()
        })

        # 更新好友列表提示
        self.update_friend_indicator(sender)

        # 显示系统通知
        self.display_message("System", f"收到来自 {sender} 的新消息")

    def add_unread_image(self, sender, image_source, hidden_message):
        """添加未读图片消息"""
        if sender not in self.unread_messages:
            self.unread_messages[sender] = []

        # 如果是文件路径，存储路径；如果是图片对象，存储为二进制数据
        if isinstance(image_source, str):
            # 文件路径
            self.unread_messages[sender].append({
                "type": "image_path",
                "path": image_source,
                "hidden_message": hidden_message,
                "timestamp": time.time()
            })
        else:
            # 图片对象，转换为二进制数据存储
            byte_io = io.BytesIO()
            image_source.save(byte_io, format='PNG')
            image_data = byte_io.getvalue()

            self.unread_messages[sender].append({
                "type": "image_data",
                "data": image_data,
                "hidden_message": hidden_message,
                "timestamp": time.time()
            })

        # 更新好友列表提示
        self.update_friend_indicator(sender)

        # 显示系统通知
        self.display_message("System", f"收到来自 {sender} 的图片消息")

    def update_friend_indicator(self, friend):
        """更新好友的消息提示"""
        if friend not in self.message_indicators:
            # 创建新提示
            indicator = tk.Label(self.friends_list, text="●", fg="red", font=("Arial", 10, "bold"))
            self.message_indicators[friend] = indicator

            # 查找好友在列表中的位置
            try:
                idx = self.friends_list.get(0, tk.END).index(friend)
                self.friends_list.itemconfig(idx, fg="blue")
            except ValueError:
                pass

        # 更新提示文本显示未读消息数量
        count = len(self.unread_messages.get(friend, []))
        if count > 0:
            self.message_indicators[friend].config(text=f"●{count}")
        else:
            self.message_indicators[friend].config(text="●")

        # 确保提示可见
        self.message_indicators[friend].pack_forget()
        self.message_indicators[friend].pack(side=tk.RIGHT)

    def update_friends_list(self):
        """更新好友列表显示"""
        if hasattr(self, 'friends_list') and self.friends_list:
            self.friends_list.delete(0, tk.END)
            for friend in sorted(self.friends):
                self.friends_list.insert(tk.END, friend)

                # 如果有未读消息，添加提示
                if friend in self.unread_messages and self.unread_messages[friend]:
                    self.update_friend_indicator(friend)

    def on_friend_select(self, event):
        """当在好友列表中选择一个好友时触发"""
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            friend_name = event.widget.get(index)
            self.start_chat_with_friend(friend_name)

    def on_online_user_select(self, event):
        """当在在线用户列表中选择一个用户时触发"""
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            user_name = event.widget.get(index)
            self.start_chat_with_friend(user_name)

    def start_chat_with_friend(self, friend_name):
        """开始与选定的好友聊天"""
        self.current_chat_partner = friend_name
        self.chat_partner_label.config(text=f"与 {friend_name} 聊天中")
        self.chat_box.config(state='normal')
        self.chat_box.delete(1.0, tk.END)
        self.chat_box.config(state='disabled')

        # 显示所有未读消息
        if friend_name in self.unread_messages and self.unread_messages[friend_name]:
            self.display_message("System", f"显示来自 {friend_name} 的未读消息:")

            for msg in self.unread_messages[friend_name]:
                if msg["type"] == "text":
                    self.display_message(friend_name, msg["content"])
                elif msg["type"] == "image_path":
                    self.display_image_message(friend_name, msg["path"], f"隐藏消息: {msg['hidden_message']}")
                elif msg["type"] == "image_data":
                    img = Image.open(io.BytesIO(msg["data"]))
                    self.display_image_message(friend_name, img, f"隐藏消息: {msg['hidden_message']}")

            # 清空未读消息
            self.unread_messages[friend_name] = []

            # 移除消息提示
            if friend_name in self.message_indicators:
                self.message_indicators[friend_name].pack_forget()
                self.message_indicators.pop(friend_name)

            # 重置好友列表颜色
            try:
                idx = self.friends_list.get(0, tk.END).index(friend_name)
                self.friends_list.itemconfig(idx, fg="black")
            except ValueError:
                pass

        # 如果还没有会话密钥，则向服务器请求对方公钥以启动密钥交换
        if friend_name not in self.session_keys:
            self.display_message("System", f"正在向 {friend_name} 发起安全连接请求...")
            req = {"action": "get_public_key", "payload": {"username": friend_name}}
            self.send_to_server(req)

    def add_friend(self):
        """添加好友"""
        friend_name = self.friend_entry.get().strip()
        if not friend_name:
            messagebox.showwarning("输入错误", "请输入好友用户名")
            return

        if friend_name == self.username:
            messagebox.showwarning("输入错误", "不能添加自己为好友")
            return

        if friend_name in self.friends:
            messagebox.showwarning("好友关系", f"'{friend_name}' 已经是您的好友")
            return

        req = {
            "action": "add_friend",
            "payload": {
                "friend": friend_name
            }
        }
        self.send_to_server(req)
        self.friend_entry.delete(0, tk.END)

    def remove_friend(self):
        """移除好友"""
        friend_name = self.friend_entry.get().strip()
        if not friend_name:
            messagebox.showwarning("输入错误", "请输入好友用户名")
            return

        if friend_name not in self.friends:
            messagebox.showwarning("好友关系", f"'{friend_name}' 不是您的好友")
            return

        req = {
            "action": "remove_friend",
            "payload": {
                "friend": friend_name
            }
        }
        self.send_to_server(req)
        self.friend_entry.delete(0, tk.END)

    def send_message(self, event=None):
        """发送文本消息"""
        msg_content = self.msg_entry.get()
        if not msg_content or not self.current_chat_partner:
            return

        # 使用会话密钥加密消息
        session_key = self.session_keys.get(self.current_chat_partner)
        if not session_key:
            messagebox.showerror("错误", "尚未与该用户建立安全连接。")
            return

        encrypted_msg = c_utils.aes_encrypt(session_key, msg_content.encode('utf-8'))
        encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode('utf-8')

        req = {
            "action": "forward_message",
            "payload": {
                "to": self.current_chat_partner,
                "type": "text",
                "content": encrypted_msg_b64
            }
        }
        self.send_to_server(req)
        self.display_message(self.username, msg_content)  # 在自己的窗口显示明文
        self.msg_entry.delete(0, tk.END)

    def send_steganography_image(self):
        """发送带有隐藏信息图片"""
        if not self.current_chat_partner:
            messagebox.showerror("错误", "请先选择一个聊天好友。")
            return

        session_key = self.session_keys.get(self.current_chat_partner)
        if not session_key:
            messagebox.showerror("错误", "尚未与该用户建立安全连接。")
            return

        secret_message = simpledialog.askstring("秘密消息", "请输入您想隐藏在图片中的消息:", parent=self)
        if not secret_message: return

        filepath = filedialog.askopenfilename(
            title="选择一张载体图片 (PNG格式)",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if not filepath: return

        try:
            # 1. 嵌入信息
            image_with_hidden_msg = c_utils.hide_message_in_image(filepath, secret_message)
            # 将图片对象保存到内存中的字节流
            byte_io = io.BytesIO()
            image_with_hidden_msg.save(byte_io, format='PNG')
            image_data = byte_io.getvalue()

            # 2. 用AES加密整个图片数据
            encrypted_image_data = c_utils.aes_encrypt(session_key, image_data)
            encrypted_image_data_b64 = base64.b64encode(encrypted_image_data).decode('utf-8')

            # 3. 发送
            req = {
                "action": "forward_message",
                "payload": {
                    "to": self.current_chat_partner,
                    "type": "steganography",
                    "content": encrypted_image_data_b64
                }
            }
            self.send_to_server(req)

            # 4. 在发送方显示图片和隐藏信息
            self.display_image_message(self.username, image_with_hidden_msg, f"已发送图片，隐藏消息: {secret_message}")

        except Exception as e:
            messagebox.showerror("错误", f"处理图片失败: {e}")

    def display_message(self, sender, message):
        """在聊天框中显示文本消息"""
        # 确保聊天框已创建
        if hasattr(self, 'chat_box') and self.chat_box:
            self.chat_box.config(state='normal')
            self.chat_box.insert(tk.END, f"[{sender}]: {message}\n")
            self.chat_box.config(state='disabled')
            self.chat_box.yview(tk.END)

    def display_image_message(self, sender, image_source, message=None):
        """
        在聊天框中显示图片消息
        image_source 可以是文件路径或 PIL.Image 对象
        """
        # 确保聊天框已创建
        if hasattr(self, 'chat_box') and self.chat_box:
            try:
                self.chat_box.config(state='normal')

                # 插入发送者标签
                self.chat_box.insert(tk.END, f"[{sender}]:\n")

                # 根据输入类型处理图片
                if isinstance(image_source, str):  # 文件路径
                    # 验证文件是否存在且有效
                    if os.path.exists(image_source) and os.path.getsize(image_source) > 0:
                        try:
                            img = Image.open(image_source)
                        except Exception as e:
                            print(f"打开图片文件失败: {e}")
                            self.chat_box.insert(tk.END, "无法打开图片文件\n")
                            return
                    else:
                        self.chat_box.insert(tk.END, "图片文件不存在或为空\n")
                        return
                elif isinstance(image_source, Image.Image):  # PIL.Image 对象
                    img = image_source
                else:
                    self.chat_box.insert(tk.END, "不支持的图片源类型\n")
                    return

                # 创建缩略图
                img.thumbnail((200, 200))

                # 转换为Tkinter可用的格式
                photo_img = ImageTk.PhotoImage(img)

                # 保留图片引用，防止被垃圾回收
                self.image_references.append(photo_img)

                # 在聊天框中插入图片
                self.chat_box.image_create(tk.END, image=photo_img)

                # 添加换行
                self.chat_box.insert(tk.END, "\n")

                # 添加隐藏消息文本
                if message:
                    self.chat_box.insert(tk.END, f"{message}\n")

                self.chat_box.config(state='disabled')
                self.chat_box.yview(tk.END)
            except Exception as e:
                print(f"显示图片消息时出错: {e}")
                self.display_message(sender, "无法显示图片")

    def on_closing(self):
        """关闭窗口时的清理工作"""
        print("正在关闭客户端...")
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
                print("已关闭套接字连接")
            except Exception as e:
                print(f"关闭套接字时出错: {e}")

        # 清理临时文件
        try:
            if os.path.exists(TEMP_IMAGE_PATH):
                os.remove(TEMP_IMAGE_PATH)
                print("已清理临时图片文件")
        except Exception as e:
            print(f"清理临时文件时出错: {e}")

        self.destroy()
        print("客户端已关闭")


if __name__ == "__main__":
    print("启动客户端...")
    app = ChatClient()
    app.mainloop()
    print("客户端退出")