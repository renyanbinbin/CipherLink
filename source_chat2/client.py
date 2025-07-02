# client.py

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog, Menu, ttk
import socket
import threading
import json
import base64
import io
import os
from PIL import Image, ImageTk
import sys
import time
import uuid
import hashlib

# 导入我们的加密和信息隐藏工具
import crypto_utils as c_utils

SERVER_HOST = '127.0.0.1'  # 如果服务器在另一台机器上，请更改此IP
SERVER_PORT = 8888

# 全局变量，用于存储临时图片文件
TEMP_IMAGE_PATH = "temp_chat_image.png"


class ChatClient(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("安全即时通讯系统")
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
        self.chat_history = {}  # 存储每个好友的聊天记录 {好友名: 聊天内容}

        # 新增：存储已发送的消息ID {消息ID: (好友名, 消息类型, 消息位置)}
        self.sent_messages = {}
        # 新增：存储已接收的消息ID {消息ID: 消息位置}
        self.received_messages = {}

        # 确保以下属性在 __init__ 中正确定义
        self.file_transfers = {}  # 存储文件传输状态
        self.unread_messages = {}  # 存储未读消息
        self.message_indicators = {}  # 存储好友列表中的消息提示标签
        self.image_references = []  # 用于存储图片引用，防止被垃圾回收

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
        self.recall_button = None  # 新增：撤回按钮

        self.pending_file_chunks = {}

        self.file_transfers = {}
        self.pending_cache_requests = {}  # 新增：缓存块请求状态

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

        # 新增：撤回按钮
        self.recall_button = tk.Button(friend_management_frame, text="撤回", command=self.recall_message)
        self.recall_button.pack(side=tk.LEFT, padx=(5, 0))

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

        # 新增：为聊天框添加右键菜单
        self.chat_menu = Menu(self.chat_box, tearoff=0)
        self.chat_menu.add_command(label="撤回消息", command=self.recall_selected_message)
        self.chat_box.bind("<Button-3>", self.show_chat_menu)

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

        # 在输入框旁边添加文件传输按钮
        self.file_button = tk.Button(input_frame, text="发送文件", command=self.send_file)
        self.file_button.pack(side=tk.RIGHT, padx=5)

        # 在聊天框下方添加文件传输进度条区域
        self.file_transfer_frame = tk.Frame(chat_area_frame)
        self.file_transfer_frame.pack(fill=tk.X, padx=5, pady=5)

        self.progress_label = tk.Label(self.file_transfer_frame, text="文件传输:")
        self.progress_label.pack(anchor=tk.W)

        self.progress_bar = ttk.Progressbar(self.file_transfer_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        self.progress_bar.pack_forget()  # 初始隐藏

        self.progress_text = tk.Label(self.file_transfer_frame, text="")
        self.progress_text.pack(anchor=tk.W)

        self.file_transfers = {}  # 确保已定义
        self.pending_file_chunks = {}  # 新增：存储尚未接受的待处理文件块

    def show_progress(self, label, total):
        """显示传输进度条"""
        self.progress_label.config(text=label)
        self.progress_bar['maximum'] = total
        self.progress_bar['value'] = 0
        self.progress_text.config(text="0%")
        self.progress_bar.pack(fill=tk.X, pady=5)  # 确保进度条可见
        # 不要在这里调用 hide_progress()!

    def update_progress(self, percent):
        """更新进度显示"""
        self.progress_bar['value'] = percent * self.progress_bar['maximum'] / 100
        self.progress_text.config(text=f"{percent}%")

    def hide_progress(self):
        """隐藏进度条"""
        self.progress_bar.pack_forget()
        self.progress_text.config(text="")


    def show_chat_menu(self, event):
        """显示聊天框的右键菜单"""
        try:
            # 获取点击位置的消息ID
            index = self.chat_box.index(f"@{event.x},{event.y}")
            tags = self.chat_box.tag_names(index)

            # 查找消息ID标签
            message_id = None
            for tag in tags:
                if tag.startswith("msg_"):
                    message_id = tag
                    break

            if message_id:
                # 检查是否是自己发送的消息
                if message_id in self.sent_messages:
                    self.selected_message_id = message_id
                    self.chat_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"显示聊天菜单出错: {e}")

    def recall_selected_message(self):
        """撤回选中的消息"""
        if hasattr(self, 'selected_message_id'):
            self.recall_message(self.selected_message_id)
            del self.selected_message_id

    def recall_message(self, message_id=None):
        """撤回消息"""
        if not self.current_chat_partner:
            messagebox.showerror("错误", "请先选择一个聊天好友。")
            return

        if not message_id:
            # 如果没有提供消息ID，尝试获取最后一条自己发送的消息
            last_sent_id = None
            for msg_id, (friend, _, _) in self.sent_messages.items():
                if friend == self.current_chat_partner:
                    last_sent_id = msg_id
                    break

            if not last_sent_id:
                messagebox.showinfo("提示", "没有可撤回的消息")
                return

            message_id = last_sent_id

        # 检查消息是否可以被撤回
        if message_id not in self.sent_messages:
            messagebox.showerror("错误", "无法撤回该消息")
            return

        friend, msg_type, _ = self.sent_messages[message_id]

        if friend != self.current_chat_partner:
            messagebox.showerror("错误", "该消息不是发送给当前聊天好友的")
            return

        # 发送撤回请求到服务器
        req = {
            "action": "recall_message",
            "payload": {
                "message_id": message_id,
                "to": friend
            }
        }
        self.send_to_server(req)

        # 本地立即更新显示
        self.process_message_recall(message_id, self.username)

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

        # 确保 file_transfers 属性存在
        if not hasattr(self, 'file_transfers'):
            self.file_transfers = {}

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
                # self.on_closing()

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
                self.display_message("System", f"已与 {friend_name} 建立安全通道。", friend_name)
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
                    self.display_message("System", f"已与 {from_user} 建立安全通道。", from_user)
                except Exception as e:
                    print(f"解密会话密钥时出错: {e}")

            # 如果是加密的文本消息
            elif msg_type == "text":
                encrypted_msg_b64 = payload.get("content")
                encrypted_msg = base64.b64decode(encrypted_msg_b64)
                message_id = payload.get("message_id")  # 新增：获取消息ID

                session_key = self.session_keys.get(from_user)
                if session_key:
                    try:
                        decrypted_msg = c_utils.aes_decrypt(session_key, encrypted_msg).decode('utf-8')

                        # 如果当前聊天对象是消息发送者，直接显示消息
                        if self.current_chat_partner == from_user:
                            self.display_message(from_user, decrypted_msg, from_user, message_id)
                        else:
                            # 否则存储为未读消息并更新提示
                            self.add_unread_message(from_user, decrypted_msg, message_id)

                    except Exception as e:
                        print(f"解密文本消息时出错: {e}")
                else:
                    self.display_message("System", f"收到来自{from_user}的加密消息，但没有会话密钥。", from_user)

            # 如果是加密的图片消息
            elif msg_type == "steganography":
                encrypted_img_data_b64 = payload.get("content")
                encrypted_img_data = base64.b64decode(encrypted_img_data_b64)
                message_id = payload.get("message_id")  # 新增：获取消息ID

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
                                self.display_image_message(from_user, img, f"隐藏消息: {hidden_message}", from_user,
                                                           message_id)
                            else:
                                # 否则存储为未读消息并更新提示
                                self.add_unread_image(from_user, img, hidden_message, message_id)

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
                                                                   f"隐藏消息: {hidden_message}", from_user, message_id)
                                    else:
                                        # 否则存储为未读消息并更新提示
                                        self.add_unread_image(from_user, TEMP_IMAGE_PATH, hidden_message, message_id)
                                else:
                                    print("临时文件创建失败或为空")
                                    self.display_message(from_user, f"收到图片但无法显示 (文件创建失败)", from_user)
                            except Exception as file_error:
                                print(f"处理图片文件时出错: {file_error}")
                                self.display_message(from_user, f"收到图片但无法显示: {file_error}", from_user)
                    except Exception as e:
                        print(f"处理图片消息时出错: {e}")
                        self.display_message("System", f"处理图片消息时出错: {e}", from_user)

        # --- 新增：处理消息撤回通知 ---
        elif action == "message_recalled":
            message_id = payload.get("message_id")
            recalled_by = payload.get("recalled_by")
            self.process_message_recall(message_id, recalled_by)

        # --- 好友列表更新 ---
        elif action == "friend_update":
            friend = payload.get("friend")
            action_type = payload.get("action")

            if action_type == "add":
                if friend not in self.friends:
                    self.friends.append(friend)
                    self.update_friends_list()
                    self.display_message("System", f"已添加 '{friend}' 为好友", friend)
            elif action_type == "remove":
                if friend in self.friends:
                    self.friends.remove(friend)
                    self.update_friends_list()
                    self.display_message("System", f"已移除好友 '{friend}'", friend)

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
                self.display_message("System", f"用户 '{sender}' 接受了您的好友请求", sender)

            elif action_type == "request" and status == "rejected":
                # 请求被拒绝
                messagebox.showinfo("好友请求", f"用户 '{sender}' 拒绝了您的好友请求。", parent=self)

            elif action_type == "add" and status == "accepted":
                # 双方已添加为好友
                self.display_message("System", f"您和 '{sender}' 已成为好友", sender)

            elif action_type == "remove" and status == "removed":
                # 被移除好友
                messagebox.showinfo("好友关系", f"您已被 '{sender}' 从好友列表中移除", parent=self)
                if sender in self.friends:
                    self.friends.remove(sender)
                    self.update_friends_list()


        # --- 文件传输请求 ---
        elif action == "file_request":
            from_user = payload.get("from")
            file_id = payload.get("file_id")
            file_name = payload.get("file_name")
            file_size = payload.get("file_size")
            file_hash = payload.get("file_hash")

            # 询问用户是否接收文件
            answer = messagebox.askyesno(
                "接收文件",
                f"{from_user} 想发送文件: {file_name} ({file_size} 字节)\n是否接收？",
                parent=self
            )

            if answer:
                # 选择保存位置
                save_path = filedialog.asksaveasfilename(
                    title="保存文件",
                    initialfile=file_name
                )

                if save_path:
                    # 初始化文件传输状态
                    self.file_transfers[file_id] = {
                        "file_name": file_name,
                        "file_size": file_size,
                        "file_hash": file_hash,
                        "save_path": save_path,
                        "received_size": 0,
                        "file": open(save_path, 'wb'),
                        "sender": from_user,
                        "status": "receiving"
                    }

                    # 显示进度条
                    self.show_progress(f"接收: {file_name}", file_size)

                    # 发送接受响应
                    req = {
                        "action": "file_accept",
                        "payload": {
                            "to": from_user,
                            "file_id": file_id,
                            "accept": True
                        }
                    }
                    self.send_to_server(req)
                else:
                    # 用户取消保存
                    req = {
                        "action": "file_accept",
                        "payload": {
                            "to": from_user,
                            "file_id": file_id,
                            "accept": False
                        }
                    }
                    self.send_to_server(req)
            else:
                # 拒绝接收
                req = {
                    "action": "file_accept",
                    "payload": {
                        "to": from_user,
                        "file_id": file_id,
                        "accept": False
                    }
                }
                self.send_to_server(req)


        # --- 文件传输开始 ---
        elif action == "file_start" and all(key in payload for key in ["file_id", "file_name", "file_size", "file_hash"]):
            file_id = payload.get("file_id")
            file_name = payload.get("file_name")
            file_size = payload.get("file_size")
            file_hash = payload.get("file_hash")
            sender = payload.get("from")

            # 询问用户是否接收文件
            answer = messagebox.askyesno(
                "接收文件",
                f"{sender} 想发送文件: {file_name} ({file_size} 字节)\n是否接收？",
                parent=self
            )

            if file_id in self.file_transfers:
                self.display_message("System", f"{sender} 已接受文件传输", sender)

            if answer:
                # 选择保存位置
                save_path = filedialog.asksaveasfilename(
                    title="保存文件",
                    initialfile=file_name
                )

                if save_path:

                    try:
                        # 初始化文件传输状态
                        self.file_transfers[file_id] = {
                            "file_name": file_name,
                            "file_size": file_size,
                            "file_hash": file_hash,
                            "save_path": save_path,
                            "received_size": 0,
                            "file": open(save_path, 'wb'),
                            "sender": sender,
                            "status": "receiving"
                        }

                        # 更新进度显示
                        self.show_progress(f"接收: {file_name}", file_size)

                        # 发送接受响应
                        req = {
                            "action": "file_accept",
                            "payload": {
                                "to": sender,
                                "file_id": file_id,
                                "accept": True
                            }
                        }
                        self.send_to_server(req)

                    except Exception as e:
                        messagebox.showerror("错误", f"创建文件失败: {e}")
                        req = {
                            "action": "file_accept",
                            "payload": {
                                "to": sender,
                                "file_id": file_id,
                                "accept": False
                            }
                        }
                        self.send_to_server(req)
                else:
                    # 用户取消保存
                    req = {
                        "action": "file_accept",
                        "payload": {
                            "to": sender,  # 指定接收者为发送方
                            "file_id": file_id,
                            "accept": False
                        }
                    }
                    self.send_to_server(req)
            else:
                # 拒绝接收
                req = {
                    "action": "file_accept",
                    "payload": {
                        "to": sender,  # 指定接收者为发送方
                        "file_id": file_id,
                        "accept": False
                    }
                }
                self.send_to_server(req)

            # --- 文件块接收 ---
        elif action == "file_chunk":
            file_id = payload.get("file_id")
            chunk_data_b64 = payload.get("chunk_data")
            sender = payload.get("from")

            if file_id in self.file_transfers and self.file_transfers[file_id]["status"] == "receiving":
                transfer = self.file_transfers[file_id]

                try:
                    # 获取会话密钥
                    session_key = self.session_keys.get(sender)
                    if not session_key:
                        raise Exception("没有会话密钥")

                    # 解密文件块
                    encrypted_chunk = base64.b64decode(chunk_data_b64)
                    chunk_data = c_utils.aes_decrypt(session_key, encrypted_chunk)

                    # 写入文件
                    transfer["file"].write(chunk_data)
                    transfer["received_size"] += len(chunk_data)

                    # 更新进度
                    progress = min(100, int(transfer["received_size"] * 100 / transfer["file_size"]))
                    self.update_progress(progress)

                except Exception as e:
                    self.display_message("System", f"接收文件块时出错: {e}", sender)
                    transfer["file"].close()
                    os.remove(transfer["save_path"])
                    self.hide_progress()
                    del self.file_transfers[file_id]

            # --- 文件传输接受响应 ---
        elif action == "file_accept":
            file_id = payload.get("file_id")
            accepted = payload.get("accept")
            from_user = payload.get("from")  # 接收方

            if file_id in self.file_transfers and self.file_transfers[file_id]["status"] == "request_sent":
                if accepted:
                    # 开始发送文件块
                    file_info = self.file_transfers[file_id]
                    threading.Thread(
                        target=self.send_file_chunks,
                        args=(
                            file_info["file_path"],
                            file_info["receiver"],
                            file_id,
                            file_info["session_key"]  # 添加这个参数
                        ),
                        daemon=True
                    ).start()

                    # 更新传输状态
                    self.file_transfers[file_id]["status"] = "sending"
                    self.show_progress(f"发送: {file_info['file_name']}", file_info["file_size"])
                else:
                    # 对方拒绝接收
                    self.display_message("System", f"{from_user} 拒绝了文件传输请求。", from_user)
                    del self.file_transfers[file_id]


        elif action == "file_end":

            file_id = payload.get("file_id")
            status = payload.get("status")
            from_user = payload.get("from")

            if file_id in self.file_transfers:
                transfer = self.file_transfers[file_id]

                if transfer["status"] == "receiving":
                    # 接收方处理结束
                    transfer["file"].close()

                    if status == "complete":
                        # 验证文件完整性
                        file_hash = self.calculate_file_hash(transfer["save_path"])
                        if file_hash == transfer["file_hash"]:
                            self.display_message("System", f"文件接收完成: {transfer['file_name']}", from_user)
                        else:
                            self.display_message("System", f"文件接收完成但校验失败: {transfer['file_name']}", from_user)
                    else:
                        self.display_message("System", f"文件传输失败: {transfer['file_name']}", from_user)
                        os.remove(transfer["save_path"])

                    self.hide_progress()
                    del self.file_transfers[file_id]

                elif transfer["status"] == "sending":
                    # 发送方处理结束
                    if status == "complete":
                        self.display_message("System", f"文件发送完成: {transfer['file_name']}", from_user)
                    else:
                        self.display_message("System", f"文件发送失败: {transfer['file_name']}", from_user)

                    self.hide_progress()
                    del self.file_transfers[file_id]

        # 处理缓存块响应
        elif action == "cached_chunk":
            self.process_file_chunk(payload)



        # 处理缓存结束通知
        elif action == "cached_chunks_end":
            file_id = payload.get("file_id")
            total_cached = payload.get("total_cached")
            chunk_count = payload.get("chunk_count")

            if file_id in self.file_transfers:
                if chunk_count > 0:
                    print(f"成功接收所有缓存块 ({chunk_count}个)")
                else:
                    print(f"无缓存块可接收")

                # 通知服务器准备接收实时块
                req = {
                    "action": "ready_for_realtime",
                    "payload": {
                        "file_id": file_id,
                        "receiver": self.username
                    }
                }
                self.send_to_server(req)

                # 更新状态为实时传输
                self.file_transfers[file_id]["status"] = "receiving_realtime"
                self.show_progress(f"实时接收: {self.file_transfers[file_id]['file_name']}")

    def process_message_recall(self, message_id, recalled_by):
        """处理消息撤回"""
        if message_id in self.received_messages:
            # 处理接收到的消息撤回
            msg_start, msg_end = self.received_messages[message_id]

            self.chat_box.config(state='normal')
            self.chat_box.delete(msg_start, msg_end)

            # 插入撤回提示
            recall_msg = f"[系统] {recalled_by} 撤回了一条消息\n"
            self.chat_box.insert(msg_start, recall_msg, "recall")

            # 更新历史记录
            if self.current_chat_partner in self.chat_history:
                # 替换原来的消息为撤回提示
                self.chat_history[self.current_chat_partner] = self.chat_history[self.current_chat_partner].replace(
                    self.chat_box.get(msg_start, msg_end), recall_msg
                )

            self.chat_box.config(state='disabled')
            self.chat_box.yview(tk.END)

            # 从接收消息记录中移除
            del self.received_messages[message_id]

        elif message_id in self.sent_messages:
            # 处理自己发送的消息撤回
            friend, msg_type, msg_start = self.sent_messages[message_id]

            if friend != self.current_chat_partner:
                # 如果当前聊天对象不是消息接收方，不需要更新UI
                del self.sent_messages[message_id]
                return

            # 找到消息结束位置
            msg_end = f"{msg_start} lineend +1l"

            self.chat_box.config(state='normal')
            self.chat_box.delete(msg_start, msg_end)

            # 插入撤回提示
            recall_msg = f"[系统] 你撤回了一条消息\n"
            self.chat_box.insert(msg_start, recall_msg, "recall")

            # 更新历史记录
            if self.current_chat_partner in self.chat_history:
                # 替换原来的消息为撤回提示
                self.chat_history[self.current_chat_partner] = self.chat_history[self.current_chat_partner].replace(
                    self.chat_box.get(msg_start, msg_end), recall_msg
                )

            self.chat_box.config(state='disabled')
            self.chat_box.yview(tk.END)

            # 从发送消息记录中移除
            del self.sent_messages[message_id]

    def add_unread_message(self, sender, message, message_id):
        """添加未读文本消息"""
        if sender not in self.unread_messages:
            self.unread_messages[sender] = []

        self.unread_messages[sender].append({
            "type": "text",
            "content": message,
            "timestamp": time.time(),
            "message_id": message_id  # 新增：存储消息ID
        })

        # 更新好友列表提示
        self.update_friend_indicator(sender)

        # 显示系统通知
        self.display_message("System", f"收到来自 {sender} 的新消息", sender)

    def add_unread_image(self, sender, image_source, hidden_message, message_id):
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
                "timestamp": time.time(),
                "message_id": message_id  # 新增：存储消息ID
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
                "timestamp": time.time(),
                "message_id": message_id  # 新增：存储消息ID
            })

        # 更新好友列表提示
        self.update_friend_indicator(sender)

        # 显示系统通知
        self.display_message("System", f"收到来自 {sender} 的图片消息", sender)

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
        # 保存当前聊天框内容到当前好友的历史记录
        if self.current_chat_partner:
            self.chat_box.config(state='normal')
            content = self.chat_box.get(1.0, tk.END)
            self.chat_history[self.current_chat_partner] = content
            self.chat_box.config(state='disabled')

        # 设置新的聊天好友
        self.current_chat_partner = friend_name
        self.chat_partner_label.config(text=f"与 {friend_name} 聊天中")

        # 恢复新的聊天好友的历史记录
        self.chat_box.config(state='normal')
        self.chat_box.delete(1.0, tk.END)
        if friend_name in self.chat_history:
            self.chat_box.insert(tk.END, self.chat_history[friend_name])
        self.chat_box.config(state='disabled')
        self.chat_box.yview(tk.END)  # 滚动到底部

        # 显示所有未读消息
        if friend_name in self.unread_messages and self.unread_messages[friend_name]:
            self.display_message("System", f"显示来自 {friend_name} 的未读消息:", friend_name)

            for msg in self.unread_messages[friend_name]:
                if msg["type"] == "text":
                    self.display_message(friend_name, msg["content"], friend_name, msg.get("message_id"))
                elif msg["type"] == "image_path":
                    self.display_image_message(friend_name, msg["path"], f"隐藏消息: {msg['hidden_message']}",
                                               friend_name, msg.get("message_id"))
                elif msg["type"] == "image_data":
                    img = Image.open(io.BytesIO(msg["data"]))
                    self.display_image_message(friend_name, img, f"隐藏消息: {msg['hidden_message']}", friend_name,
                                               msg.get("message_id"))

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
            self.display_message("System", f"正在向 {friend_name} 发起安全连接请求...", friend_name)
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

        # 新增：生成唯一消息ID
        message_id = f"msg_{uuid.uuid4().hex}"

        req = {
            "action": "forward_message",
            "payload": {
                "to": self.current_chat_partner,
                "type": "text",
                "content": encrypted_msg_b64,
                "message_id": message_id  # 新增：包含消息ID
            }
        }
        self.send_to_server(req)

        # 记录消息位置
        self.chat_box.config(state='normal')
        msg_start = self.chat_box.index(tk.INSERT)
        self.display_message(self.username, msg_content, self.current_chat_partner, message_id)  # 在自己的窗口显示明文
        msg_end = self.chat_box.index(tk.INSERT)
        self.chat_box.config(state='disabled')

        # 存储已发送消息
        self.sent_messages[message_id] = (self.current_chat_partner, "text", msg_start)

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

            # 新增：生成唯一消息ID
            message_id = f"msg_{uuid.uuid4().hex}"

            # 3. 发送
            req = {
                "action": "forward_message",
                "payload": {
                    "to": self.current_chat_partner,
                    "type": "steganography",
                    "content": encrypted_image_data_b64,
                    "message_id": message_id  # 新增：包含消息ID
                }
            }
            self.send_to_server(req)

            # 4. 在发送方显示图片和隐藏信息
            self.chat_box.config(state='normal')
            msg_start = self.chat_box.index(tk.INSERT)
            self.display_image_message(self.username, image_with_hidden_msg, f"已发送图片，隐藏消息: {secret_message}",
                                       self.current_chat_partner, message_id)
            msg_end = self.chat_box.index(tk.INSERT)
            self.chat_box.config(state='disabled')

            # 存储已发送消息
            self.sent_messages[message_id] = (self.current_chat_partner, "image", msg_start)

        except Exception as e:
            messagebox.showerror("错误", f"处理图片失败: {e}")

    def display_message(self, sender, message, partner, message_id=None):
        """在聊天框中显示文本消息"""
        # 确保聊天框已创建
        if hasattr(self, 'chat_box') and self.chat_box:
            self.chat_box.config(state='normal')

            # 记录消息开始位置
            start_index = self.chat_box.index(tk.INSERT)

            # 插入消息，添加消息ID标签
            if message_id:
                self.chat_box.insert(tk.END, f"[{sender}]: {message}\n", (f"msg_{message_id}",))
            else:
                self.chat_box.insert(tk.END, f"[{sender}]: {message}\n")

            # 记录消息结束位置
            end_index = self.chat_box.index(tk.INSERT)

            self.chat_box.config(state='disabled')
            self.chat_box.yview(tk.END)

            # 添加到聊天历史记录
            if partner not in self.chat_history:
                self.chat_history[partner] = ""
            self.chat_history[partner] += f"[{sender}]: {message}\n"

            # 如果是接收的消息，存储位置信息
            if sender != self.username and message_id:
                self.received_messages[message_id] = (start_index, end_index)

    def display_image_message(self, sender, image_source, message, partner, message_id=None):
        """
        在聊天框中显示图片消息
        image_source 可以是文件路径或 PIL.Image 对象
        """
        # 确保聊天框已创建
        if hasattr(self, 'chat_box') and self.chat_box:
            try:
                self.chat_box.config(state='normal')

                # 记录消息开始位置
                start_index = self.chat_box.index(tk.INSERT)

                # 插入发送者标签
                if message_id:
                    self.chat_box.insert(tk.END, f"[{sender}]:\n", (f"msg_{message_id}",))
                else:
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

                # 记录消息结束位置
                end_index = self.chat_box.index(tk.INSERT)

                self.chat_box.config(state='disabled')
                self.chat_box.yview(tk.END)

                # 添加到聊天历史记录
                if partner not in self.chat_history:
                    self.chat_history[partner] = ""
                self.chat_history[partner] += f"[{sender}]: [图片消息] {message}\n"

                # 如果是接收的消息，存储位置信息
                if sender != self.username and message_id:
                    self.received_messages[message_id] = (start_index, end_index)
            except Exception as e:
                print(f"显示图片消息时出错: {e}")
                self.display_message(sender, "无法显示图片", partner)

    def send_file(self):
        """发送文件"""
        if not self.current_chat_partner:
            messagebox.showerror("错误", "请先选择一个聊天好友。")
            return

        session_key = self.session_keys.get(self.current_chat_partner)
        if not session_key:
            messagebox.showerror("错误", "尚未与该用户建立安全连接。")
            return

        filepath = filedialog.askopenfilename(title="选择要发送的文件")
        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        # 计算文件哈希用于完整性验证
        file_hash = self.calculate_file_hash(filepath)

        # 生成唯一文件ID
        file_id = f"{self.username}_{int(time.time())}"

        # 发送文件请求
        req = {
            "action": "file_request",
            "payload": {
                "to": self.current_chat_partner,
                "file_id": file_id,
                "file_name": filename,
                "file_size": filesize,
                "file_hash": file_hash
            }
        }
        self.send_to_server(req)

        # 存储文件传输信息，等待接收方响应
        self.file_transfers[file_id] = {
            "status": "request_sent",
            "file_path": filepath,
            "file_name": filename,
            "file_size": filesize,
            "receiver": self.current_chat_partner,
            "session_key": session_key  # 存储会话密钥
        }

        self.display_message("System", f"已向 {self.current_chat_partner} 发送文件传输请求: {filename}",
                             self.current_chat_partner)

        # 显示进度条（但实际传输会在接收方确认后开始）
        self.show_progress(f"等待 {self.current_chat_partner} 确认...", filesize)

    def send_file_chunks(self, filepath, receiver, file_id, session_key):
        """分块发送文件内容"""
        CHUNK_SIZE = 65536  # 64KB每块
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE


        try:
            # 获取会话密钥
            session_key = self.session_keys.get(receiver)
            if not session_key:
                raise Exception("尚未与该用户建立安全连接")

            with open(filepath, 'rb') as f:
                for chunk_index in range(total_chunks):
                    chunk = f.read(CHUNK_SIZE)

                    # 加密文件块
                    encrypted_chunk = c_utils.aes_encrypt(session_key, chunk)
                    encrypted_chunk_b64 = base64.b64encode(encrypted_chunk).decode('utf-8')

                    # 发送文件块
                    req = {
                        "action": "file_chunk",
                        "payload": {
                            "to": receiver,
                            "file_id": file_id,
                            "chunk_data": encrypted_chunk_b64
                        }
                    }
                    self.send_to_server(req)

                    # 实时更新进度
                    progress = min(100, int((chunk_index + 1) * 100 / total_chunks))
                    self.update_progress(progress)

                    # 小延迟避免阻塞
                    time.sleep(0.01)

            # 发送文件结束标志
            req = {
                "action": "file_end",
                "payload": {
                    "to": receiver,
                    "file_id": file_id,
                    "status": "complete",
                    "file_size": filesize
                }
            }
            self.send_to_server(req)

            self.display_message("System", f"文件 {filename} 发送完成", receiver)

        except Exception as e:
            # 发送失败通知
            req = {
                "action": "file_end",
                "payload": {
                    "to": receiver,
                    "file_id": file_id,
                    "status": "failed"
                }
            }
            self.send_to_server(req)

            self.after(0, lambda: messagebox.showerror("错误", f"发送文件失败: {e}"))
            self.hide_progress()

    def process_file_chunk(self, payload):
        """处理文件块，考虑传输状态"""
        file_id = payload["file_id"]
        chunk_data = payload["chunk_data"]

        # 如果传输尚未初始化，缓冲块
        if file_id not in self.file_transfers:
            if file_id not in self.pending_file_chunks:
                self.pending_file_chunks[file_id] = []
            self.pending_file_chunks[file_id].append(chunk_data)
            return

        # 正常处理块
        transfer = self.file_transfers[file_id]

    def calculate_file_hash(self, filepath):
        """计算文件的SHA256哈希"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

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