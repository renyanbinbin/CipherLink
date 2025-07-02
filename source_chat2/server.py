import socket
import threading
import json
import hashlib
import time
import uuid
from collections import defaultdict

HOST = '0.0.0.0'  # 监听所有网络接口
PORT = 8888

# 使用锁来保证线程安全
users_lock = threading.Lock()
online_users_lock = threading.Lock()

# 简单的内存数据库
# users_db = {
#   "username": {
#       "password_hash": "...",
#       "email": "...",
#       "public_key": "...",
#       "friends": ["friend1", "friend2"]   # 新增好友列表
#   }
# }
users_db = {}
# online_users = { "username": client_socket }
online_users = {}
# 存储待处理的好友请求 {receiver: {sender: status}}，status: pending, accepted, rejected
friend_requests = {}
# 新增：存储消息记录 {message_id: (sender, receiver, timestamp)}
message_store = {}


def broadcast_online_list():
    """向所有在线用户广播更新后的在线列表"""
    with online_users_lock:
        online_usernames = list(online_users.keys())
        response = {
            "action": "update_online_list",
            "payload": online_usernames
        }
        for user, sock in online_users.items():
            try:
                sock.sendall((json.dumps(response) + '\n').encode('utf-8'))
            except Exception as e:
                print(f"[广播错误] 发送给 {user} 失败: {e}")


def notify_friend_request(sender, receiver, action, status=None):
    """通知用户好友请求"""
    with online_users_lock:
        receiver_socket = online_users.get(receiver)
        if receiver_socket:
            response = {
                "action": "friend_request",
                "payload": {
                    "sender": sender,
                    "action": action,
                    "status": status
                }
            }
            try:
                receiver_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
            except Exception as e:
                print(f"[好友请求通知错误] 发送给 {receiver} 失败: {e}")


def notify_friend_update(username, friend, action):
    """通知用户好友列表更新"""
    with online_users_lock:
        user_socket = online_users.get(username)
        if user_socket:
            response = {
                "action": "friend_update",
                "payload": {
                    "friend": friend,
                    "action": action  # "add" 或 "remove"
                }
            }
            try:
                user_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
            except Exception as e:
                print(f"[好友更新通知错误] 发送给 {username} 失败: {e}")


def notify_message_recall(message_id, recalled_by, receiver):
    """通知用户消息被撤回"""
    with online_users_lock:
        receiver_socket = online_users.get(receiver)
        if receiver_socket:
            response = {
                "action": "message_recalled",
                "payload": {
                    "message_id": message_id,
                    "recalled_by": recalled_by
                }
            }
            try:
                receiver_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
            except Exception as e:
                print(f"[撤回通知错误] 发送给 {receiver} 失败: {e}")


def add_friend_to_db(sender, receiver):
    """将双方添加为好友"""
    with users_lock:
        # 添加sender到receiver的好友列表
        if sender not in users_db[receiver]["friends"]:
            users_db[receiver]["friends"].append(sender)

        # 添加receiver到sender的好友列表
        if receiver not in users_db[sender]["friends"]:
            users_db[sender]["friends"].append(receiver)

        # 移除待处理的请求
        if receiver in friend_requests and sender in friend_requests[receiver]:
            del friend_requests[receiver][sender]
            if not friend_requests[receiver]:  # 如果没有其他请求，移除空字典
                del friend_requests[receiver]

        # 通知双方更新好友列表
        notify_friend_update(sender, receiver, "add")
        notify_friend_update(receiver, sender, "add")

        # 通知双方好友请求已接受
        notify_friend_request(sender, receiver, "add", "accepted")
        notify_friend_request(receiver, sender, "add", "accepted")


def remove_friend_from_db(user1, user2):
    """从双方好友列表中移除对方"""
    with users_lock:
        # 从user1的好友列表中移除user2
        if user2 in users_db[user1]["friends"]:
            users_db[user1]["friends"].remove(user2)

        # 从user2的好友列表中移除user1
        if user1 in users_db[user2]["friends"]:
            users_db[user2]["friends"].remove(user1)

        # 通知双方更新好友列表
        notify_friend_update(user1, user2, "remove")
        notify_friend_update(user2, user1, "remove")

        # 通知双方已被移除
        notify_friend_request(user1, user2, "remove", "removed")
        notify_friend_request(user2, user1, "remove", "removed")


def cleanup_message_store():
    """定期清理过期的消息记录"""
    while True:
        time.sleep(300)  # 每5分钟清理一次
        current_time = time.time()
        expired_ids = []

        # 找出超过2分钟的消息
        for msg_id, (_, _, timestamp) in message_store.items():
            if current_time - timestamp > 120:  # 2分钟
                expired_ids.append(msg_id)

        # 删除过期消息
        for msg_id in expired_ids:
            del message_store[msg_id]
            print(f"[清理] 已删除过期消息: {msg_id}")

pending_file_data = {}  # 存储等待传输的文件数据
# 全局字典，用于管理实时文件传输的接收方
file_realtime_receivers = {}

# 全局缓存字典
file_chunk_cache = defaultdict(lambda: defaultdict(list))

def handle_client(client_socket, address):
    """处理单个客户端连接的线程函数"""
    print(f"[新连接] {address} 已连接。")
    current_user = None
    try:
        # 使用文件流的方式读取数据，防止粘包
        client_file = client_socket.makefile('r')
        for line in client_file:
            request = json.loads(line)
            action = request.get("action")
            payload = request.get("payload", {})

            # 会话验证 - 要求登录的操作
            if action not in ["register", "login"] and not current_user:
                response = {"status": "error", "message": "请先登录"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                continue

            # --- 注册 ---
            if action == "register":
                username = payload.get("username")
                password = payload.get("password")
                email = payload.get("email")
                public_key = payload.get("public_key")

                with users_lock:
                    if username in users_db:
                        response = {"status": "error", "message": "用户名已存在"}
                    else:
                        # 存储密码的哈希值
                        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                        users_db[username] = {
                            "password_hash": password_hash,
                            "email": email,
                            "public_key": public_key,
                            "friends": []  # 初始化好友列表为空
                        }
                        response = {"status": "ok", "message": "注册成功"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 登录 ---
            elif action == "login":
                username = payload.get("username")
                password = payload.get("password")

                with users_lock:
                    user_data = users_db.get(username)
                    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

                if user_data and user_data["password_hash"] == password_hash:
                    with online_users_lock:
                        online_users[username] = client_socket
                    current_user = username

                    # 发送登录成功响应
                    response = {
                        "status": "ok",
                        "message": "登录成功",
                        "friends": user_data.get("friends", [])  # 返回好友列表
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    print(f"[登录] 用户 '{username}' 登录成功。")
                    broadcast_online_list()  # 通知所有人更新列表

                    # 发送等待的文件
                    send_pending_files(username, client_socket)
                else:
                    response = {"status": "error", "message": "用户名或密码错误"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 获取公钥 ---
            elif action == "get_public_key":
                target_user = payload.get("username")
                with users_lock:
                    target_data = users_db.get(target_user)

                if target_data:
                    response = {"status": "ok", "username": target_user, "public_key": target_data["public_key"]}
                else:
                    response = {"status": "error", "message": "用户不存在"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 消息转发 (P2P中继) ---
            # 服务器只负责转发，无法解密内容
            elif action == "forward_message":
                to_user = payload.get("to")

                # +++ 新增：验证是否为好友 +++
                is_friend = False
                with users_lock:
                    # 检查发送方和接收方是否互为好友
                    if current_user in users_db and to_user in users_db:
                        # 检查双方是否在彼此的好友列表中
                        if (current_user in users_db[to_user]["friends"] and
                                to_user in users_db[current_user]["friends"]):
                            is_friend = True

                if not is_friend:
                    # 如果不是好友，返回错误
                    response = {
                        "status": "error",
                        "message": f"无法发送消息：您和 {to_user} 不是好友关系"
                    }
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue
                # +++ 好友验证结束 +++

                # 新增：存储消息记录
                message_id = payload.get("message_id")
                if message_id:
                    message_store[message_id] = (current_user, to_user, time.time())

                with online_users_lock:
                    target_socket = online_users.get(to_user)

                if target_socket:
                    # 在载荷中加入发送方信息
                    payload["from"] = current_user
                    forward_req = {"action": "receive_message", "payload": payload}
                    target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))
                else:
                    # 如果对方不在线，可以发送错误回报
                    response = {"status": "error", "message": f"用户 '{to_user}' 不在线。"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 新增：撤回消息 ---
            elif action == "recall_message":
                message_id = payload.get("message_id")
                to_user = payload.get("to")

                # 验证消息是否存在且属于当前用户
                if message_id not in message_store:
                    response = {"status": "error", "message": "消息不存在或已过期"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                sender, receiver, timestamp = message_store[message_id]

                if sender != current_user:
                    response = {"status": "error", "message": "无权撤回该消息"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                # 检查消息是否超过2分钟
                if time.time() - timestamp > 120:  # 2分钟
                    response = {"status": "error", "message": "消息已超过可撤回时间"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                # 通知接收方消息已被撤回
                notify_message_recall(message_id, current_user, receiver)

                # 从消息存储中删除
                del message_store[message_id]

                response = {"status": "ok", "message": "消息已撤回"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 添加好友 ---
            elif action == "add_friend":
                friend_name = payload.get("friend")

                with users_lock:
                    # 检查好友是否存在
                    if friend_name not in users_db:
                        response = {"status": "error", "message": f"用户 '{friend_name}' 不存在。"}
                        client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                        continue

                    # 检查是否已经是好友
                    if friend_name in users_db[current_user]["friends"]:
                        response = {"status": "error", "message": f"'{friend_name}' 已经是您的好友。"}
                        client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                        continue

                    # 检查是否已有待处理的请求
                    if friend_name in friend_requests and current_user in friend_requests[friend_name]:
                        status = friend_requests[friend_name][current_user]
                        if status == "pending":
                            response = {"status": "error",
                                        "message": f"您已向 '{friend_name}' 发送过好友请求，请等待对方处理。"}
                            client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                            continue

                # 添加好友请求到待处理列表
                if friend_name not in friend_requests:
                    friend_requests[friend_name] = {}
                friend_requests[friend_name][current_user] = "pending"

                # 发送好友请求通知
                notify_friend_request(current_user, friend_name, "request", "pending")

                response = {"status": "ok", "message": f"已向 '{friend_name}' 发送好友请求。"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 响应好友请求 ---
            elif action == "respond_friend_request":
                sender = payload.get("sender")
                accept = payload.get("accept")  # True or False

                # 验证请求是否存在
                if current_user not in friend_requests or sender not in friend_requests[current_user]:
                    response = {"status": "error", "message": "未找到该好友请求。"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                if accept:
                    # 双方互相添加为好友
                    add_friend_to_db(sender, current_user)
                    response = {"status": "ok", "message": f"已接受 '{sender}' 的好友请求。"}
                else:
                    # 拒绝请求
                    del friend_requests[current_user][sender]
                    if not friend_requests[current_user]:  # 如果没有其他请求，移除空字典
                        del friend_requests[current_user]

                    # 通知请求发起者
                    notify_friend_request(current_user, sender, "request", "rejected")
                    response = {"status": "ok", "message": f"已拒绝 '{sender}' 的好友请求。"}

                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 删除好友 ---
            elif action == "remove_friend":
                friend_name = payload.get("friend")

                with users_lock:
                    # 检查是否是好友
                    if friend_name not in users_db[current_user]["friends"]:
                        response = {"status": "error", "message": f"'{friend_name}' 不是您的好友。"}
                        client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                        continue

                # 从双方好友列表中移除
                remove_friend_from_db(current_user, friend_name)
                response = {"status": "ok", "message": f"已成功移除好友 '{friend_name}'。"}
                client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 文件传输请求 ---
            elif action == "file_request":
                to_user = payload.get("to")
                file_id = payload.get("file_id")
                file_name = payload.get("file_name")
                file_size = payload.get("file_size")
                file_hash = payload.get("file_hash")

                # 检查接收方是否在线
                with online_users_lock:
                    target_socket = online_users.get(to_user)

                if target_socket:
                    # 添加发送方信息
                    payload["from"] = current_user
                    forward_req = {"action": "file_request", "payload": payload}
                    target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))
                else:
                    response = {"status": "error", "message": f"用户 '{to_user}' 不在线。"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 文件元数据（开始传输）---
            elif action == "file_start":
                # 确保所有必要字段存在
                if not all(key in payload for key in ["to", "file_id", "file_name", "file_size", "file_hash"]):
                    response = {"status": "error", "message": "文件元数据不完整"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                to_user = payload.get("to")

                with online_users_lock:
                    target_socket = online_users.get(to_user)

                if target_socket:
                    # 添加发送方信息
                    payload["from"] = current_user
                    forward_req = {"action": "file_start", "payload": payload}
                    target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))
                else:
                    # 如果对方不在线，存储文件元数据而不是直接丢弃
                    store_file_metadata(to_user, payload)
                    response = {"status": "error", "message": f"用户 '{to_user}' 不在线。文件已存储，将在其上线时通知。"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # --- 文件块传输 ---
            elif action == "file_chunk":
                # 确保所有必要字段存在
                if not all(key in payload for key in ["to", "file_id", "chunk_data"]):
                    print("文件块数据不完整")
                    continue

                to_user = payload.get("to")
                file_id = payload.get("file_id")
                chunk_data = payload.get("chunk_data")

                # 获取接收方的socket
                with online_users_lock:
                    target_socket = online_users.get(to_user)

                # 如果接收方在线，立即转发
                if target_socket:
                    try:
                        # 添加发送方信息
                        payload["from"] = current_user
                        forward_req = {"action": "file_chunk", "payload": payload}
                        target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))
                        print(f"转发文件块 {file_id} 给 {to_user}，块大小: {len(chunk_data)}")
                    except Exception as e:
                        print(f"转发文件块给 {to_user} 失败: {e}")
                        # 转发失败则存储
                        store_pending_chunk(to_user, file_id, chunk_data)
                else:
                    # 接收方不在线，存储为待处理
                    store_pending_chunk(to_user, file_id, chunk_data)

            # --- 文件传输接受响应 ---
            elif action == "file_accept":
                to_user = payload.get("to")  # 这里的to_user是原始发送方
                file_id = payload.get("file_id")
                accepted = payload.get("accept")

                # 检查发送方是否在线
                with online_users_lock:
                    target_socket = online_users.get(to_user)

                if target_socket:
                    # 添加接收方信息
                    payload["from"] = current_user
                    forward_req = {"action": "file_accept", "payload": payload}
                    target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))
                else:
                    response = {"status": "error", "message": f"用户 '{to_user}' 不在线。"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))


                # --- 文件传输结束 ---
            elif action == "file_end":
                # 确保所有必要字段存在
                if not all(key in payload for key in ["to", "file_id", "status"]):
                    response = {"status": "error", "message": "文件结束信息不完整"}
                    client_socket.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    continue

                to_user = payload.get("to")

                # 如果接收方在线，尝试转发
                with online_users_lock:
                    target_socket = online_users.get(to_user)
                if target_socket:
                    # 添加发送方信息
                    payload["from"] = current_user
                    forward_req = {"action": "file_end", "payload": payload}
                    target_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))


            # 缓存块请求处理

            elif action == "request_cached_chunks":

                file_id = payload.get("file_id")

                receiver = payload.get("receiver")

                print(f"收到来自 {receiver} 的缓存块请求，文件ID: {file_id}")

                # 检查是否有缓存块

                if receiver in file_chunk_cache and file_id in file_chunk_cache[receiver]:

                    chunks = file_chunk_cache[receiver][file_id]

                    chunk_count = len(chunks)

                    print(f"准备向 {receiver} 发送 {chunk_count} 个缓存块")

                    # 发送所有缓存块

                    for i, chunk in enumerate(chunks):
                        req = {

                            "action": "cached_chunk",

                            "payload": {

                                "to": receiver,

                                "file_id": file_id,

                                "chunk_data": chunk,

                                "chunk_index": i + 1,  # 索引从1开始

                                "total_chunks": chunk_count

                            }

                        }

                        client_socket.sendall((json.dumps(req) + '\n').encode('utf-8'))

                    # 发送缓存结束通知

                    req = {

                        "action": "cached_chunks_end",

                        "payload": {

                            "file_id": file_id,

                            "chunk_count": chunk_count

                        }

                    }

                    client_socket.sendall((json.dumps(req) + '\n').encode('utf-8'))

                    # 清理缓存

                    del file_chunk_cache[receiver][file_id]

                    print(f"已向 {receiver} 发送所有缓存块并清除缓存")

                else:

                    print(f"接收方 {receiver} 无缓存块")

                    # 没有缓存块时也发送结束通知

                    req = {

                        "action": "cached_chunks_end",

                        "payload": {

                            "file_id": file_id,

                            "chunk_count": 0

                        }

                    }

                    client_socket.sendall((json.dumps(req) + '\n').encode('utf-8'))


            # 接收方准备就绪处理

            elif action == "ready_for_realtime":

                file_id = payload.get("file_id")

                receiver = payload.get("receiver")

                # 设置实时传输标志

                if file_id not in file_realtime_receivers:
                    file_realtime_receivers[file_id] = []

                file_realtime_receivers[file_id].append(receiver)

                print(f"{receiver} 已准备好接收实时块，文件ID: {file_id}")


            # 文件块处理 (更新部分)

            elif action == "file_chunk":

                to_user = payload.get("to")

                file_id = payload.get("file_id")

                chunk_data = payload.get("chunk_data")

                # 首先检查是否有缓存块需要存储

                # ...（原有逻辑，但命名改成file_chunk_cache）...

                # 然后检查是否有实时接收方需要转发

                if file_id in file_realtime_receivers:

                    for receiver in file_realtime_receivers[file_id]:

                        if receiver in online_users:

                            try:

                                # 转发给实时接收方

                                forward_req = {

                                    "action": "file_chunk",

                                    "payload": {

                                        "to": receiver,

                                        "file_id": file_id,

                                        "chunk_data": chunk_data,

                                        "source": "realtime"

                                    }

                                }

                                online_users[receiver].sendall((json.dumps(forward_req) + '\n').encode('utf-8'))

                            except Exception as e:

                                print(f"转发实时块给 {receiver} 失败: {e}")
                    # 接收方不在线时，存储到统一缓存
                else:
                    store_pending_chunk(to_user, file_id, chunk_data)
                    print(f"存储文件块到缓存: {file_id} (接收方: {to_user})")

    except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError) as e:
        print(f"[连接错误] {address}: {e}")
    finally:
        if current_user:
            with online_users_lock:
                if current_user in online_users:
                    del online_users[current_user]
            print(f"[下线] 用户 '{current_user}' 已下线。")
            broadcast_online_list()  # 通知所有人更新列表

        client_socket.close()


# 在全局范围内定义存储待处理文件的字典
pending_files = {}


# 在 server.py 顶部添加全局存储
file_transfer_data = {}  # {file_id: {"metadata": {...}, "chunks": [...]}}

# 修改 store_file_metadata 函数
def store_file_metadata(receiver, metadata):
    file_id = metadata["file_id"]
    if receiver not in file_transfer_data:
        file_transfer_data[receiver] = {}
    if file_id not in file_transfer_data[receiver]:
        file_transfer_data[receiver][file_id] = {
            "metadata": metadata,
            "chunks": []  # 存储所有文件块
        }

# 修改 send_pending_files 函数
def send_pending_files(username, client_socket):
    """当用户上线时发送所有等待的文件"""
    if username in pending_file_data:
        for file_id, file_data in pending_file_data[username].items():
            # 发送文件元数据
            metadata = file_data["metadata"]
            forward_req = {"action": "file_start", "payload": metadata}
            client_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))

            # 发送所有文件块
            for chunk in file_data["chunks"]:
                chunk_payload = {
                    "to": username,
                    "file_id": file_id,
                    "chunk_data": chunk,
                    "from": metadata["from"]  # 保留原始发送者
                }
                forward_req = {"action": "file_chunk", "payload": chunk_payload}
                client_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))

            # 如果收到了结束标志，发送它
            if file_data.get("end_received", False):
                end_payload = file_data["end_data"]
                end_payload["to"] = username
                forward_req = {"action": "file_end", "payload": end_payload}
                client_socket.sendall((json.dumps(forward_req) + '\n').encode('utf-8'))

        # 清理已发送的文件
        del pending_file_data[username]

# 全局缓存字典
cached_chunks = defaultdict(lambda: defaultdict(list))

pending_file_chunks = defaultdict(lambda: defaultdict(list))


def store_pending_chunk(receiver, file_id, chunk_data):
    """存储待处理的文件块到统一缓存"""
    # 同时存储到两种结构中确保兼容性
    pending_file_chunks[receiver][file_id].append(chunk_data)
    file_chunk_cache[receiver][file_id].append(chunk_data)


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] 服务器正在监听 {HOST}:{PORT}")

    # 启动消息清理线程
    cleanup_thread = threading.Thread(target=cleanup_message_store, daemon=True)
    cleanup_thread.start()

    while True:
        client_socket, address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
        client_handler.daemon = True
        client_handler.start()


if __name__ == "__main__":
    main()