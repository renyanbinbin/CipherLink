# server.py

import socket
import threading
import json
import hashlib

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


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] 服务器正在监听 {HOST}:{PORT}")

    while True:
        client_socket, address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
        client_handler.daemon = True
        client_handler.start()


if __name__ == "__main__":
    main()