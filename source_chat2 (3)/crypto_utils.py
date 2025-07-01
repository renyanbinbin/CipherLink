# crypto_utils.py

import os
from PIL import Image

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# --- RSA (非对称) 功能 ---

def generate_rsa_keys():
    """生成2048位的RSA密钥对"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """将公钥对象序列化为PEM格式的字符串"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def serialize_private_key(private_key):
    """将私钥对象序列化为PEM格式的字符串 (不加密)"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def load_public_key(pem_data):
    """从PEM格式的字符串加载公钥对象"""
    return serialization.load_pem_public_key(pem_data.encode('utf-8'), backend=default_backend())


def load_private_key(pem_data):
    """从PEM格式的字符串加载私钥对象"""
    return serialization.load_pem_private_key(pem_data.encode('utf-8'), password=None, backend=default_backend())


def rsa_encrypt(public_key, data):
    """使用公钥加密数据 (用于加密会话密钥)"""
    return public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, encrypted_data):
    """使用私钥解密数据"""
    return private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# --- AES (对称) 功能 ---

def generate_aes_key():
    """生成一个256位的AES密钥 (32字节)"""
    return os.urandom(32)


def aes_encrypt(key, plaintext):
    """使用AES-CBC模式加密明文"""
    iv = os.urandom(16)  # 128位的IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # 将IV和密文连接在一起


def aes_decrypt(key, iv_and_ciphertext):
    """使用AES-CBC模式解密"""
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# --- 信息隐藏 (Steganography) 功能 ---

def text_to_binary(text):
    """将文本字符串转换为二进制字符串"""
    return ''.join(format(ord(i), '08b') for i in text)


def binary_to_text(binary):
    """将二进制字符串转换回文本"""
    # 确保长度是8的倍数
    if len(binary) % 8 != 0:
        binary = binary[:-(len(binary) % 8)]

    return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))


def hide_message_in_image(image_path, secret_message):
    """将秘密信息隐藏到图片中"""
    img = Image.open(image_path).convert('RGB')

    # 添加一个独特的结束标记
    secret_message += "<-END->"
    binary_message = text_to_binary(secret_message)

    if len(binary_message) > img.width * img.height * 3:
        raise ValueError("错误：秘密信息对于所选图片来说太长了。")

    data_index = 0
    pixels = img.load()

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]

            # 修改R通道
            if data_index < len(binary_message):
                r = r & ~1 | int(binary_message[data_index])
                data_index += 1
            # 修改G通道
            if data_index < len(binary_message):
                g = g & ~1 | int(binary_message[data_index])
                data_index += 1
            # 修改B通道
            if data_index < len(binary_message):
                b = b & ~1 | int(binary_message[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

            if data_index >= len(binary_message):
                return img  # 返回修改后的Image对象

    return img


def extract_message_from_image(image_with_message):
    """从图片中提取隐藏的信息"""
    # 如果传入的是路径，则打开；如果是Image对象，则直接使用
    if isinstance(image_with_message, str):
        img = Image.open(image_with_message).convert('RGB')
    else:
        img = image_with_message.convert('RGB')

    binary_data = ""
    pixels = img.load()

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)

    message = binary_to_text(binary_data)

    # 查找结束标记
    end_marker = "<-END->"
    if end_marker in message:
        return message.split(end_marker)[0]
    else:
        return "未能在图片中找到隐藏信息或结束标记。"