import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from androguard.core.apk import APK
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

import jks
import json
import os

# 加载语言配置文件
import sys


def load_language(lang_code):
    lang_file = f"lang_{lang_code}.json"

    # 如果是打包后的环境
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS  # 获取临时解压目录
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))  # 开发环境

    lang_path = os.path.join(base_path, lang_file)

    if os.path.exists(lang_path):
        with open(lang_path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        raise FileNotFoundError(f"Language file {lang_path} not found.")


# 全局变量，用于存储当前语言
current_lang = "en"  # 默认语言为英语
lang_texts = load_language(current_lang)

# 全局变量，用于存储用户输入的密码
password = None
root = None


def copy_to_clipboard(text):
    """
    将文本复制到剪贴板。
    """
    root.clipboard_clear()  # 清空剪贴板
    if checkbox_var.get() == 1:
        modified_text = text.replace(':', '')  # 替换冒号为空字符串
        root.clipboard_append(modified_text)  # 添加修改后的文本到剪贴板
    else:
        root.clipboard_append(text)  # 添加原始文本到剪贴板
    root.update()  # 更新剪贴板内容

def get_certificate_fingerprint(cert, algorithm="sha256"):
    """
    计算证书的指纹（MD5、SHA1 或 SHA256）。
    """
    if algorithm == "md5":
        hash_algorithm = hashes.MD5()
    elif algorithm == "sha1":
        hash_algorithm = hashes.SHA1()
    elif algorithm == "sha256":
        hash_algorithm = hashes.SHA256()
    else:
        raise ValueError("Unsupported hash algorithm")

    # 计算指纹
    fingerprint = cert.fingerprint(hash_algorithm)
    return ":".join(f"{b:02X}" for b in fingerprint)


def get_rsa_public_key_details(public_key):
    """
    获取 RSA 公钥的详细信息。
    """
    # 提取模数和指数
    numbers = public_key.public_numbers()
    modulus = numbers.n
    exponent = numbers.e

    # 返回模数和指数
    details = "Public Key Type: RSA\n"
    details += f"    Modulus Size (bits): {public_key.key_size}\n"
    details += f"    Modulus: {modulus}\n"
    details += f"    Exponent: {exponent}\n"
    return details, modulus  # 返回模数


def get_certificate_details(cert):
    """
    获取证书的详细信息。
    """
    details = "Type: X.509\n"
    details += f"Version: {cert.version.name}\n"
    details += f"Serial Number: {hex(cert.serial_number)}\n"
    details += f"Subject: {cert.subject.rfc4514_string()}\n"
    details += f"Valid From (UTC): {cert.not_valid_before_utc}\n"
    details += f"Valid Until (UTC): {cert.not_valid_after_utc}\n"

    # 公钥信息
    public_key = cert.public_key()
    modulus = None
    if isinstance(public_key, rsa.RSAPublicKey):
        key_details, modulus = get_rsa_public_key_details(public_key)
        details += key_details
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        details += "Public Key Type: EC\n"
        details += f"    Curve: {public_key.curve.name}\n"
    else:
        details += "Public Key Type: Unknown\n"

    # 签名算法
    details += f"Signature Algorithm: {cert.signature_algorithm_oid._name}\n"

    # 证书指纹
    md5_fingerprint = get_certificate_fingerprint(cert, "md5")
    sha1_fingerprint = get_certificate_fingerprint(cert, "sha1")
    sha256_fingerprint = get_certificate_fingerprint(cert, "sha256")
    details += "Certificate Fingerprints:\n"
    details += f"    MD5: {md5_fingerprint}\n"
    details += f"    SHA1: {sha1_fingerprint}\n"
    details += f"    SHA256: {sha256_fingerprint}\n"

    return details, modulus, md5_fingerprint


def read_pkcs12_keystore(keystore_path, password, text_widget):
    """
    读取并解析 PKCS12 格式的密钥库文件。
    """
    try:
        with open(keystore_path, "rb") as f:
            pkcs12_data = f.read()

        # 解析 PKCS12 文件
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pkcs12_data, password.encode()
        )

        if not certificate:
            text_widget.insert(tk.END, "No certificate found in the keystore.\n")
            return None, None

        # 显示证书详细信息
        text_widget.insert(tk.END, "Certificate Information:\n")
        details, modulus, md5_fingerprint = get_certificate_details(certificate)
        text_widget.insert(tk.END, details)

        # 如果有附加证书，显示附加证书信息
        if additional_certificates:
            text_widget.insert(tk.END, "\nAdditional Certificates:\n")
            for idx, additional_cert in enumerate(additional_certificates):
                text_widget.insert(tk.END, f"Certificate {idx + 1}:\n")
                text_widget.insert(tk.END, get_certificate_details(additional_cert)[0])

        return modulus, md5_fingerprint

    except Exception as e:
        text_widget.insert(tk.END, f"Error reading PKCS12 keystore: {e}\n")
        messagebox.showerror("Error", f"Failed to read PKCS12 keystore: {e}")
        return None, None


def read_jks_keystore(keystore_path, password, text_widget):
    """
    读取并解析 JKS 格式的密钥库文件。
    """
    try:
        # 读取 JKS 文件
        keystore = jks.KeyStore.load(keystore_path, password)

        # 显示密钥库类型
        text_widget.insert(tk.END, f"Keystore Type: {keystore.store_type}\n")

        modulus = None
        md5_fingerprint = None

        # 遍历所有条目
        for alias, entry in keystore.entries.items():
            text_widget.insert(tk.END, f"\nAlias: {alias}\n")
            if isinstance(entry, jks.PrivateKeyEntry):
                text_widget.insert(tk.END, "Entry Type: Private Key Entry\n")
                text_widget.insert(tk.END, "Certificate Chain:\n")
                for cert in entry.cert_chain:
                    # 将 pyjks 的证书转换为 cryptography 的 x509.Certificate 对象
                    cert = x509.load_der_x509_certificate(cert[1])
                    details, mod, md5 = get_certificate_details(cert)
                    text_widget.insert(tk.END, details)
                    if mod is not None:
                        modulus = mod
                    if md5 is not None:
                        md5_fingerprint = md5
            elif isinstance(entry, jks.TrustedCertEntry):
                text_widget.insert(tk.END, "Entry Type: Trusted Certificate Entry\n")
                # 将 pyjks 的证书转换为 cryptography 的 x509.Certificate 对象
                cert = x509.load_der_x509_certificate(entry.cert)
                details, mod, md5 = get_certificate_details(cert)
                text_widget.insert(tk.END, details)
                if mod is not None:
                    modulus = mod
                if md5 is not None:
                    md5_fingerprint = md5
            else:
                text_widget.insert(tk.END, "Entry Type: Unknown\n")

        return modulus, md5_fingerprint

    except Exception as e:
        text_widget.insert(tk.END, f"Error reading JKS keystore: {e}\n")
        messagebox.showerror("Error", f"Failed to read JKS keystore: {e}")
        return None, None


def get_file_type(file_path):
    """
    通过魔数判断文件类型。
    """
    with open(file_path, "rb") as f:
        magic_number = f.read(8).hex().upper()
        if magic_number.startswith("FEEDFEED"):
            return "JKS"
        elif magic_number.startswith("3082"):
            return "PKCS12"
        else:
            return "Unknown"


def read_keystore(keystore_path, password, text_widget):
    """
    自动判断密钥库类型并读取内容。
    """
    file_type = get_file_type(keystore_path)
    if file_type == "PKCS12":
        text_widget.insert(tk.END, "Detected PKCS12 keystore.\n")
        return read_pkcs12_keystore(keystore_path, password, text_widget)
    elif file_type == "JKS":
        text_widget.insert(tk.END, "Detected JKS keystore.\n")
        return read_jks_keystore(keystore_path, password, text_widget)
    else:
        text_widget.insert(tk.END, "Unsupported keystore format.\n")
        return None, None


def custom_password_dialog(parent):
    dialog = tk.Toplevel(parent)
    dialog.title(lang_texts["password_dialog_title"])
    dialog.geometry("400x150")

    parent_x = parent.winfo_x()
    parent_y = parent.winfo_y()
    parent_width = parent.winfo_width()
    parent_height = parent.winfo_height()

    dialog_width = 400
    dialog_height = 150

    x = parent_x + (parent_width - dialog_width) // 2
    y = parent_y + (parent_height - dialog_height) // 2

    dialog.geometry(f"+{x}+{y}")

    label = tk.Label(dialog, text=lang_texts["password_label"])
    label.pack(pady=10)

    entry = tk.Entry(dialog, show="*", width=40)
    entry.insert(0, "***")
    entry.pack(pady=10)

    def on_ok():
        global password
        password = entry.get()
        dialog.destroy()

    ok_button = tk.Button(dialog, text=lang_texts["ok_button"], command=on_ok)
    ok_button.pack(pady=10)

    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)


def open_file(text_widget):
    """
    打开文件对话框并读取密钥库文件或APK文件。
    支持 .jks, .p12, .pfx 和 .apk 文件类型。
    """
    file_path = filedialog.askopenfilename(
        title=lang_texts["open_button"],
        filetypes=[
            ("Keystore and APK Files", "*.jks *.p12 *.pfx *.apk"),
            ("Keystore Files", "*.jks *.p12 *.pfx"),
            ("APK Files", "*.apk"),
            ("All Files", "*.*")
        ]
    )

    if file_path:  # 确保用户选择了文件
        file_extension = os.path.splitext(file_path.lower())[1]  # 获取文件扩展名并转为小写
        if file_extension == '.apk':
            # APK 文件处理逻辑
            try:
                text_widget.delete(1.0, tk.END)  # 清空文本框
                modulus, md5_fingerprint = get_certificate_info(file_path, text_widget)
                if modulus:
                    copy_modulus_button.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(str(modulus)))
                if md5_fingerprint:
                    copy_md5_button.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(md5_fingerprint))
            except Exception as e:
                text_widget.insert(tk.END, f"Error processing APK file: {str(e)}\n")
        else:
            custom_password_dialog(root)
            if password:
                text_widget.delete(1.0, tk.END)  # 清空文本框
                modulus, md5_fingerprint = read_keystore(file_path, password, text_widget)
                if modulus:
                    copy_modulus_button.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(str(modulus)))
                if md5_fingerprint:
                    copy_md5_button.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(md5_fingerprint))
            else:
                messagebox.showerror("Error", lang_texts["error_password_required"])


# 从APK中读取签名信息
def format_fingerprint(digest):
    """将字节形式的指纹转换为冒号分隔的十六进制字符串"""
    return ':'.join(f'{byte:02X}' for byte in digest)


def get_certificate_info(apk_path, text_widget):
    # 加载 APK，只解析签名部分
    apk = APK(apk_path, skip_analysis=True)  # 跳过代码和资源分析

    # 获取证书（支持 v1/v2/v3/v4 签名）
    certs = apk.get_certificates()
    if not certs:
        print("No certificates found in the APK.")
        return

    # 使用第一个证书
    cert = certs[0]

    # 检查证书类型并获取公钥
    if isinstance(cert, x509.Certificate):
        # 如果是 cryptography 的证书对象
        public_key = cert.public_key()
    else:
        # 如果是 asn1crypto 的证书对象，转换为 cryptography 对象
        cert_der = cert.dump()  # 获取 DER 编码
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        public_key = cert.public_key()

    # 获取公钥参数
    numbers = public_key.public_numbers()
    modulus = numbers.n
    exponent = numbers.e

    # 获取证书 DER 格式用于计算指纹
    cert_der = cert.public_bytes(encoding=Encoding.DER)

    # 计算证书指纹
    md5_digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    md5_digest.update(cert_der)
    md5_hex = format_fingerprint(md5_digest.finalize())

    sha1_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    sha1_digest.update(cert_der)
    sha1_hex = format_fingerprint(sha1_digest.finalize())

    sha256_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256_digest.update(cert_der)
    sha256_hex = format_fingerprint(sha256_digest.finalize())

    # 格式化证书信息
    text_widget.insert(tk.END, "Type: X.509\n")
    text_widget.insert(tk.END, f"Version: v{cert.version.value + 1}\n")
    text_widget.insert(tk.END, f"Serial Number: {hex(cert.serial_number)}\n")
    text_widget.insert(tk.END, f"Subject: {cert.subject.rfc4514_string()}\n")
    text_widget.insert(tk.END, f"Valid From (UTC): {cert.not_valid_before_utc.isoformat()}+00:00\n")
    text_widget.insert(tk.END, f"Valid Until (UTC): {cert.not_valid_after_utc.isoformat()}+00:00\n")
    text_widget.insert(tk.END, "Public Key Type: RSA\n")
    text_widget.insert(tk.END, f"    Modulus Size (bits): {public_key.key_size}\n")
    text_widget.insert(tk.END, f"    Modulus: {modulus}\n")
    text_widget.insert(tk.END, f"    Exponent: {exponent}\n")
    text_widget.insert(tk.END, f"Signature Algorithm: {cert.signature_algorithm_oid._name}\n")
    text_widget.insert(tk.END, "Certificate Fingerprints:\n")
    text_widget.insert(tk.END, f"    MD5: {md5_hex}\n")
    text_widget.insert(tk.END, f"    SHA1: {sha1_hex}\n")
    text_widget.insert(tk.END, f"    SHA256: {sha256_hex}\n")
    return modulus, md5_hex


# 创建 GUI
if __name__ == "__main__":
    root = tk.Tk()
    root.title(lang_texts["title"])
    root.geometry("800x600")

    text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
    text_widget.pack(padx=10, pady=10)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    checkbox_var = tk.IntVar()
    checkbox = tk.Checkbutton(
        button_frame,
        text=lang_texts["check_box"],
        variable=checkbox_var)
    checkbox.pack(side=tk.LEFT, padx=5)

    open_button = tk.Button(button_frame, text=lang_texts["open_button"], command=lambda: open_file(text_widget))
    open_button.pack(side=tk.LEFT, padx=5)

    copy_modulus_button = tk.Button(button_frame, text=lang_texts["copy_modulus_button"], state=tk.DISABLED)
    copy_modulus_button.pack(side=tk.LEFT, padx=5)

    copy_md5_button = tk.Button(button_frame, text=lang_texts["copy_md5_button"], state=tk.DISABLED)
    copy_md5_button.pack(side=tk.LEFT, padx=5)



    # 添加语言切换功能
    def change_language(lang_code):
        global current_lang, lang_texts
        current_lang = lang_code
        lang_texts = load_language(lang_code)
        root.title(lang_texts["title"])
        open_button.config(text=lang_texts["open_button"])
        checkbox.config(text=lang_texts["check_box"])
        copy_modulus_button.config(text=lang_texts["copy_modulus_button"])
        copy_md5_button.config(text=lang_texts["copy_md5_button"])


    # 添加语言切换按钮
    language_frame = tk.Frame(root)
    language_frame.pack(pady=10)

    english_button = tk.Button(language_frame, text="English", command=lambda: change_language("en"))
    english_button.pack(side=tk.LEFT, padx=5)

    chinese_button = tk.Button(language_frame, text="中文", command=lambda: change_language("zh"))
    chinese_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()
