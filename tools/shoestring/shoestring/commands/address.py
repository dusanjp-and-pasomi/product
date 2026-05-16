import sys
import os
import re
import glob
import argparse
import configparser
from getpass import getpass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.symbol.KeyPair import KeyPair

NODE_KEY_PEM = "/cert/node.key.pem"
REMOTE_KEY_PEM = "/remote.pem"
VRF_KEY_PEM = "/vrf.pem"

def xxd_epoch(file_path):
    try:
        with open(file_path, 'rb') as f:
            f.seek(0x0001)
            byte1_start = f.read(1)
            f.seek(0x0000)
            byte2_start = f.read(1)
            f.seek(0x0009)
            byte1_end = f.read(1)
            f.seek(0x0008)
            byte2_end = f.read(1)
           
            if not byte1_start or not byte2_start or not byte1_end or not byte2_end:
                print("おや、ファイルが短すぎて指定の位置を読み取れませんでしたわ。💖うふふっ💕")
                return
           
            hex_start = byte1_start.hex() + byte2_start.hex()
            dec_start = int(hex_start, 16)
            hex_end = byte1_end.hex() + byte2_end.hex()
            dec_end = int(hex_end, 16)
           
            print(f"開始エポック:\t{dec_start}\tでございますわ。💖うふふっ💕")
            print(f"終了エポック:\t{dec_end}\tでございますわ。💖うふふっ💕")
    except FileNotFoundError:
        print(f"おや、'{file_path}' というファイルが見つかりませんでしたわ。💖うふふっ💕")
    except Exception as e:
        print(f"あら、問題が起きましたわ：{e} でございますわ。💖うふふっ💕")

def xxd_like_dump(file_path, start_offset=0x0020, end_offset=0x003f, lines_per_page=24):
    try:
        with open(file_path, 'rb') as f:
            f.seek(start_offset)
            offset = start_offset
            line_count = 0
            hex_concatenated = ""
            
            while offset <= end_offset:
                chunk = f.read(min(16, end_offset - offset + 1))
                if not chunk:
                    break
                for b in chunk:
                    hex_concatenated += f"{b:02X}"
                offset += 16
                line_count += 1
                if line_count % lines_per_page == 0:
                    input("どうぞ、続けるにはエンターを押してくださいませ。💖うふふっ💕")
            
            print(f"公開鍵:\t{hex_concatenated}\tでございますわ。💖うふふっ💕")
            xxd_epoch(file_path)
            print(f"ファイル名:\t{os.path.basename(file_path)}\tでございますわ。💖うふふっ💕")

    except FileNotFoundError:
        print(f"おや、'{file_path}' というファイルが見つかりませんでしたわ。💖うふふっ💕")
    except Exception as e:
        print(f"あら、問題が起きましたわ：{e} でございますわ。💖うふふっ💕")

def process_voting_keys():
    voting_dirs = [
        os.path.normpath("keys/voting"),
        os.path.normpath("node/keys/voting")
    ]
    
    voting_dir = None
    for dir_path in voting_dirs:
        if os.path.exists(dir_path):
            voting_dir = dir_path
            break
    
    if not voting_dir:
        print("投票キーはございませんわ。💖うふふっ💕")
        return
    
    files = glob.glob(os.path.join(voting_dir, "private_key_tree*.dat"))
    if not files:
        print("投票キーはございませんわ。💖うふふっ💕")
        return
    
    print("投票キー情報をお伝えいたしますわ:\t💖うふふっ💕")
    def get_number(filename):
        match = re.search(r'private_key_tree(\d+)\.dat', filename)
        return int(match.group(1)) if match else 0
    
    sorted_files = sorted(files, key=get_number, reverse=True)
    for i, file_path in enumerate(sorted_files):
        xxd_like_dump(file_path)
        if i < len(sorted_files) - 1:
            print()

def get_network_name(config_path):
    config = configparser.ConfigParser()
    paths_to_check = [config_path, os.path.normpath(os.path.join(os.path.dirname(os.getcwd()), "shoestring", "shoestring.ini"))]
    
    for path in paths_to_check:
        try:
            if os.path.exists(path):
                config.read(path, encoding="utf-8")
                return config.get("network", "name", fallback="testnet")
        except Exception:
            continue
    print("shoestring.ini が見つかりませんでしたわ。デフォルトの 'testnet' を使用いたしますわ。💖うふふっ💕")
    return "testnet"

def read_public_keys_from_pem_chain(cert_path):
    paths_to_check = [cert_path]
    if os.path.basename(cert_path) == "node.full.crt.pem":
        node_path = os.path.normpath(os.path.join("node", cert_path))
        paths_to_check.append(node_path)
    
    for path in paths_to_check:
        try:
            with open(path, "rb") as cert_file:
                pem_data = cert_file.read()
                certs = pem_data.split(b"-----END CERTIFICATE-----")
                public_keys = []
                for cert_pem in certs:
                    cert_pem = cert_pem.strip()
                    if cert_pem:
                        cert_pem += b"\n-----END CERTIFICATE-----\n"
                        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                        der_bytes = cert.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )[12:]
                        public_keys.append(der_bytes)
                return public_keys
        except Exception:
            continue
    print(f"{os.path.basename(cert_path)} が見つかりませんでしたわ。💖うふふっ💕")
    return []

def read_private_key_from_pem(pem_path):
    paths_to_check = [pem_path]
    if os.path.basename(pem_path) != "ca.key.pem":
        node_path = os.path.normpath(os.path.join("node", pem_path))
        paths_to_check.append(node_path)
    if os.path.basename(pem_path) == "ca.key.pem":
        parent_path = os.path.join(os.path.dirname(pem_path), "..", "ca.key.pem")
        paths_to_check.append(os.path.normpath(parent_path))
    
    for path in paths_to_check:
        try:
            with open(path, "rb") as ca_key_file:
                ca_key_data = ca_key_file.read()
                try:
                    private_key_obj = serialization.load_pem_private_key(
                        ca_key_data, password=None, backend=default_backend()
                    )
                except (ValueError, TypeError):
                    password = getpass(f"{os.path.basename(path)} のパスワードを教えてくださいませ：💖うふふっ💕")
                    if not password:
                        print(f"{os.path.basename(path)} のパスワードが入力されませんでしたわ。💖うふふっ💕")
                        continue
                    try:
                        private_key_obj = serialization.load_pem_private_key(
                            ca_key_data, password=password.encode('utf-8'), backend=default_backend()
                        )
                    except Exception as e:
                        print(f"{os.path.basename(path)} の復号に失敗しましたわ：パスワードが正しくないか、キーが壊れているようですわ。💖うふふっ💕")
                        continue
                der_bytes = private_key_obj.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )[16:]
                return der_bytes.hex().upper()
        except FileNotFoundError:
            continue
    print(f"{os.path.basename(pem_path)} が見つかりませんでしたわ。💖うふふっ💕")
    return None

def show_account_info(args, facade, account_type, private_key_path, cert_index, label):
    private_key_hex = read_private_key_from_pem(private_key_path)
    if private_key_hex is not None:
        key_pair = KeyPair(PrivateKey(private_key_hex))
        private_public_key = key_pair.public_key
    else:
        private_public_key = None
    
    cert_public_key = None
    cert_public_account = None
    if account_type in ("main", "node"):
        cert_public_keys = read_public_keys_from_pem_chain(
            args.keys_path + "/cert/node.full.crt.pem"
        )
        if not cert_public_keys or len(cert_public_keys) <= cert_index:
            print(f"{label}公開鍵を証明書から取得できませんでしたわ。💖うふふっ💕")
            return
        cert_public_key = PublicKey(cert_public_keys[cert_index])
        cert_public_account = facade.create_public_account(cert_public_key)
        if private_public_key is not None and private_public_key != cert_public_key:
            print(f"{label}証明書の秘密鍵と公開鍵が一致しませんわ。💖うふふっ💕")
            return
    
    print(f"{label}アカウント情報をご覧くださいませ:\t💖うふふっ💕")
    if cert_public_account:
        print(f"アドレス:\t{cert_public_account.address}\tでございますわ。💖うふふっ💕")
        print(f"公開鍵:\t\t{cert_public_key}\tでございますわ。💖うふふっ💕")
    elif private_public_key is not None:
        account = facade.create_public_account(private_public_key)
        print(f"アドレス:\t{account.address}\tでございますわ。💖うふふっ💕")
        print(f"公開鍵:\t\t{private_public_key}\tでございますわ。💖うふふっ💕")
    else:
        print(f"{label}キーの秘密鍵を読み込めませんでしたわ。💖うふふっ💕")
        return
    if args.show_private_key and private_key_hex is not None:
        print(f"秘密鍵:\t\t{private_key_hex}\tでございますわ。💖うふふっ💕")
    print()

def show_all_keys(args):
    facade = SymbolFacade(get_network_name(args.config))
    show_account_info(args, facade, "main", args.ca_key_path, 1, "メイン")
    show_account_info(args, facade, "node", args.keys_path + NODE_KEY_PEM, 0, "ノード")
    show_account_info(args, facade, "remote", args.keys_path + REMOTE_KEY_PEM, None, "リモート")
    show_account_info(args, facade, "vrf", args.keys_path + VRF_KEY_PEM, None, "VRF")

async def link_node_keys(args):
    print("ノードキーをリンクする機能はまだ実装されておりませんわ。💖うふふっ💕")
    return None

async def unlink_node_keys(args):
    print("ノードキーをアンリンクする機能はまだ実装されておりませんわ。💖うふふっ💕")
    return None

def show_voting_keys(args):
    process_voting_keys()

def get_common_showkey_args():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c", "--config", type=str, default="shoestring/shoestring.ini",
        help="ノードコンフィグのパスでございますわ[デフォルト: shoestring/shoestring.ini]💖うふふっ💕"
    )
    parent.add_argument(
        "-ca", "--ca-key-path", type=str, default="ca.key.pem",
        help="CA証明書のパスでございますわ[デフォルト: ca.key.pem]💖うふふっ💕"
    )
    parent.add_argument(
        "-k", "--keys-path", type=str, default="keys",
        help="keysディレクトリのパスでございますわ[デフォルト: keys]💖うふふっ💕"
    )
    parent.add_argument(
        "-p", "--show-private-key", action="store_true",
        help="プライベートキーを表示いたしますわ💖うふふっ💕"
    )
    return parent

def get_common_link_args():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c", "--config", type=str, default="shoestring/shoestring.ini",
        help="ノードコンフィグのパスでございますわ[デフォルト: shoestring/shoestring.ini]💖うふふっ💕"
    )
    parent.add_argument(
        "-k", "--keys-path", type=str, default="keys",
        help="keysディレクトリのパスでございますわ[デフォルト: keys]💖うふふっ💕"
    )
    return parent

class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    """サブコマンドのヘルプをタブで揃えるカスタムフォーマッターでございますわ"""
    def _format_action(self, action):
        if isinstance(action, argparse._SubParsersAction):
            parts = []
            parts.append(self._format_action_invocation(action))
            parts.append('\n')
            subcommands = [
                ('show-key', 'すべてのノードキー情報を表示いたしますわ。💖うふふっ💕'),
                ('show-key -p', 'すべてのノードキー情報を表示いたしますわ（秘密鍵も含めてでございますわ）。💖うふふっ💕'),
                ('link', 'ハーベスティングリンクいたしますわ。💖うふふっ💕'),
                ('unlink', 'ハーベスティングアンリンクいたしますわ。💖うふふっ💕'),
                ('show-voting', '投票キー情報を表示いたしますわ。💖うふふっ💕'),
            ]
            for cmd, help_text in subcommands:
                parts.append(f"  {cmd:<12}\t{help_text}")
            parts.append('\n')
            return '\n'.join(parts)
        return super()._format_action(action)

class CustomArgumentParser(argparse.ArgumentParser):
    """カスタムパーサーでエラー時のヘルプ表示を抑制し、フォーマッターを適用いたしますわ"""
    def __init__(self, *args, **kwargs):
        kwargs['formatter_class'] = CustomHelpFormatter
        super().__init__(*args, **kwargs)
    
    def error(self, message):
        sys.exit(2)
    
    def print_help(self, file=None):
        self._print_message(self.format_help(), file)

def add_arguments(parser):
    """addressサブコマンドの引数を定義いたしますわ"""
    custom_parser = CustomArgumentParser(
        prog=parser.prog,
        description=parser.description,
        formatter_class=CustomHelpFormatter,
        add_help=True
    )
    custom_parser.set_defaults(func=main)
    subparsers = custom_parser.add_subparsers(title="サブコマンド", metavar="", dest="command", required=False)
    
    show_common_args = [get_common_showkey_args()]
    show_parser = subparsers.add_parser(
        "show-key", help="すべてのノードキー情報を表示いたしますわ💖うふふっ💕", parents=show_common_args, add_help=True
    )
    show_parser.set_defaults(func=show_all_keys)
    
    link_common_args = [get_common_link_args()]
    link_parser = subparsers.add_parser(
        "link", help="ハーベスティングリンクいたしますわ💖うふふっ💕", parents=link_common_args, add_help=True
    )
    link_parser.set_defaults(func=link_node_keys)
    
    unlink_parser = subparsers.add_parser(
        "unlink", help="ハーベスティングアンリンクいたしますわ💖うふふっ💕", parents=link_common_args, add_help=True
    )
    unlink_parser.set_defaults(func=unlink_node_keys)
    
    voting_parser = subparsers.add_parser(
        "show-voting", help="投票キー情報を表示いたしますわ💖うふふっ💕", parents=[], add_help=True
    )
    voting_parser.set_defaults(func=show_voting_keys)
    
    parser.__dict__.update(custom_parser.__dict__)

async def main(args):
    """addressサブコマンドのメイン処理でございますわ"""
    if not hasattr(args, 'config'):
        args.config = "shoestring/shoestring.ini"
    if not hasattr(args, 'ca_key_path'):
        args.ca_key_path = "ca.key.pem"
    if not hasattr(args, 'keys_path'):
        args.keys_path = "keys"
    if not hasattr(args, 'show_private_key'):
        args.show_private_key = True
    if not hasattr(args, 'command') or not args.command:
        args.command = "show-key"
        args.show_private_key = True
        show_all_keys(args)
        print()
        process_voting_keys()
    else:
        if hasattr(args, 'func'):
            if args.command == "show-key":
                show_all_keys(args)
                print()
                process_voting_keys()
            elif args.command == "show-voting":
                show_voting_keys(args)
            else:
                await args.func(args)
        else:
            args.show_private_key = True
            show_all_keys(args)
            print()
            process_voting_keys()
    return None
