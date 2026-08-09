#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
edgetunnel 订阅转换脚本
======================
功能:
  1. 拉取 edgetunnel 生成的订阅(Clash YAML 格式,或 base64 的 v2ray 链接格式)
  2. 提取其中所有节点(proxies)
  3. 输出只包含节点、不含 dns / proxy-groups / rules 的纯净 Clash YAML
     —— 这种格式可直接被 subs-check、OpenClash 等工具识别使用

背景:
  edgetunnel 默认订阅带有 dns 配置、策略组和几千条分流规则,
  直接导入 OpenClash / subs-check 时容易解析失败。
  本脚本只保留 proxies 段,生成"纯节点订阅",兼容性最好。

用法:
  python3 sub_convert.py [--url 订阅地址] [-o 输出文件]

  订阅地址优先级:命令行 --url > 环境变量 SUB_URL。
  两者都未提供时脚本报错退出,不会内置任何地址。

依赖:
  优先使用 pyyaml(pip install pyyaml),解析更健壮;
  没有 pyyaml 时自动回退到内置的轻量解析器(针对本订阅的 flow 格式)。

作者: 用户自用脚本,含中文注释便于维护
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.request

# ---------------------------------------------------------------------------
# 配置区
# ---------------------------------------------------------------------------

# 注意:订阅地址(含 token)不写死在脚本里,避免上传公开仓库时泄露凭证。
# 请通过以下任一方式提供:
#   1. 环境变量 SUB_URL(推荐,配合 GitHub Actions Secret 使用)
#   2. 命令行参数 --url https://xxx/sub?token=xxx&clash
# 两者都未提供时脚本会报错退出。

# 请求头:伪装成 Clash 客户端,避免订阅服务返回其他格式
REQUEST_HEADERS = {
    "User-Agent": "ClashForWindows/0.20.39",
    "Accept": "*/*",
}


# ---------------------------------------------------------------------------
# 拉取订阅
# ---------------------------------------------------------------------------

def fetch_subscription(url: str) -> str:
    """下载订阅内容并解码为文本。

    :param url: 订阅链接
    :return: 订阅文本内容
    """
    req = urllib.request.Request(url, headers=REQUEST_HEADERS)
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    # 依次尝试 UTF-8 / latin-1 解码,保证中文节点名不乱码
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# 订阅格式识别
# ---------------------------------------------------------------------------

def looks_like_base64(text: str) -> bool:
    """判断文本是否是 base64 编码的 v2ray 链接列表(如 vmess:// 等)。

    :param text: 订阅文本
    :return: True 表示是 base64 订阅
    """
    s = re.sub(r"\s+", "", text.strip())
    if len(s) < 16:
        return False
    # base64 只允许这些字符
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s) is None:
        return False
    try:
        # 补全 padding 后严格解码
        decoded = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        return any(m in decoded for m in (b"vmess://", b"vless://", b"trojan://", b"ss://"))
    except Exception:
        return False


def looks_like_links(text: str) -> bool:
    """判断文本是否直接就是 v2ray 链接列表(每行一个链接)。

    :param text: 订阅文本
    :return: True 表示是链接列表
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    # 至少 80% 的行是 v2ray 链接才判定为链接列表
    ok = sum(1 for ln in lines if ln.startswith(("vmess://", "vless://", "trojan://", "ss://")))
    return ok > 0 and ok / len(lines) >= 0.8


# ---------------------------------------------------------------------------
# 轻量 YAML flow 解析(回退方案,不依赖 pyyaml)
# ---------------------------------------------------------------------------

def split_top_level(s: str, sep: str = ","):
    """按顶层分隔符切分字符串,忽略引号内和 {} 嵌套内的分隔符。

    :param s: 待切分字符串
    :param sep: 分隔符,默认逗号
    :return: 切分后的片段列表
    """
    parts = []
    depth = 0          # {} 嵌套深度
    quote = None       # 当前引号类型(' 或 "),None 表示不在引号内
    cur = []
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def parse_flow_value(v: str):
    """解析 flow 风格的单个值:引号字符串 / 数字 / bool / 嵌套映射。

    :param v: 值文本
    :return: 解析后的 Python 值
    """
    v = v.strip()
    if v.startswith("{") and v.endswith("}"):
        return parse_flow_map(v[1:-1])
    if v == "true":
        return True
    if v == "false":
        return False
    if v in ("null", "~"):
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    # 纯数字(端口、alterId 等)
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def parse_flow_map(text: str) -> dict:
    """解析 flow 风格的映射,如 {name: x, server: y, ws-opts: {path: /}}。

    :param text: 花括号内部的文本
    :return: 映射字典
    """
    result = {}
    for pair in split_top_level(text, ","):
        # 按第一个顶层冒号切分 key: value
        kv = split_top_level(pair, ":")
        if len(kv) < 2:
            continue
        key = kv[0].strip()
        value = parse_flow_value(":".join(kv[1:]).strip())
        result[key] = value
    return result


def parse_clash_yaml_with_fallback(text: str):
    """从 Clash YAML 中提取 proxies 列表。

    优先用 pyyaml(如果安装了);没有则用内置 flow 解析器。

    :param text: 订阅全文
    :return: 节点字典列表;解析失败返回 None
    """
    # 方式一:pyyaml 全量解析,最健壮
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            return data["proxies"]
    except Exception:
        pass

    # 方式二:内置解析器——定位 proxies 段,逐行解析 flow 格式节点
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^proxies\s*:", line):
            start = i + 1
            break
    if start is None:
        return None

    nodes = []
    for line in lines[start:]:
        # 遇到下一个顶层键(顶格且以冒号结尾)则结束
        if line and not line.startswith((" ", "\t")):
            break
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        entry = stripped[2:].strip()
        # 只处理 flow 单行节点:{...}
        if entry.startswith("{") and entry.endswith("}"):
            nodes.append(parse_flow_map(entry[1:-1]))
        elif entry:
            # block 多行格式且没有 pyyaml 时无法可靠解析,返回 None 走报错提示
            return None
    return nodes if nodes else None


# ---------------------------------------------------------------------------
# v2ray 链接 → Clash 节点(备用兼容,处理非 clash 格式的订阅)
# ---------------------------------------------------------------------------

def _query_dict(qs: str) -> dict:
    """把 URL query 字符串转成普通字典(取每个参数最后一个值)。"""
    result = {}
    for item in qs.split("&"):
        if not item:
            continue
        k, _, v = item.partition("=")
        # 手动 urldecode,兼容 %2F 等转义
        result[k] = urllib.request.unquote(v)
    return result


def vless_to_clash(link: str) -> dict:
    """vless:// 链接转 Clash 节点。

    格式: vless://uuid@host:port?type=ws&security=tls&path=%2F&host=xxx&sni=xxx#名字
    """
    body = link[len("vless://"):]
    frag = ""
    if "#" in body:
        body, frag = body.rsplit("#", 1)
    userinfo, _, hostport = body.partition("@")
    hostport, _, qs = hostport.partition("?")
    host, _, port = hostport.rpartition(":")
    q = _query_dict(qs)

    node = {
        "name": frag or f"{host}:{port}",
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": userinfo,
        "tls": q.get("security") == "tls",
        "skip-cert-verify": False,
        "servername": q.get("sni") or q.get("host") or host,
        "client-fingerprint": q.get("fp") or "chrome",
        "network": q.get("type") or "tcp",
        "udp": True,
    }
    if node["network"] == "ws":
        ws_opts = {"path": q.get("path") or "/"}
        if q.get("host"):
            ws_opts["headers"] = {"Host": q["host"]}
        node["ws-opts"] = ws_opts
    return node


def vmess_to_clash(link: str) -> dict:
    """vmess:// 链接转 Clash 节点(链接主体是 base64 的 JSON)。"""
    try:
        payload = link[len("vmess://"):]
        data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None

    node = {
        "name": data.get("ps") or data.get("add", "vmess"),
        "type": "vmess",
        "server": data.get("add", ""),
        "port": int(data.get("port", 0)),
        "uuid": data.get("id", ""),
        "alterId": int(data.get("aid", 0)),
        "cipher": "auto",
        "udp": True,
    }
    net = data.get("net", "tcp")
    if net == "ws":
        opts = {"path": data.get("path", "/")}
        if data.get("host"):
            opts["headers"] = {"Host": data["host"]}
        node["ws-opts"] = opts
    if data.get("tls") in ("tls", True):
        node["tls"] = True
        if data.get("sni"):
            node["servername"] = data["sni"]
    return node


def trojan_to_clash(link: str) -> dict:
    """trojan:// 链接转 Clash 节点。"""
    body = link[len("trojan://"):]
    frag = ""
    if "#" in body:
        body, frag = body.rsplit("#", 1)
    password, _, hostport = body.partition("@")
    hostport, _, qs = hostport.partition("?")
    host, _, port = hostport.rpartition(":")
    q = _query_dict(qs)
    return {
        "name": frag or f"{host}:{port}",
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": q.get("sni") or host,
        "udp": True,
    }


def ss_to_clash(link: str) -> dict:
    """ss:// 链接转 Clash 节点(支持 SIP002 与旧式 base64 两种格式)。"""
    body = link[len("ss://"):]
    frag = ""
    if "#" in body:
        body, frag = body.rsplit("#", 1)

    if "@" in body:
        # SIP002: ss://base64(method:password)@host:port 或明文 method:password@host:port
        head, _, hostport = body.partition("@")
        host, _, port = hostport.rpartition(":")
        if ":" in head:
            method, _, password = head.partition(":")
        else:
            try:
                dec = base64.b64decode(head + "=" * (-len(head) % 4)).decode()
                method, _, password = dec.partition(":")
            except Exception:
                return None
    else:
        # 旧式:整段 base64(method:password@host:port)
        try:
            dec = base64.b64decode(body + "=" * (-len(body) % 4)).decode()
            method, _, rest = dec.partition(":")
            password, _, hostport = rest.rpartition("@")
            host, _, port = hostport.rpartition(":")
        except Exception:
            return None

    return {
        "name": frag or f"{host}:{port}",
        "type": "ss",
        "server": host,
        "port": int(port),
        "cipher": method,
        "password": password,
        "udp": True,
    }


def parse_v2ray_links(text: str):
    """解析 v2ray 链接列表(每行一个链接)为 Clash 节点列表。

    :param text: 链接列表文本
    :return: 节点字典列表
    """
    nodes = []
    for line in text.splitlines():
        link = line.strip()
        if not link:
            continue
        node = None
        if link.startswith("vless://"):
            node = vless_to_clash(link)
        elif link.startswith("vmess://"):
            node = vmess_to_clash(link)
        elif link.startswith("trojan://"):
            node = trojan_to_clash(link)
        elif link.startswith("ss://"):
            node = ss_to_clash(link)
        if node:
            nodes.append(node)
    return nodes


# ---------------------------------------------------------------------------
# 订阅入口:自动识别格式并提取节点
# ---------------------------------------------------------------------------

def extract_proxies(text: str):
    """识别订阅格式并提取节点列表。

    :param text: 订阅全文
    :return: 节点字典列表(可能为空)
    """
    stripped = text.strip()
    if looks_like_base64(stripped):
        # base64 编码的链接列表
        decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4)).decode("utf-8", "ignore")
        return parse_v2ray_links(decoded)
    if looks_like_links(stripped):
        # 明文链接列表
        return parse_v2ray_links(stripped)
    # Clash YAML
    proxies = parse_clash_yaml_with_fallback(text)
    return proxies or []


# ---------------------------------------------------------------------------
# 输出:生成纯净 Clash YAML
# ---------------------------------------------------------------------------

def dump_scalar(v) -> str:
    """把 Python 标量序列化为 YAML 标量(必要时加引号)。"""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    # 含 YAML 特殊字符(如 [ ] { } , : # 引号等)时加双引号,保证可被正确解析
    if s == "" or any(c in s for c in '[]{}:,&*#|>!%@`"\'') or s[0] in " -?":  # noqa: E501
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def render_mapping(m: dict, prefix: str) -> list:
    """把映射渲染为缩进的 YAML 行。

    :param m: 映射字典
    :param prefix: 每行前缀(用于 "- " 与缩进对齐)
    :return: YAML 行列表
    """
    lines = []
    for k, v in m.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.extend(render_mapping(v, prefix + "  "))
        else:
            lines.append(f"{prefix}{k}: {dump_scalar(v)}")
    return lines


def render_proxies_yaml(proxies: list) -> str:
    """把节点列表渲染为纯净 Clash YAML 文本(block 风格)。

    :param proxies: 节点字典列表
    :return: YAML 文本
    """
    out = ["proxies:"]
    for node in proxies:
        # 首行用 "- " 标记列表项,后续行对齐缩进
        keys = list(node.keys())
        for i, k in enumerate(keys):
            v = node[k]
            prefix = "  - " if i == 0 else "    "
            if isinstance(v, dict):
                out.append(f"{prefix}{k}:")
                out.extend(render_mapping(v, prefix + "  "))
            else:
                out.append(f"{prefix}{k}: {dump_scalar(v)}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def mask_subscription_url(url: str) -> str:
    """脱敏订阅地址:隐藏 query 中的 token 等敏感参数值,防止泄露到日志。

    GitHub Actions 日志对公开仓库是公开可见的,
    即使 GitHub 会自动掩码部分 secret,也不能依赖它,必须主动脱敏。

    :param url: 原始订阅地址
    :return: 脱敏后的地址(token 等参数值替换为 ***)
    """
    # 只替换敏感参数(token/key/password 等)的值,其余字符原样保留
    # 例如: ?token=abc&clash → ?token=***&clash
    return re.sub(
        r"([?&](?:token|key|password|secret|auth|pwd|passwd)=)[^&#]*",
        r"\1***",
        url,
        flags=re.IGNORECASE,
    )


def split_urls(urls_text: str):
    """把多个订阅地址(逗号或换行分隔)拆成列表。

    :param urls_text: 原始输入,可含多个地址,用逗号或换行分隔
    :return: 去空白后的地址列表
    """
    # 统一把逗号、换行都当作分隔符
    parts = re.split(r"[,，\n]+", urls_text.strip())
    return [p.strip() for p in parts if p.strip()]


def main():
    """命令行入口:拉取订阅(可多个)→ 提取节点 → 合并去重 → 输出纯净 YAML。"""
    parser = argparse.ArgumentParser(
        description="edgetunnel 订阅转换:拉取一个或多个订阅并生成只含节点的纯净 Clash YAML"
    )
    parser.add_argument(
        "--url",
        default=None,
        help="订阅地址(可多个,用逗号分隔;也可通过环境变量 SUB_URL 提供)",
    )
    parser.add_argument(
        "-o", "--output",
        default="clash.yaml",
        help="输出文件名(默认 clash.yaml)",
    )
    args = parser.parse_args()

    # 订阅地址获取优先级:命令行 --url > 环境变量 SUB_URL > 报错退出
    urls = split_urls(args.url) if args.url else split_urls(os.environ.get("SUB_URL", ""))
    if not urls:
        print(
            "错误: 未提供订阅地址。请使用 --url 参数,或设置环境变量 SUB_URL。\n"
            "示例: SUB_URL='https://xxx/sub?token=xxx&clash' python3 sub_convert.py\n"
            "支持多个订阅,用逗号分隔: SUB_URL='url1,url2'",
            file=sys.stderr,
        )
        sys.exit(1)

    # 逐个拉取并解析订阅,合并所有节点
    all_proxies = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{len(urls)}] 正在拉取订阅...")
        try:
            text = fetch_subscription(url)
        except Exception as e:
            # 单个订阅失败不中断整体,记录后继续拉取下一个
            print(f"    警告: 该订阅拉取失败,跳过。", file=sys.stderr)
            continue
        proxies = extract_proxies(text)
        if not proxies:
            print(f"    警告: 该订阅未解析出任何节点,跳过。", file=sys.stderr)
            continue
        print(f"    该订阅提取 {len(proxies)} 个节点")
        all_proxies.extend(proxies)

    if not all_proxies:
        print("错误: 所有订阅均未解析出任何节点,请检查订阅地址是否有效。", file=sys.stderr)
        sys.exit(1)

    # 合并去重:按 (type, server, port) 判重,保留第一个出现的节点
    seen = set()
    merged = []
    for p in all_proxies:
        key = (p.get("type"), p.get("server"), p.get("port"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(p)

    # 重名处理:同名节点追加序号,保证 Clash 配置中节点名唯一
    name_count = {}
    for p in merged:
        name = p.get("name", "unnamed")
        n = name_count.get(name, 0)
        name_count[name] = n + 1
        if n > 0:
            p["name"] = f"{name} ({n + 1})"

    print(f"[3/3] 合并后共 {len(merged)} 个节点(去重 {len(all_proxies) - len(merged)} 个),"
          f"正在写入订阅文件…")
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(render_proxies_yaml(merged))

    print(f"完成! ...")
    print(f"提示: 该文件只包含 proxies,不含 dns/proxy-groups/rules,"
          f"可直接用于 subs-check 和 OpenClash。")


if __name__ == "__main__":
    main()
