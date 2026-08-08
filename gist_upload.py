#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secret Gist 自动上传脚本
========================
功能:
  把生成的 clash.yaml 上传/更新到 GitHub 的 secret gist 上。
  - 首次运行:自动创建一个新的 secret gist(不会被搜索、不出现在主页)
  - 之后运行:自动更新同一个 gist(通过固定的描述标记识别,无需手动记 ID)

为什么用 secret gist:
  转换后的订阅节点里包含你的域名,不能提交到公开仓库。
  而且 subs-check / OpenClash 可以直接用它的 raw 链接拉取。

用法:
  GIST_TOKEN=你的令牌 python3 gist_upload.py [--file clash.yaml] [--gist-id 可选ID]

环境变量:
  GIST_TOKEN  GitHub 个人访问令牌(PAT),只需 gist 权限(必填)
  GIST_ID     secret gist 的 ID(可选);提供时直接更新该 gist,跳过自动查找

输出:
  打印订阅 raw 链接,可直接填给 subs-check / OpenClash。
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# Gist API 地址
API_BASE = "https://api.github.com"

# 固定描述标记:用于识别"这是订阅自动更新用的 gist",避免重复创建
GIST_MARKER = "clash-sub-auto"

# 上传的文件名(在 gist 中的文件名,也决定 raw 链接后缀)
GIST_FILENAME = "clash.yaml"


def api_request(method: str, path: str, token: str, payload=None) -> dict:
    """调用 GitHub REST API。

    :param method: HTTP 方法(GET / POST / PATCH)
    :param path: API 路径,如 "/user" 或 "/gists/abc123"
    :param token: GitHub PAT
    :param payload: 请求体(字典),None 表示无请求体
    :return: 解析后的 JSON 响应
    """
    req = urllib.request.Request(API_BASE + path, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "clash-sub-auto")
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        raise SystemExit(f"GitHub API 请求失败 ({e.code}): {body}")


def find_marked_gist(token: str, login: str):
    """在用户的 gist 列表中查找带固定标记的 gist。

    :param token: GitHub PAT
    :param login: GitHub 用户名
    :return: 找到的 gist 字典,找不到返回 None
    """
    page = 1
    while True:
        gists = api_request(
            "GET", f"/users/{login}/gists?per_page=100&page={page}", token
        )
        for g in gists:
            if g.get("description") == GIST_MARKER:
                return g
        # 不足一页说明已经翻完,结束查找
        if len(gists) < 100:
            return None
        page += 1


def main():
    """主流程:读文件 → 找 gist(或新建)→ 上传/更新 → 打印订阅链接。"""
    parser = argparse.ArgumentParser(description="把 clash.yaml 上传到 secret gist")
    parser.add_argument("--file", default="clash.yaml", help="要上传的文件(默认 clash.yaml)")
    parser.add_argument("--gist-id", default=None, help="指定 gist ID(可选,跳过自动查找)")
    args = parser.parse_args()

    # 1. 检查令牌
    token = os.environ.get("GIST_TOKEN", "")
    if not token:
        print(
            "错误: 未设置 GIST_TOKEN 环境变量。\n"
            "请先在 GitHub 创建个人访问令牌(只需 gist 权限),然后:\n"
            "GIST_TOKEN=你的令牌 python3 gist_upload.py",
            file=sys.stderr,
        )
        sys.exit(1)

    # 2. 读取要上传的内容
    try:
        with open(args.file, encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        print(f"错误: 无法读取文件 {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. 获取当前用户信息(用于构造链接和查找 gist)
    user = api_request("GET", "/user", token)
    login = user.get("login", "")

    # 4. 确定目标 gist:指定 ID > 自动查找标记 gist > 新建
    gist_id = args.gist_id
    if not gist_id:
        found = find_marked_gist(token, login)
        gist_id = found.get("id") if found else None

    files = {GIST_FILENAME: {"content": content}}

    if gist_id:
        # 已存在:更新文件内容
        api_request("PATCH", f"/gists/{gist_id}", token, {"files": files})
        action = "已更新"
    else:
        # 不存在:创建新的 secret gist(public=False 是关键,别人看不到)
        g = api_request(
            "POST",
            "/gists",
            token,
            {"description": GIST_MARKER, "public": False, "files": files},
        )
        gist_id = g.get("id")
        action = "已创建"

    # 5. 订阅链接写入本地文件,不打印到控制台!

    raw_url = f"https://gist.githubusercontent.com/{login}/{gist_id}/raw/{GIST_FILENAME}"
    with open("subscription-url.txt", "w", encoding="utf-8") as f:
        f.write(raw_url + "\n")

    # 控制台只输出一行状态,不包含任何链接
    print(f"{action} secret gist,订阅链接已保存到 subscription-url.txt")


if __name__ == "__main__":
    main()
