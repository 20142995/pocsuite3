import os
import re
import csv
import shutil
import json
import asyncio
import tempfile
import subprocess
import requests
import time
import hashlib
import zipfile
import platform

requests.packages.urllib3.disable_warnings()

current_path = os.path.dirname(os.path.abspath(__file__))


def md5(msg, encoding='utf8'):
    """md5"""
    return hashlib.md5(msg.encode(encoding)).hexdigest()


def write_json(path, data, encoding="utf8"):
    """写入json"""
    with open(path, "w", encoding=encoding) as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def read_json(path, default_data={}, encoding="utf8"):
    """读取json"""
    data = {}
    if os.path.exists(path):
        try:
            data = json.loads(open(path, "r", encoding=encoding).read())
        except:
            data = default_data
            write_json(path, data, encoding=encoding)
    else:
        data = default_data
        write_json(path, data, encoding=encoding)
    return data


def search_projects(keyword):
    """搜索项目"""
    token = os.getenv("GH_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36",
    }
    search_url = f"https://api.github.com/search/repositories?q={keyword}&sort=updated&page=1&per_page=100"
    response = requests.get(search_url, headers=headers,
                            verify=False, allow_redirects=False).json()
    projects = [i['html_url'] for i in response.get("items", [])]

    return projects

def search_codes(keyword):
    """搜索代码"""
    token = os.getenv("GH_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36",
    }
    params = {'q': keyword, 'page': 1, 'per_page': 100}
    search_url = f"https://api.github.com/search/code"
    response = requests.get(search_url, headers=headers,params=params,
                            verify=False, allow_redirects=False).json()
    projects = [i['repository']['html_url'] for i in response.get("items", [])]

    return projects


def poc_validate(file_path):

    try:
        command = ["pocsuite", "-r", file_path, "--options"]
        print(" ".join(command))
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,universal_newlines=True, encoding='utf8',timeout=5)
    except subprocess.CalledProcessError as e:
        output = e.output
    print(output)
    if re.search('\[ERROR\].*?No module named ["\'](.*?)["\']', output):
        try:
            command = ["python", "-m", "pip", "install",
                       re.search('\[ERROR\].*?No module named ["\'](.*?)["\']', output).group(1)]
            print(" ".join(command))
            returncode = subprocess.run(command, shell=True).returncode
            if returncode == 1:
                return False
        except:
            pass
    if re.search('\[INFO\].*?requires ["\'](.*?)["\'] to be installed', output):
        for name in re.search('\[INFO\].*?requires ["\'](.*?)["\'] to be installed', output).group(1).split(','):
            try:
                command = ["python", "-m", "pip", "install", name]
                print(" ".join(command))
                returncode = subprocess.run(command, shell=True).returncode
                if returncode == 1:
                    return False
            except:
                pass
    return True


def commit_push(msg):
    os.chdir(current_path)
    os.system('git add .')
    os.system(f'git commit -m "{msg}"')

def find_pocs(json_file_path, data, temp_directory, links):
    """查找poc"""
    for link in links:
        for root, _, files in os.walk(os.path.join(temp_directory, md5(link))):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf8') as f:
                            content = f.read()
                    except:
                        continue
                    if re.search('from\s+pocsuite3\.api\s+import\s+.*\s+class\s+\w+\(POCBase\)\:.*def\s+_verify\(self\).*', content, re.S):
                        if file not in data.get(link, {}):
                            # if poc_validate(file_path):
                            print(file)
                            data.setdefault(link, {})
                            data[link][file] = time.strftime(
                                "%Y-%m-%d %H:%M:%S")
                            os.makedirs(os.path.join(
                                current_path, 'poc'), exist_ok=True)
                            shutil.copy2(file_path, os.path.join(
                                current_path, 'poc'))
                          
        write_json(json_file_path, data=data)
        commit_push(f"add from {link}")

async def clone_github_project(link, save_directory):
    """克隆GitHub项目到指定目录"""
    project_name = link.split('/')[-1].replace('.git', '')
    save_directory = os.path.join(save_directory, f"{project_name}")
    os.makedirs(save_directory, exist_ok=True)
    clone_command = f'git clone {link} {save_directory}'
    process = await asyncio.create_subprocess_shell(clone_command)
    await process.wait()


async def clone_github_projects(links, temp_directory):
    """克隆GitHub项目列表"""
    tasks = []
    for link in links:
        task = clone_github_project(
            link, os.path.join(temp_directory, md5(link)))
        tasks.append(task)

    await asyncio.gather(*tasks)


async def main():
    """主函数"""

    # 读取旧链接
    file_path = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), 'data.json')
    data = read_json(file_path)
    links_0 = []
    links_1 = list(data.keys())

    # 搜索新链接
    keyword2 = '"pocsuite3.api" language:Python'
    links_2 = search_codes(keyword2)
    keyword3 = 'pocsuite3'
    links_3 = search_projects(keyword3)
    links = list(set(links_0 + links_1 + links_2 + links_3))

    if 'https://github.com/20142995/pocsuite3' in links:
        links.remove('https://github.com/20142995/pocsuite3')
    if 'https://github.com/20142995/pocs' in links:
        links.remove('https://github.com/20142995/pocs')
    # 克隆项目
    temp_directory = tempfile.mkdtemp()
    await clone_github_projects(links, temp_directory)

    # 查找poc-验证poc-提交poc-记录信息
    find_pocs(file_path, data, temp_directory, links)


# 运行主函数
if __name__ == '__main__':
    asyncio.run(main())

