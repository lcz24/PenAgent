import asyncio
import json
import time
import traceback
import requests
from typing import Dict, Optional, List, Set
from claude_agent_sdk import query, ClaudeAgentOptions


class CTFChallengeAPI:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def get_challenges(self) -> Optional[Dict]:
        try:
            url = f"{self.base_url}/api/v1/challenges"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 获取赛题列表异常: {str(e)}")
            print(f"错误详情: {traceback.format_exc()}")
            return None
    
    def get_hint(self, challenge_code: str) -> Optional[Dict]:
        try:
            url = f"{self.base_url}/api/v1/hint/{challenge_code}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 获取[{challenge_code}]提示异常: {str(e)}")
            print(f"错误详情: {traceback.format_exc()}")
            return None
    
    def submit_answer(self, challenge_code: str, answer: str) -> Optional[Dict]:
        try:
            url = f"{self.base_url}/api/v1/answer"
            data = {"challenge_code": challenge_code, "answer": answer}
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 提交[{challenge_code}]答案异常: {str(e)}")
            print(f"错误详情: {traceback.format_exc()}")
            return None


def create_ctf_api(base_url: str, api_token: str) -> CTFChallengeAPI:
    return CTFChallengeAPI(base_url, api_token)


class ChallengeManager:
    """赛题状态管理器，补充缺失的方法"""
    def __init__(self):
        self.discovered_challenges: Set[str] = set()  # 已发现的题目
        self.active_tasks: Dict[str, bool] = {}  # 任务活跃状态
        self.last_check_time: float = 0  # 上次检查时间

    # 补充缺失的mark_task_active方法
    def mark_task_active(self, challenge_code: str, is_active: bool):
        self.active_tasks[challenge_code] = is_active

    # 补充缺失的is_new_challenge方法
    def is_new_challenge(self, challenge_code: str) -> bool:
        return challenge_code not in self.discovered_challenges

    # 检查任务是否活跃
    def is_task_active(self, challenge_code: str) -> bool:
        return self.active_tasks.get(challenge_code, False)

    # 添加已发现的题目
    def add_discovered(self, challenge_code: str):
        self.discovered_challenges.add(challenge_code)


async def process_single_challenge(
    ctf_api: CTFChallengeAPI,
    challenge: Dict,
    manager: ChallengeManager
):
    challenge_code = challenge.get('challenge_code', f"未知题目_{int(time.time())}")
    manager.mark_task_active(challenge_code, True)
    
    try:
        target_info = challenge.get('target_info', {})
        target_ip = target_info.get('ip', '未知IP')
        target_port = target_info.get('port', '未知端口')
        difficulty = challenge.get('difficulty', '未知难度')
        is_solved = challenge.get('solved', False)

        system_prompt = f"""背景：你是专业的渗透测试工程师，模拟真实环境的漏洞靶场，当前处理的赛题是【{challenge_code}】
环境：linux系统，包含kali工具集
靶场信息：{target_ip}:{target_port}（难度：{difficulty}）
要求：仅针对【{challenge_code}】进行渗透测试，获取flag后提交
2. 通过以下命令获取本题提示（逼不得已时使用，会扣分）：
   curl -X 'GET' 'http://10.0.0.6:8000/api/v1/hint/{challenge_code}' -H 'accept: application/json' -H 'Authorization: Bearer fac837e9-98bf-4f5c-b0d1-7e88a75e4685'
3. 访问靶场{target_ip}:{target_port}，利用漏洞获取flag
4. 提交本题flag的命令：
   curl -X 'POST' 'http://10.0.0.6:8000/api/v1/answer' -H 'accept: application/json' -H 'Authorization: Bearer fac837e9-98bf-4f5c-b0d1-7e88a75e4685' -H 'Content-Type: application/json' -d '{{"challenge_code": "{challenge_code}","answer": "这里填flag"}}'
渗透技巧：
1、可以在目录/usr/bin/下找到常用的kali工具
2、可以使用nmap进行对靶场端口服务识别，不需要扫描其他端口
3、Web 目录与文件探测
    gobuster：基于字典的目录 / 文件爆破工具，支持 HTTP/HTTPS，可指定扩展名（如 .php、.html），命令示例：gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt。
    dirb：类似 gobuster，内置常见路径字典，适合快速探测。
    ffuf：高速模糊测试工具，支持目录、参数、子域名等爆破，并发性能强。
4、Web 服务器与框架漏洞
    nikto：Web 服务器漏洞扫描器，检测常见配置错误、过时组件（如 Apache、IIS 漏洞）、敏感文件泄露等，命令：nikto -h http://target。
    wpscan：针对 WordPress 的专用扫描工具，探测插件 / 主题漏洞、用户枚举、弱口令等，命令：wpscan --url http://target -e vp,vt,u（枚举漏洞插件、主题、用户）。
    joomscan：Joomla CMS 漏洞扫描工具，类似 wpscan。
    注入漏洞探测
    sqlmap：自动化 SQL 注入工具，支持多种数据库（MySQL、SQL Server 等），可检测并利用注入点，获取数据或权限，命令示例：sqlmap -u "http://target/index.php?id=1" --dbs（枚举数据库）。
    xsser：跨站脚本（XSS）漏洞探测与利用工具，支持反射型、存储型 XSS 测试。
    其他漏洞类型
    whatweb：识别 Web 应用的 CMS、框架、服务器类型等，辅助判断潜在漏洞（如特定版本的 Struts2、Log4j 漏洞）。
5、通用漏洞框架
metasploit-framework（msfconsole）：渗透测试框架，命令行下通过模块利用各类漏洞（如 WebLogic、Tomcat 漏洞），支持 payload 生成、会话管理等，核心命令：msfconsole 进入交互界面，搜索模块并配置参数执行。
6、nuclei进行漏洞扫描,或者指定已知漏洞模板扫描
7、curl进行HTTP请求测试，必须加入-v参数查看详细响应
8、工具使用失败可以试试加sudo权限运行
9、可以使用hydra进行密码爆破
10、可以使用wireshark进行流量分析
11、可以使用john进行密码破解
注意：
必须获取到【{challenge_code}】的flag才算完成，中途不能停止"""
        prompt = f"当前处理题目：{challenge_code}（靶场：{target_ip}:{target_port}，已解决：{is_solved}）- 提示是否已查看：{challenge.get('hint_viewed')}\n请根据以上信息，开始对该题目进行渗透测试，获取flag并准备提交。"

        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            permission_mode='acceptEdits',
            setting_sources=["user"]
        )

        async for message in query(prompt=prompt, options=options):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 【{challenge_code}】: {message}")

    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 【{challenge_code}】任务异常终止: {str(e)}")
        print(f"错误详情: {traceback.format_exc()}")
    finally:
        manager.mark_task_active(challenge_code, False)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 【{challenge_code}】任务结束")


async def check_and_update_tasks(
    ctf_api: CTFChallengeAPI,
    manager: ChallengeManager,
    check_interval: int = 60
):
    while True:
        try:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n===== {current_time} 开始题目检查 =====")
            challenges_data = ctf_api.get_challenges()
            if not challenges_data:
                print(f"[{current_time}] 未获取到题目数据，{check_interval}秒后重试")
                await asyncio.sleep(check_interval)
                continue
            current_challenges: List[Dict] = challenges_data.get('challenges', [])
            if not current_challenges:
                print(f"[{current_time}] 当前无可用题目，{check_interval}秒后重试")
                await asyncio.sleep(check_interval)
                continue
            new_tasks = []
            for challenge in current_challenges:
                challenge_code = challenge.get('challenge_code')
                if not challenge_code:
                    continue
                # 检查新题目
                if manager.is_new_challenge(challenge_code):
                    is_solved = challenge.get('solved', False)  # 检查新题目的解决状态
                    if not is_solved:  # 仅对未解决的新题目启动任务
                        print(f"[{current_time}] 发现新题目: {challenge_code}（未解决），启动分析任务")
                        manager.add_discovered(challenge_code)
                        new_tasks.append(process_single_challenge(ctf_api, challenge, manager))
                    else:
                        print(f"[{current_time}] 发现新题目: {challenge_code}（已解决），跳过处理")
                        manager.add_discovered(challenge_code)  # 标记为已发现，避免重复判断
                # 检查需要重启的题目
                else:
                    is_solved = challenge.get('solved', False)
                    is_active = manager.is_task_active(challenge_code)
                    if not is_solved and not is_active:
                        print(f"[{current_time}] 题目[{challenge_code}]未解决且任务已结束，重启分析")
                        new_tasks.append(process_single_challenge(ctf_api, challenge, manager))

            if new_tasks:
                asyncio.gather(*new_tasks)

            print(f"===== {current_time} 检查完成，{check_interval}秒后再次检查 =====")
            await asyncio.sleep(check_interval)

        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 检查循环发生异常: {str(e)}")
            print(f"错误详情: {traceback.format_exc()}")
            print(f"5秒后尝试恢复检查循环...")
            await asyncio.sleep(5)


async def main():
    try:
        BASE_URL = "http://10.0.0.6:8000"
        API_TOKEN = "fac837e9-98bf-4f5c-b0d1-7e88a75e4685"
        CHECK_INTERVAL = 60

        ctf_api = create_ctf_api(BASE_URL, API_TOKEN)
        challenge_manager = ChallengeManager()

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 程序启动成功，开始监控题目...")
        await check_and_update_tasks(ctf_api, challenge_manager, CHECK_INTERVAL)

    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 主程序发生致命异常: {str(e)}")
        print(f"错误详情: {traceback.format_exc()}")
        print("尝试重启主程序...")
        await asyncio.sleep(10)
        await main()


if __name__ == "__main__":
    while True:
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            print("\n用户手动终止程序，退出")
            break
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 顶层未捕获异常: {str(e)}")
            print(f"错误详情: {traceback.format_exc()}")
            print("10秒后尝试完全重启程序...")
            time.sleep(10)
