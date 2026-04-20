import re
from collections import defaultdict
from datetime import datetime, timedelta
import urllib.parse
import requests
import subprocess
import time
import os


class NIDSAnalyzer:
    """
    Основной класс анализатора NIDS (Network Intrusion Detection System).
    Отвечает за парсинг логов и обнаружение различных типов атак.
    """

    def __init__(self):
        """
        Инициализация анализатора.
        Создает словарь для отслеживания неудачных попыток входа по IP-адресам.
        defaultdict(list) автоматически создает пустой список для каждого нового IP.
        """
        self.failed_logins = defaultdict(list)

    def analyze_log(self, log_line):
        """
        Основной метод анализа строки лога.

        Аргументы:
            log_line (str): Строка лога для анализа

        Возвращает:
            list: Список обнаруженных атак (алертов)
        """
        # Парсим строку лога в структурированный формат
        parsed = self.parse_apache_log(log_line)
        if not parsed:
            return []  # Если парсинг не удался, возвращаем пустой список
        return self.analyze_parsed_log(parsed)  # Анализируем распарсенные данные

    def parse_apache_log(self, line):
        """
        Парсит строку лога в формате Apache Combined Log Format.
        Поддерживает извлечение реального IP из заголовка X-Forwarded-For.

        Формат лога: IP - - [время] "МЕТОД URL HTTP/версия" статус размер "referer" "user-agent"

        Аргументы:
            line (str): Строка лога

        Возвращает:
            dict: Словарь с распарсенными данными или None при ошибке
        """
        # Извлекаем реальный IP клиента из заголовка X-Forwarded-For
        # Формат строки: "клиентский_IP - docker_IP - [время] ..."
        xff_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+\.\d+)', line)
        if xff_match:
            ip = xff_match.group(1)  # Берем первый IP (реальный клиентский)
        else:
            # Если X-Forwarded-For нет, берем первый IP из строки
            ip_match = re.match(r'(\S+)', line)
            ip = ip_match.group(1) if ip_match else '0.0.0.0'

        # Извлекаем временную метку из квадратных скобок
        time_match = re.search(r'\[(.*?)\]', line)
        if not time_match:
            return None
        try:
            # Преобразуем строку времени в объект datetime
            # Формат: 01/Jan/2024:12:00:00 +0300
            timestamp = datetime.strptime(time_match.group(1), '%d/%b/%Y:%H:%M:%S %z')
        except:
            # Если парсинг не удался, используем текущее время
            timestamp = datetime.now()

        # Извлекаем метод HTTP и URL запроса
        request_match = re.search(r'"(\S+) (.+?) HTTP/\d\.\d"', line)
        if not request_match:
            return None
        method = request_match.group(1)  # GET, POST, PUT, DELETE и т.д.
        url = request_match.group(2)  # Запрашиваемый URL

        # Извлекаем HTTP статус ответа (200, 401, 404 и т.д.)
        status_match = re.search(r'" (\d{3}) ', line)
        status = int(status_match.group(1)) if status_match else 0

        # Извлекаем User-Agent (последняя часть в кавычках)
        parts = line.split('"')
        user_agent = parts[-1] if len(parts) > 1 else ''

        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'url': url,
            'status': status,
            'user_agent': user_agent
        }

    def analyze_parsed_log(self, parsed):
        """
        Анализирует распарсенные данные лога на наличие признаков атак.

        Аргументы:
            parsed (dict): Распарсенные данные лога (результат parse_apache_log)

        Возвращает:
            list: Список обнаруженных атак
        """
        alerts = []
        ip = parsed['ip']
        timestamp = parsed['timestamp']
        url = parsed['url']
        status = parsed['status']

        # Декодируем URL (преобразуем %20 в пробелы и т.д.) и приводим к нижнему регистру
        decoded = urllib.parse.unquote(url).lower()

        # Список паттернов статических файлов, которые не нужно анализировать
        # Это уменьшает количество ложных срабатываний
        static_patterns = [".css", ".js", ".png", ".jpg", ".ico", ".woff", ".woff2",
                           ".ttf", ".eot", ".svg", "/assets/", "/media/", "favicon.ico",
                           "robots.txt"]

        # Проверяем, является ли запрос к статическому файлу
        is_static = False
        for pattern in static_patterns:
            # Если найден паттерн и нет параметров запроса (знака ?)
            if pattern in decoded and "?" not in decoded:
                is_static = True
                break

        # Пропускаем статические файлы, чтобы уменьшить количество ложных срабатываний
        if is_static:
            return alerts

        # Выводим информацию об анализируемом запросе (для отладки)
        print(f"🔍 Analyzing from IP: {ip}, URL: {decoded[:150]}")

        # Последовательно проверяем различные типы атак
        if self.detect_sql(decoded):
            print("✅ SQL Injection detected!")
            alerts.append(self.make_alert(ip, timestamp, "SQL Injection", "high",
                                          "SQL injection payload", url))

        if self.detect_xss(decoded):
            print("✅ XSS Attack detected!")
            alerts.append(self.make_alert(ip, timestamp, "XSS Attack", "high",
                                          "XSS payload", url))

        if self.detect_command(decoded):
            print("✅ Command Injection detected!")
            alerts.append(self.make_alert(ip, timestamp, "Command Injection", "high",
                                          "Command injection payload", url))

        if self.detect_path(decoded):
            print("✅ Path Traversal detected!")
            alerts.append(self.make_alert(ip, timestamp, "Path Traversal", "high",
                                          "Path traversal attempt", url))

        # Проверяем на брутфорс (множественные неудачные логины)
        # Если URL содержит /login и статус ответа 401 (Unauthorized)
        if "/login" in url and status == 401:
            bf = self.detect_bruteforce(ip, timestamp)
            if bf:
                alerts.append(bf)

        return alerts

    def detect_sql(self, text):
        """
        Обнаруживает SQL инъекции в тексте запроса.

        SQL инъекции позволяют злоумышленнику выполнять произвольные SQL запросы к базе данных.

        Аргументы:
            text (str): Декодированный URL или параметры запроса

        Возвращает:
            bool: True если обнаружена SQL инъекция
        """
        # Список характерных признаков SQL инъекций
        patterns = ["or 1=1",  # Классическая инъекция
                    "' or '1'='1",  # Обход аутентификации
                    "union select",  # UNION инъекция
                    "information_schema",  # Доступ к метаданным БД
                    "sleep(",  # Инъекция с задержкой (time-based)
                    "benchmark(",  # Инъекция с нагрузкой
                    "version()",  # Получение версии БД
                    "database()",  # Получение имени БД
                    "--",  # Комментарий в SQL
                    "#",  # Комментарий в MySQL
                    "/*",  # Многострочный комментарий
                    "; drop",  # DROP команда
                    "; insert",  # INSERT команда
                    "; update",  # UPDATE команда
                    "; delete"]  # DELETE команда
        for pattern in patterns:
            if pattern in text:
                return True
        return False

    def detect_xss(self, text):
        """
        Обнаруживает XSS (Cross-Site Scripting) атаки.

        XSS позволяет злоумышленнику внедрять вредоносный JavaScript код на страницы сайта.

        Аргументы:
            text (str): Декодированный URL или параметры запроса

        Возвращает:
            bool: True если обнаружена XSS атака
        """
        # Декодируем текст и приводим к нижнему регистру
        text = urllib.parse.unquote(text).lower()

        # Сигнатуры XSS атак
        signatures = ["<script",  # Тег script
                      "</script",  # Закрывающий тег script
                      "<iframe",  # Встраивание iframe
                      "<img",  # Тег img с обработчиками событий
                      "<svg",  # SVG с JavaScript
                      "<body",  # Тег body с обработчиками
                      "alert(",  # Функция alert
                      "prompt(",  # Функция prompt
                      "confirm(",  # Функция confirm
                      "eval(",  # Функция eval
                      "onerror=",  # Обработчик ошибок
                      "onload=",  # Обработчик загрузки
                      "onclick=",  # Обработчик клика
                      "onmouseover=",  # Обработчик наведения мыши
                      "javascript:",  # Псевдо-протокол javascript
                      "vbscript:",  # VBScript (старые IE)
                      "onerror%3d",  # URL-encoded onerror=
                      "alert%28"]  # URL-encoded alert(
        for sig in signatures:
            if sig in text:
                return True
        return False

    def detect_command(self, text):
        """
        Обнаруживает инъекции команд операционной системы.

        Command injection позволяет выполнять произвольные команды на сервере.

        Аргументы:
            text (str): Декодированный URL или параметры запроса

        Возвращает:
            bool: True если обнаружена command injection
        """
        # Символы, используемые для выполнения команд
        dangerous = [';',  # Разделитель команд в Linux/Windows
                     '|',  # Конвейер (pipe)
                     '&&',  # Логическое И (выполнить если первая успешна)
                     '`',  # Обратные кавычки (выполнение команды)
                     '$(']  # Подстановка команды в bash
        return any(sym in text for sym in dangerous)

    def detect_path(self, text):
        """
        Обнаруживает path traversal атаки (обход директорий).

        Path traversal позволяет читать файлы вне веб-директории сервера.

        Аргументы:
            text (str): Декодированный URL или параметры запроса

        Возвращает:
            bool: True если обнаружена path traversal атака
        """
        # Декодируем текст и приводим к нижнему регистру
        text = urllib.parse.unquote(text).lower()

        # Паттерны path traversal атак
        patterns = ["../",  # Переход на уровень выше (Unix)
                    "..\\",  # Переход на уровень выше (Windows)
                    "/etc/passwd",  # Файл с пользователями Linux
                    "/etc/shadow",  # Файл с паролями Linux
                    "c:\\windows",  # Системная папка Windows
                    "c:\\boot.ini",  # Файл загрузки Windows
                    "package.json",  # Файл Node.js проекта
                    ".env",  # Файл с переменными окружения
                    "ftp/../",  # Обход через FTP директорию
                    "..;/"]  # Обход в некоторых системах
        for pattern in patterns:
            if pattern in text:
                return True
        return False

    def detect_bruteforce(self, ip, timestamp):
        """
        Обнаруживает брутфорс атаки по множественным неудачным попыткам входа.

        Брутфорс - это перебор паролей путем многократных попыток входа.

        Аргументы:
            ip (str): IP-адрес источника
            timestamp (datetime): Время текущей попытки

        Возвращает:
            dict or None: Алерт при обнаружении брутфорса, иначе None
        """
        # Добавляем текущую попытку в историю для данного IP
        self.failed_logins[ip].append(timestamp)

        # Оставляем только попытки за последние 5 минут
        cutoff = timestamp - timedelta(minutes=5)
        self.failed_logins[ip] = [t for t in self.failed_logins[ip] if t > cutoff]

        # Если за 5 минут было 10 и более неудачных попыток - это брутфорс
        if len(self.failed_logins[ip]) >= 10:
            # Сбрасываем счетчик после обнаружения (чтобы не спамить)
            self.failed_logins[ip] = []
            return self.make_alert(ip, timestamp, "Bruteforce", "medium",
                                   "Multiple failed logins (10+ attempts in 5 minutes)",
                                   "/rest/user/login")
        return None

    def make_alert(self, ip, timestamp, type_, severity, details, url):
        """
        Создает структурированный объект алерта.

        Аргументы:
            ip (str): IP-адрес атакующего
            timestamp (datetime): Время атаки
            type_ (str): Тип атаки
            severity (str): Уровень опасности (high, medium, low)
            details (str): Детальное описание атаки
            url (str): URL запроса

        Возвращает:
            dict: Структурированный алерт для сохранения в БД
        """
        return {
            "timestamp": timestamp.isoformat(),  # Время в ISO формате
            "ip": ip,  # IP атакующего
            "type": type_,  # Тип атаки
            "severity": severity,  # Уровень опасности
            "details": details,  # Детали атаки
            "request": url,  # URL запроса
            "payload": url  # Полезная нагрузка (URL запроса)
        }


class JuiceShopScanner:
    """
    Класс для генерации тестовых атак на Juice Shop.
    Используется для проверки работы NIDS системы.
    Все методы возвращают списки словарей с информацией об атаках.
    """

    def __init__(self, juice_shop_url="http://localhost:3000"):
        """
        Инициализация сканера Juice Shop.

        Аргументы:
            juice_shop_url (str): URL адрес Juice Shop приложения
        """
        self.url = juice_shop_url

    def perform_sql_injection(self):
        """
        Выполняет SQL инъекцию через поисковый запрос.
        Используется классический payload ' OR 1=1-- для обхода условий.

        Возвращает:
            list: Список с информацией о выполненной атаке
        """
        return [{
            "method": "GET",  # HTTP метод
            "url": self.url + "/rest/products/search?q=' OR 1=1--",  # URL с SQL инъекцией
            "status": 200,  # Ожидаемый статус ответа
            "size": 512,  # Размер ответа
            "attack": "SQL Injection"  # Тип атаки
        }]

    def perform_xss_attack(self):
        """
        Выполняет XSS атаку через поисковый запрос.
        Внедряет тег img с обработчиком onerror для выполнения JavaScript.

        Возвращает:
            list: Список с информацией о выполненной атаке
        """
        return [{
            "method": "GET",
            "url": self.url + "/rest/products/search?q=<img src=x onerror=alert(1)>",
            "status": 200,
            "size": 512,
            "attack": "XSS"
        }]

    def perform_bruteforce(self):
        """
        Симулирует брутфорс атаку (неудачную попытку входа).
        Возвращает статус 401 (Unauthorized).

        Возвращает:
            list: Список с информацией о выполненной атаке
        """
        return [{
            "method": "POST",
            "url": self.url + "/rest/user/login",
            "status": 401,  # Неавторизованный доступ
            "size": 0,  # Пустой ответ
            "attack": "Bruteforce"
        }]

    def perform_path_traversal(self):
        """
        Выполняет path traversal атаку для чтения файлов вне веб-директории.
        Пытается прочитать package.json через множественный выход из директории ftp.

        Возвращает:
            list: Список с информацией о выполненной атаке
        """
        return [{
            "method": "GET",
            "url": self.url + "/ftp/../../../../package.json",
            "status": 200,
            "size": 512,
            "attack": "Path Traversal"
        }]

    def perform_command_injection(self):
        """
        Выполняет инъекцию команды ОС через поисковый запрос.
        Добавляет команду 'ls' после точки с запятой.

        Возвращает:
            list: Список с информацией о выполненной атаке
        """
        return [{
            "method": "GET",
            "url": self.url + "/rest/products/search?q=test; ls",
            "status": 200,
            "size": 512,
            "attack": "Command Injection"
        }]

    def run_attack_suite(self):
        """
        Запускает полный набор всех типов атак.
        Объединяет результаты всех методов в один список.

        Возвращает:
            list: Объединенный список всех атак
        """
        return (self.perform_sql_injection() +  # SQL инъекция
                self.perform_xss_attack() +  # XSS атака
                self.perform_bruteforce() +  # Брутфорс
                self.perform_path_traversal() +  # Path traversal
                self.perform_command_injection())  # Command injection