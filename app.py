from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime
import sqlite3
import os
import requests
import threading
import time
from nids_analyzer import NIDSAnalyzer, JuiceShopScanner

# Инициализация Flask приложения
app = Flask(__name__)

# Получаем URL Juice Shop из переменной окружения или используем значение по умолчанию
# nginx:80 - это имя сервиса в Docker сети
JUICE_SHOP_URL = os.getenv('JUICE_SHOP_URL', 'http://nginx:80')

# Создаем экземпляры классов для анализа атак и генерации тестовых атак
analyzer = NIDSAnalyzer()  # Анализатор для обнаружения атак в логах
juice_scanner = JuiceShopScanner(JUICE_SHOP_URL)  # Генератор тестовых атак

# Пути к файлам логов
LOG_FILE = 'access.log'  # Локальный файл логов
NGINX_LOG = '/app/logs/access.log'  # Путь к логам nginx внутри Docker контейнера

# Создаем пустой файл логов, если он не существует
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        f.write('')


def init_db():
    """
    Инициализация базы данных SQLite.
    Создает таблицу alerts для хранения обнаруженных атак.
    """
    # Подключаемся к базе данных (файл nids.db создастся автоматически)
    conn = sqlite3.connect('nids.db')
    c = conn.cursor()

    # Создаем таблицу alerts, если она еще не существует
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  # Уникальный идентификатор
        timestamp TEXT,                         # Время обнаружения атаки
        src_ip TEXT,                            # IP-адрес источника атаки
        attack_type TEXT,                       # Тип атаки (SQL injection, XSS и т.д.)
        severity TEXT,                          # Уровень опасности (high, medium, low)
        details TEXT,                           # Детальное описание атаки
        status TEXT DEFAULT 'new',              # Статус обработки (new, reviewed)
        payload TEXT                            # Полезная нагрузка атаки
    )''')

    # Проверяем, существует ли колонка payload (для обратной совместимости)
    c.execute("PRAGMA table_info(alerts)")
    columns = [col[1] for col in c.fetchall()]
    if 'payload' not in columns:
        # Добавляем колонку payload, если её нет
        c.execute("ALTER TABLE alerts ADD COLUMN payload TEXT")

    # Сохраняем изменения и закрываем соединение
    conn.commit()
    conn.close()


# Вызываем инициализацию базы данных при старте приложения
init_db()


def write_to_log(log_line):
    """
    Записывает строку лога в файл и анализирует её на наличие атак.

    Аргументы:
        log_line (str): Строка лога для записи и анализа

    Возвращает:
        bool: True если операция успешна, False в случае ошибки
    """
    try:
        # Открываем файл логов в режиме добавления (append)
        with open(LOG_FILE, 'a') as f:
            f.write(log_line + '\n')  # Записываем строку
            f.flush()  # Принудительно сбрасываем буфер на диск

        # Анализируем лог на наличие атак с помощью NIDSAnalyzer
        alerts = analyzer.analyze_log(log_line)

        # Сохраняем каждое обнаруженное предупреждение в базу данных
        for alert in alerts:
            save_alert(alert)
        return True
    except Exception as e:
        print(f"Log write error: {e}")
        return False


def save_alert(alert):
    """
    Сохраняет информацию об обнаруженной атаке в базу данных.

    Аргументы:
        alert (dict): Словарь с данными об атаке, содержащий:
            - ip: IP-адрес атакующего
            - type: тип атаки
            - severity: уровень опасности
            - details: описание атаки
            - payload: полезная нагрузка (опционально)

    Возвращает:
        bool: True если сохранение успешно, False в случае ошибки
    """
    try:
        # Подключаемся к базе данных
        conn = sqlite3.connect('nids.db')
        c = conn.cursor()

        # Вставляем данные о атаке в таблицу alerts
        c.execute('''INSERT INTO alerts (timestamp, src_ip, attack_type, severity, details, payload)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (datetime.now().isoformat(),  # Текущее время в ISO формате
                   alert['ip'],  # IP атакующего
                   alert['type'],  # Тип атаки
                   alert['severity'],  # Уровень опасности
                   alert['details'],  # Детали атаки
                   alert.get('payload', '')))  # Payload (если нет - пустая строка)

        # Сохраняем изменения и закрываем соединение
        conn.commit()
        conn.close()
        print(f"✅ Alert saved: {alert['type']} from {alert['ip']}")
        return True
    except Exception as e:
        print(f"DB error: {e}")
        return False


# ===== МОНИТОРИНГ ЛОГОВ NGINX =====

# Глобальная переменная для хранения последней прочитанной позиции в файле логов
# Это позволяет читать только новые строки при каждом обновлении
last_log_position = 0


def read_nginx_logs():
    """
    Читает новые строки из лог-файла nginx.
    Использует глобальную переменную last_log_position для отслеживания позиции.
    Каждая новая строка отправляется на анализ в write_to_log().
    """
    global last_log_position  # Используем глобальную переменную
    try:
        # Проверяем, существует ли файл логов nginx
        if os.path.exists(NGINX_LOG):
            # Открываем файл для чтения
            with open(NGINX_LOG, 'r') as f:
                # Перемещаемся к последней прочитанной позиции
                f.seek(last_log_position)
                # Читаем все новые строки
                new_lines = f.readlines()
                # Сохраняем новую позицию для следующего чтения
                last_log_position = f.tell()

                # Обрабатываем каждую новую строку лога
                for line in new_lines:
                    line = line.strip()  # Удаляем лишние пробелы и переносы строк
                    if line:  # Если строка не пустая
                        print(f"📝 Processing log: {line[:100]}...")
                        write_to_log(line)  # Отправляем на анализ
    except Exception as e:
        print(f"Error reading nginx logs: {e}")


def periodic_log_reader():
    """
    Фоновый поток, который периодически проверяет новые записи в логах nginx.
    Запускается в отдельном потоке и работает бесконечно.
    """
    while True:
        read_nginx_logs()  # Читаем новые логи
        time.sleep(2)  # Пауза 2 секунды между проверками


# Запускаем фоновый поток мониторинга логов
# daemon=True означает, что поток завершится при завершении основного приложения
threading.Thread(target=periodic_log_reader, daemon=True).start()
print("✅ Мониторинг логов nginx запущен")


# ===== API ENDPOINTS =====

@app.route('/')
def index():
    """
    Главная страница веб-интерфейса.
    Возвращает HTML шаблон dashboard'а NIDS.
    """
    return render_template('index.html')


@app.route('/api/alerts')
def get_alerts():
    """
    API endpoint для получения списка всех предупреждений.

    Возвращает:
        JSON: Список последних 200 алертов, отсортированных по времени (новые сверху)
    """
    # Подключаемся к базе данных
    conn = sqlite3.connect('nids.db')
    c = conn.cursor()

    # Получаем последние 200 записей из таблицы alerts, сортируем по убыванию времени
    c.execute(
        'SELECT timestamp, src_ip, attack_type, severity, details, status, payload FROM alerts ORDER BY timestamp DESC LIMIT 200')

    # Преобразуем результат в список словарей для удобной работы с JSON
    alerts = []
    for row in c.fetchall():
        alerts.append({
            'timestamp': row[0],  # Время атаки
            'src_ip': row[1],  # IP источник
            'attack_type': row[2],  # Тип атаки
            'severity': row[3],  # Уровень опасности
            'details': row[4],  # Детали
            'status': row[5],  # Статус обработки
            'payload': row[6] or ''  # Payload (если None - пустая строка)
        })

    conn.close()
    return jsonify(alerts)  # Возвращаем JSON ответ


@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    """
    API endpoint для очистки всех алертов и логов.
    Метод: POST

    Возвращает:
        JSON: Статус операции и сообщение об успехе или ошибке
    """
    try:
        # Удаляем все записи из таблицы alerts
        conn = sqlite3.connect('nids.db')
        c = conn.cursor()
        c.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()

        # Очищаем файл логов (перезаписываем пустым содержимым)
        with open(LOG_FILE, 'w') as f:
            f.write('')

        return jsonify({'status': 'success', 'message': 'Все алерты и логи удалены'})
    except Exception as e:
        # В случае ошибки возвращаем код 500 (Internal Server Error)
        return jsonify({'error': str(e)}), 500


@app.route('/api/juice-shop/attack', methods=['POST'])
def attack_juice_shop():
    """
    API endpoint для запуска различных типов атак на Juice Shop.
    Метод: POST
    Ожидает JSON с полем 'type', которое может быть:
        - 'sql': SQL инъекция
        - 'xss': XSS атака
        - 'bruteforce': Брутфорс паролей
        - 'path_traversal': Path traversal
        - 'command_injection': Command injection
        - 'all': Все типы атак (значение по умолчанию)

    Возвращает:
        JSON: Результаты выполнения атак и количество созданных логов
    """
    try:
        # Получаем тип атаки из JSON тела запроса, по умолчанию 'all'
        attack_type = request.json.get('type', 'all')

        # Выполняем соответствующий тип атаки через JuiceShopScanner
        if attack_type == 'sql':
            results = juice_scanner.perform_sql_injection()
        elif attack_type == 'xss':
            results = juice_scanner.perform_xss_attack()
        elif attack_type == 'bruteforce':
            results = juice_scanner.perform_bruteforce()
        elif attack_type == 'path_traversal':
            results = juice_scanner.perform_path_traversal()
        elif attack_type == 'command_injection':
            results = juice_scanner.perform_command_injection()
        else:  # 'all'
            results = juice_scanner.run_attack_suite()

        # Генерируем временную метку в формате логов Apache
        timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0300')
        log_count = 0  # Счетчик созданных логов

        # Создаем записи в логах для каждой выполненной атаки
        for res in results:
            ip = '127.0.0.1'  # IP источника атаки (локальный)
            method = res.get('method', 'GET')  # HTTP метод

            # Формируем путь URL из полного URL
            if 'url' in res:
                full_url = res['url']
                # Убираем базовый URL, оставляем только путь и параметры
                path_and_params = full_url.replace(JUICE_SHOP_URL, '')
                if not path_and_params:
                    path_and_params = '/'
            else:
                # Для брутфорса используем путь логина
                path_and_params = '/rest/user/login' if res.get('attack') == 'Bruteforce' else '/'

            status = res.get('status', 200)  # HTTP статус ответа
            size = res.get('size', 0)  # Размер ответа

            # Формируем строку лога в формате Combined Log Format
            log_line = f'{ip} - - [{timestamp}] "{method} {path_and_params} HTTP/1.1" {status} {size} "-" "JuiceShop-Attacker"'

            # Записываем лог и увеличиваем счетчик при успехе
            if write_to_log(log_line):
                log_count += 1

        # Для брутфорса добавляем дополнительные неудачные попытки входа
        # Это необходимо для срабатывания детектора брутфорса (10+ попыток)
        if attack_type == 'bruteforce' or attack_type == 'all':
            for _ in range(12):  # Добавляем 12 неудачных попыток
                log_line = f'127.0.0.1 - - [{timestamp}] "POST /rest/user/login HTTP/1.1" 401 0 "-" "JuiceShop-Attacker"'
                write_to_log(log_line)
                log_count += 1

        # Возвращаем успешный ответ с информацией о выполненых атаках
        return jsonify({'status': 'success', 'attacks_performed': len(results), 'logs_added': log_count})
    except Exception as e:
        # В случае ошибки возвращаем код 500
        return jsonify({'error': str(e)}), 500


@app.route('/api/juice-shop/status', methods=['GET'])
def juice_shop_status():
    """
    API endpoint для проверки статуса Juice Shop.
    Метод: GET

    Возвращает:
        JSON: Статус сервера ('running', 'error', 'stopped') и его URL
    """
    try:
        # Пытаемся выполнить GET запрос к Juice Shop с таймаутом 2 секунды
        resp = requests.get(JUICE_SHOP_URL, timeout=2)
        # Если статус ответа 200 - сервер работает, иначе ошибка
        status = 'running' if resp.status_code == 200 else 'error'
    except:
        # Если соединение не установлено - сервер остановлен
        status = 'stopped'

    return jsonify({'status': status, 'url': 'http://localhost:3000'})


@app.route('/api/health')
def health():
    """
    API endpoint для проверки работоспособности NIDS системы.
    Метод: GET

    Возвращает:
        JSON: Статус системы, общее количество алертов и текущая временная метка
    """
    # Получаем общее количество записей в таблице alerts
    conn = sqlite3.connect('nids.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM alerts')
    alert_count = c.fetchone()[0]  # Извлекаем значение из результата
    conn.close()

    # Возвращаем информацию о состоянии системы
    return jsonify({
        'status': 'healthy',  # Статус системы
        'alerts_count': alert_count,  # Количество алертов в БД
        'timestamp': datetime.now().isoformat()  # Текущее время
    })


# ===== ЗАПУСК ПРИЛОЖЕНИЯ =====
if __name__ == '__main__':
    # Выводим информацию о запуске системы в консоль
    print("=" * 60)
    print("🛡️ NIDS System Starting...")
    print("📁 Web Interface: http://localhost:5000")
    print("🍹 Juice Shop: http://localhost:3000")
    print("🌐 Прокси: http://localhost:5000/proxy/")
    print("📝 Реальные IP-адреса клиентов отображаются в Dashboard!")
    print("=" * 60)

    # Запускаем Flask сервер
    # host='0.0.0.0' - слушаем все сетевые интерфейсы (доступно извне)
    # port=5000 - стандартный порт Flask
    # debug=False - отключаем debug режим (для production)
    app.run(host='0.0.0.0', port=5000, debug=False)