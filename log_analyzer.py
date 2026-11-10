import requests
import urllib3
import csv # НОВО: Вграден модул за създаване на CSV таблици

# Скриваме системното предупреждение за Mac
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

print("--- Стартиране на SOC Log Analyzer (Ниво 4: CSV Експорт) ---")

malicious_ips = []

# 1. Четене на лог файла
with open('server.log', 'r') as file:
    for line in file:
        if "FAILED LOGIN" in line:
            ip_address = line.split()[-1]
            if ip_address not in malicious_ips:
                malicious_ips.append(ip_address)

print(f"Открити са {len(malicious_ips)} подозрителни адреса. Генериране на доклад...\n")

# 2. Подготовка за Threat Intelligence
API_KEY = '61e61446b898d704db3c3a5af96b8c7b37361f3ba0f6e1bc52c886e24571e1d50155f4e55986aece' # <-- Постави своя ключ тук!
API_URL = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# 3. НОВО: Създаваме и отваряме нов CSV файл за записване ('w' - write)
with open('threat_report.csv', 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    
    # Записваме заглавния ред на таблицата
    writer.writerow(['IP Address', 'Country', 'Abuse Score', 'Status'])

    # Проверяваме всяко IP и записваме резултата директно в таблицата
    for ip in malicious_ips:
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            response = requests.get(url=API_URL, headers=headers, params=querystring)
            
            if response.status_code == 200:
                data = response.json()
                score = data['data']['abuseConfidenceScore']
                country = data['data']['countryCode']
                
                # Определяме статуса въз основа на рейтинга
                status = "MALICIOUS (BLOCKED)" if score > 0 else "CLEAN"
                
                # Записваме данните за това IP като нов ред в таблицата
                writer.writerow([ip, country, f"{score}%", status])
                
                print(f"[+] Успешно анализирано и записано IP: {ip}")
            else:
                print(f"[-] Грешка при проверка на {ip}: Status {response.status_code}")
                
        except Exception as e:
            print(f"[-] Възникна проблем при връзката: {e}")

print("\n--- Анализът е завършен! Резултатите са запазени в 'threat_report.csv' ---")
