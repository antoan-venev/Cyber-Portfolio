import requests
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)


print("--- Стартиране на SOC Log Analyzer (Ниво 3: Threat Intelligence) ---")

malicious_ips = []

# Четене на лог файла (както в Ниво 2)
with open('server.log', 'r') as file:
    for line in file:
        if "FAILED LOGIN" in line:
            ip_address = line.split()[-1]
            if ip_address not in malicious_ips:
                malicious_ips.append(ip_address)

print(f"Открити са {len(malicious_ips)} подозрителни адреса. Започва проверка в AbuseIPDB...\n")

# --- THREAT INTELLIGENCE ИНТЕГРАЦИЯ ---
API_KEY = '61e61446b898d704db3c3a5af96b8c7b37361f3ba0f6e1bc52c886e24571e1d50155f4e55986aece' # <-- Постави своя ключ тук!
API_URL = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# Проверяваме всяко намерено IP в базата данни
for ip in malicious_ips:
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90' # Търсим данни за атаки от последните 90 дни
    }
    
    try:
        # Изпращане на заявката през интернет
        response = requests.get(url=API_URL, headers=headers, params=querystring)
        
        # Ако сървърът върне статус 200 (ОК - успешно)
        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']
            country = data['data']['countryCode']
            
            print(f"[!] Резултат за IP: {ip}")
            print(f"    - Държава: {country}")
            print(f"    - Рисков рейтинг (Abuse Score): {score}%")
            
            if score > 0:
                print("    -> ЗАКЛЮЧЕНИЕ: ВНИМАНИЕ! Това IP е докладвано от други компании!\n")
            else:
                print("    -> ЗАКЛЮЧЕНИЕ: Засега това IP изглежда чисто.\n")
        else:
            print(f"Грешка при проверка на {ip}: Status {response.status_code}")
            
    except Exception as e:
        print(f"Възникна проблем при връзката: {e}")

print("--- Анализът е завършен ---")



