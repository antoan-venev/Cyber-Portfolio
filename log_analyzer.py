# Базов анализатор на логове за SOC (Security Operations Center)
# Цел: Автоматично засичане на IP адреси с неуспешни опити за вход (Brute-force атаки)

print("--- Стартиране на SOC Log Analyzer ---")
print("Сканиране на сървърните логове...\n")

# Симулирани логове от сървър (в реалност това се чете от огромен .log файл)
server_logs = [
    "10:00:01 - SUCCESS - User 'admin' logged in from 192.168.1.10",
    "10:05:22 - FAILED LOGIN - User 'root' from 203.0.113.45",
    "10:05:25 - FAILED LOGIN - User 'root' from 203.0.113.45",
    "10:06:10 - FAILED LOGIN - User 'admin' from 198.51.100.23",
    "10:15:00 - SUCCESS - User 'employee' logged in from 10.0.0.5"
]

# Създаваме празен списък, в който ще пазим подозрителните IP адреси
suspicious_ips = []

# Логиката на скрипта: проверяваме ред по ред
for log in server_logs:
    if "FAILED LOGIN" in log:
        # Разцепваме изречението на думи и взимаме последната (IP адреса)
        parts = log.split()
        ip_address = parts[-1]
        
        # Добавяме IP-то в списъка, само ако вече не е там
        if ip_address not in suspicious_ips:
            suspicious_ips.append(ip_address)

# Отпечатваме резултата
print("Открити са потенциално злонамерени IP адреси:")
for ip in suspicious_ips:
    print(f"[!] ВНИМАНИЕ: Блокирай IP -> {ip}")

print("\n--- Анализът е завършен ---")
