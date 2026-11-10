print("--- Стартиране на SOC Log Analyzer (Ниво 2) ---")

malicious_ips = []

# Отваряме външния лог файл в режим на четене ('r' - read)
with open('server.log', 'r') as file:
    for line in file:
        if "FAILED LOGIN" in line:
            # Разделяме реда на отделни думи и взимаме последната (IP адреса)
            ip_address = line.split()[-1]
            
            if ip_address not in malicious_ips:
                malicious_ips.append(ip_address)

print("Открити са потенциално злонамерени IP адреси:")
for ip in malicious_ips:
    print(f"[!] ВНИМАНИЕ: Блокирай IP -> {ip}")


