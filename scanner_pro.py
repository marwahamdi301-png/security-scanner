import socket
import concurrent.futures
import sys
from datetime import datetime

COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}
VULNERABILITIES = {"FTP":"[!] FTP بدون تشفير - استخدم SFTP","Telnet":"[!!] Telnet خطير جدا - استخدم SSH","SSH":"[OK] SSH آمن - تاكد من كلمة مرور قوية","HTTP":"[!] HTTP بدون تشفير - انتقل الى HTTPS","HTTPS":"[OK] HTTPS مشفر","SMB":"[!!] SMB هدف للهجمات - حدث النظام","RDP":"[!!] RDP عرضة لهجمات - فعل NLA","MySQL":"[!] قاعدة بيانات مكشوفة","PostgreSQL":"[!] قاعدة بيانات مكشوفة","Redis":"[!!] Redis بدون مصادقة - خطر كبير","MongoDB":"[!!] MongoDB عرضة للاختراق","DNS":"[i] تاكد من تعطيل Zone Transfer","SMTP":"[!] تاكد من SPF/DKIM/DMARC","POP3":"[!] قد ينقل كلمات المرور بدون تشفير","IMAP":"[!] قد ينقل كلمات المرور بدون تشفير"}

def scan_port(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except:
        return False

def main():
    print("="*50)
    print("  Vulnerability Scanner - كاشف الثغرات")
    print("  للاستخدام القانوني فقط")
    print("="*50)
    host = input("\nادخل IP او النطاق: ").strip()
    try:
        ip = socket.gethostbyname(host)
    except:
        print("خطا: لا يمكن الوصول للهدف")
        sys.exit(1)
    print(f"\nIP: {ip}")
    print(f"جاري فحص {len(COMMON_PORTS)} منفذ...\n")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in COMMON_PORTS}
        for f in concurrent.futures.as_completed(futures):
            p = futures[f]
            if f.result():
                open_ports.append(p)
                print(f"[OPEN] {p} ({COMMON_PORTS[p]})")
    print("\n" + "="*50)
    print(f"النتائج - {len(open_ports)} منفذ مفتوح:")
    for p in sorted(open_ports):
        s = COMMON_PORTS.get(p,"Unknown")
        v = VULNERABILITIES.get(s,"لا ملاحظات")
        print(f"\n  Port {p} ({s})")
        print(f"  {v}")
    print("\n" + "="*50)
    print("انتهى الفحص")

if __name__ == "__main__":
    main()
