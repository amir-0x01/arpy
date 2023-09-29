# arpy
ARP Spoofing tool created my memset-0x00

![image](https://user-images.githubusercontent.com/56231894/151802480-28f0b113-53d4-40e6-8f49-96faa1e7501a.png)

sudo python3 arpy.py [iface] [target] [gateway] [outfile]
                      OR
sudo python3 arpy.py (to access cli)

Requires sudo to work !

ARP poisoning attacks often make use of Gratuitous ARP (Address Resolution Protocol) to facilitate their malicious activities. ARP poisoning, also known as ARP spoofing, is a type of cyber attack in which an attacker sends falsified or malicious ARP packets onto a local area network to associate their MAC address with the IP address of another host, typically the default gateway or a target host. Gratuitous ARP packets can be used at various stages of such an attack:

    Initial ARP Spoofing Setup: In an ARP poisoning attack, the attacker typically starts by sending out Gratuitous ARP packets to inform all hosts on the network that their MAC address is associated with the IP address of the target host. This causes the local ARP caches of the other hosts to update with the attacker's MAC address as the legitimate one for the target IP address.

    Maintaining the Attack: Once the initial ARP poisoning setup is complete, the attacker can continue to periodically send Gratuitous ARP packets to maintain the deception. By doing so, the attacker ensures that the ARP caches of other hosts on the network continue to associate their MAC address with the target's IP address.

    Stealing Data: With ARP poisoning successfully in place, the attacker can intercept and potentially modify network traffic passing between the target host and other hosts on the network. This allows the attacker to capture sensitive information, such as login credentials, and potentially launch man-in-the-middle attacks.

Gratuitous ARP is a useful tool for ARP poisoning attacks because it allows the attacker to quickly and efficiently update the ARP caches of all hosts on the network, making it easier to intercept and manipulate network traffic without raising immediate suspicion.
