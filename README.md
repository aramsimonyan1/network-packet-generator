## A network packet generator tool (using Python Scapy library) with a user-friendly GUI (Graphical User Interface). It lets users create and send network packets over protocols like TCP, UDP, ICMP, or ARP.

    Users can easily input details like source/destination IPs, ports, the message, and select whether to encrypt the data.
    If encryption is selected, the payload message gets securely scrambled using AES encryption before being sent.
    Depending on the chosen protocol, packets are built with specific structures (e.g., TCP/UDP has ports, ICMP and ARP don’t).
    The actual packet sending runs in a background thread, ensuring the app doesn't freeze while doing its thing.