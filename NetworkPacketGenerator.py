import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import IP, TCP, UDP, ICMP, ARP, send
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
  
# Function to encrypt data using AES (Advanced Encryption Standard)
# Ensures the confidentiality of the payload before sending it within the network.
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))                # Create a new AES cipher in CBC (Cipher Block Chaining) mode with a random initialization vector (IV).
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))   # Encrypt the data and pad it to ensure it aligns with AES block size.
    return cipher.iv + encrypted_data                                     # Return the IV prepended to the encrypted data for later decryption.

# Function to craft and send a network packet based on the selected protocol (supports TCP, UDP, ICMP, and ARP protocols).
""" Parameters:
    - protocol (str): The protocol to use ("TCP", "UDP", "ICMP", "ARP").
    - src_ip (str): Source IP address of the packet.
    - dst_ip (str): Destination IP address of the packet.
    - src_port (int, optional): Source port number (used for TCP and UDP).
    - dst_port (int, optional): Destination port number (used for TCP and UDP packets).
    - message (str, optional): Message to include as payload (TCP/UDP ony). 
    - encrypt (bool): Whether to encrypt the payload."""
def send_packet(protocol, src_ip, dst_ip, src_port, dst_port, message, encrypt):
    key = os.urandom(16)                             # Generate a random 16-byte encryption key for AES.
    if encrypt:                                      # If encryption is enabled, encrypt the payload message.
        message = encrypt_data(message, key)

    packet = IP(src=src_ip, dst=dst_ip)              # Start crafting the base packet with IP headers.

    # Add specific protocol layers based on the selected protocol.
    if protocol == "TCP":                            # Transmission Control Protocol for reliable communication.
        packet /= TCP(sport=int(src_port), dport=int(dst_port)) / message
    elif protocol == "UDP":                          # User Datagram Protocol for lightweight communication.
        packet /= UDP(sport=int(src_port), dport=int(dst_port)) / message
    elif protocol == "ICMP":                         # Internet Control Message Protocol (e.g., ping).
        packet = IP(src=src_ip, dst=dst_ip) / ICMP() # ICMP does not use ports or payloads.
    elif protocol == "ARP":                          # Address Resolution Protocol (IP to MAC resolution).
        packet = ARP(pdst=dst_ip)                    # ARP operates at the network layer and does not use IP headers.
    else:
        messagebox.showerror("Error", "Unsupported Protocol")   # Display an error message if an unsupported protocol is selected.
        return
    
    send(packet, verbose=False)                      # Send the constructed packet over the network without verbose output.
    messagebox.showinfo("Success", "Packet Sent Successfully") # Display a success message after sending the packet.

# Function to start sending packets in a separate thread to prevent GUI freezing.
def start_sending():
    # Retrieve user-selected options from the GUI fields.
    protocol = protocol_var.get()
    src_ip = src_ip_entry.get()
    dst_ip = dst_ip_entry.get()
    src_port = src_port_entry.get()
    dst_port = dst_port_entry.get()
    message = message_entry.get()
    encrypt = encrypt_var.get()
    
    # Launch the send_packet function in a new thread for asynchronous execution.
    threading.Thread(target=send_packet, args=(protocol, src_ip, dst_ip, src_port, dst_port, message, encrypt), daemon=True).start()

# Set up the GUI for the network packet generator.
root = tk.Tk()
root.title("Network Packet Generator")               # Set the title of the main window.

# Dropdown for selecting the protocol type (TCP, UDP, ICMP, ARP).
protocol_var = tk.StringVar(value="TCP")             # Default protocol is TCP.
tk.Label(root, text="Protocol:").grid(row=0, column=0)
ttk.Combobox(root, textvariable=protocol_var, values=["TCP", "UDP", "ICMP", "ARP"]).grid(row=0, column=1)

# Input field for the source IP address.
src_ip_entry = tk.Entry(root)
tk.Label(root, text="Source IP:").grid(row=1, column=0)
src_ip_entry.grid(row=1, column=1)

# Input field for the destination IP address.
dst_ip_entry = tk.Entry(root)
tk.Label(root, text="Destination IP:").grid(row=2, column=0)
dst_ip_entry.grid(row=2, column=1)

# Input field for the source port (only for TCP/UDP).
src_port_entry = tk.Entry(root)
tk.Label(root, text="Source Port:").grid(row=3, column=0)
src_port_entry.grid(row=3, column=1)

# Input field for the destination port (only for TCP/UDP).
dst_port_entry = tk.Entry(root)
tk.Label(root, text="Destination Port:").grid(row=4, column=0)
dst_port_entry.grid(row=4, column=1)

# Input field for the message payload (only for TCP/UDP).
tk.Label(root, text="Message:").grid(row=5, column=0)
message_entry = tk.Entry(root)
message_entry.grid(row=5, column=1)

# Checkbox for enabling encryption of the payload message.
encrypt_var = tk.BooleanVar()                        # Boolean value for encryption toggle.
tk.Checkbutton(root, text="Encrypt Payload", variable=encrypt_var).grid(row=6, columnspan=2)

# Button to send the packet based on user input.
tk.Button(root, text="Send Packet", command=start_sending).grid(row=7, columnspan=2)

# Start the GUI main loop to keep the window running.
root.mainloop()