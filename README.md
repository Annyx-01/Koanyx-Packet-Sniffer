# Koanyx-Packet-Sniffer
A lightweight, raw packet sniffer written in Python that captures and analyzes network traffic in real-time. See exactly what packets are flowing through your network with detailed protocol analysis and traffic classification.This packet sniffer is a network diagnostic tool that captures raw packets from your network interface and decodes them.
<img width="803" height="532" alt="image" src="https://github.com/user-attachments/assets/a538981e-e0dc-4462-aa1d-f632f8c396e6" />

Koanyx Packet Sniffer
This packet sniffer is like x-ray vision for your internet connection - it captures and shows you every single packet of data that passes through your network interface.
What It Actually Does
Think of it as a network surveillance camera. When you run this tool, it watches all the data flowing in and out of your computer and shows you what's happening in real time. Every time you visit a website, send an email, or even just have your computer check for updates, you'll see the packets flying by
What Makes This Useful
You can finally see what your computer is actually doing online. That mysterious network activity when you're not browsing anything? You'll see it. That app that's "phoning home"? You'll catch it. That game checking for updates? Right there in the packet stream.

The tool automatically figures out what each packet means. It knows that port 80 is web traffic, port 53 is DNS lookups, port 443 is secure browsing. It tells you whether traffic is coming into your computer, going out, or just passing through. It even separates local network chatter from real internet traffic.

How It Works Under the Hood
The sniffer creates a special kind of socket that captures everything - not just data meant for your computer, but all packets the network card sees. It then pulls apart each packet like reading the layers of an onion.

First it reads the IP header, which tells it where the packet came from and where it's going. Then it looks deeper to see if it's carrying TCP data (like web pages), UDP data (like DNS queries), or ICMP messages (like pings). For TCP packets, it even decodes the flags that show whether a connection is starting (SYN), ending (FIN), or actively transferring data (ACK).

Just open a terminal as administrator (Windows) or with sudo (Linux/Mac), navigate to the folder, and type:
python sniffer.py

This tool strips away the mystery of networking. Instead of just knowing that "the internet works," you actually see the machinery in motion. It's perfect for students trying to understand TCP/IP, developers debugging network code, or just curious folks who want to know what their computer is really doing when they're not looking.
