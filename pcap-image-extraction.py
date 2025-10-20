#!/usr/bin/env python3
# Génère password.jpg (avec le texte "UseTheForce") et capture_suspect.pcap.pcap
# Le PCAP contient : le flux TCP du JPEG (sans header HTTP), et ~30 paquets "bruit" distribués aléatoirement.
# Usage: pip install scapy pillow
# puis: python make_pcap_with_noise.py

from PIL import Image, ImageDraw, ImageFont
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap
import random, time, os

# ------------- Configuration -------------
IMAGE_NAME = "password.jpg"
PCAP_NAME = "capture_suspect.pcap"
NOISE_COUNT = 30  # nombre de trames "bruit" à insérer
MTU = 1400
MIN_GAP_MS = 10
MAX_GAP_MS = 99

# Adresses/ports pour le flux "cible"
CLIENT_IP = "192.168.1.2"
SERVER_IP = "10.10.1.254"
CLIENT_PORT = 54321
SERVER_PORT = 80
ETH_SRC = "AB:BC:CD:EF:AB:BC"
ETH_DST = "FA:AB:BC:CD:EF:FA"
CLIENT_ISN = 1000
SERVER_ISN = 2000

# ------------- Chemins absolus pour rester dans le dossier du script -------------
script_dir = os.path.dirname(os.path.abspath(__file__))
IMAGE_PATH = os.path.join(script_dir, IMAGE_NAME)
PCAP_PATH = os.path.join(script_dir, PCAP_NAME)

# ------------- Création de l'image -------------
img_w, img_h = 800, 300
img = Image.new("RGB", (img_w, img_h), color=(255,255,255))
draw = ImageDraw.Draw(img)
try:
    font = ImageFont.truetype("DejaVuSans-Bold.ttf", 72)
except Exception:
    font = ImageFont.load_default()

text = "UseTheForce"
bbox = draw.textbbox((0, 0), text, font=font)
text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
draw.text(((img_w - text_w) / 2, (img_h - text_h) / 2), text, fill=(0,0,0), font=font)

img.save(IMAGE_PATH, format="JPEG")
with open(IMAGE_PATH, "rb") as f:
    img_data = f.read()
print("[OK] Image créée :", IMAGE_PATH, len(img_data), "octets")

# ------------- Helper timing -------------
t0 = time.time()
def rand_delay_ms():
    return random.uniform(MIN_GAP_MS/1000.0, MAX_GAP_MS/1000.0)

# ------------- Construire le flux image (sans en-tête HTTP) -------------
pkts = []
t = t0

# Handshake TCP (SYN, SYN-ACK, ACK)
p1 = Ether(src=ETH_SRC,dst=ETH_DST)/IP(src=CLIENT_IP,dst=SERVER_IP)/TCP(sport=CLIENT_PORT,dport=SERVER_PORT,flags="S",seq=CLIENT_ISN)
p1.time = t; pkts.append(p1)
t += rand_delay_ms()

p2 = Ether(src=ETH_DST,dst=ETH_SRC)/IP(src=SERVER_IP,dst=CLIENT_IP)/TCP(sport=SERVER_PORT,dport=CLIENT_PORT,flags="SA",seq=SERVER_ISN,ack=CLIENT_ISN+1)
p2.time = t; pkts.append(p2)
t += rand_delay_ms()

p3 = Ether(src=ETH_SRC,dst=ETH_DST)/IP(src=CLIENT_IP,dst=SERVER_IP)/TCP(sport=CLIENT_PORT,dport=SERVER_PORT,flags="A",seq=CLIENT_ISN+1,ack=SERVER_ISN+1)
p3.time = t; pkts.append(p3)
t += rand_delay_ms()

# Optional: GET (client -> server) to make flow realistic
http_get = f"GET /{IMAGE_NAME} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"
get_pkt = Ether(src=ETH_SRC,dst=ETH_DST)/IP(src=CLIENT_IP,dst=SERVER_IP)/TCP(sport=CLIENT_PORT,dport=SERVER_PORT,flags="PA",seq=CLIENT_ISN+1,ack=SERVER_ISN+1)/Raw(load=http_get.encode())
get_pkt.time = t; pkts.append(get_pkt)
t += rand_delay_ms()

# Server ACK for GET
srv_ack = Ether(src=ETH_DST,dst=ETH_SRC)/IP(src=SERVER_IP,dst=CLIENT_IP)/TCP(sport=SERVER_PORT,dport=CLIENT_PORT,flags="A",seq=SERVER_ISN+1,ack=CLIENT_ISN+1+len(http_get))
srv_ack.time = t; pkts.append(srv_ack)
t += rand_delay_ms()

# Send JPEG payload only (no HTTP headers) in chunks
seq = SERVER_ISN + 1
acknum = CLIENT_ISN + 1 + len(http_get)
chunks = [img_data[i:i+MTU] for i in range(0, len(img_data), MTU)]
for chunk in chunks:
    pkt = Ether(src=ETH_DST,dst=ETH_SRC)/IP(src=SERVER_IP,dst=CLIENT_IP)/TCP(sport=SERVER_PORT,dport=CLIENT_PORT,seq=seq,ack=acknum,flags="PA")/Raw(load=chunk)
    pkt.time = t
    pkts.append(pkt)
    seq += len(chunk)
    t += rand_delay_ms()

# FIN/ACK to close
fin = Ether(src=ETH_DST,dst=ETH_SRC)/IP(src=SERVER_IP,dst=CLIENT_IP)/TCP(sport=SERVER_PORT,dport=CLIENT_PORT,seq=seq,ack=acknum,flags="FA")
fin.time = t; pkts.append(fin)
t += rand_delay_ms()
ack_fin = Ether(src=ETH_SRC,dst=ETH_DST)/IP(src=CLIENT_IP,dst=SERVER_IP)/TCP(sport=CLIENT_PORT,dport=SERVER_PORT,seq=acknum,ack=seq+1,flags="A")
ack_fin.time = t; pkts.append(ack_fin)
t += rand_delay_ms()

# ------------- Générer du "bruit" (paquets aléatoires) -------------
noise_pkts = []
def rand_ip():
    return "{}.{}.{}.{}".format(random.randint(11,223), random.randint(1,254), random.randint(1,254), random.randint(1,254))

for i in range(NOISE_COUNT):
    choice = random.choice(["udp","icmp","tcp_syn","tcp_data"])
    src = rand_ip()
    dst = rand_ip()
    if src in (CLIENT_IP, SERVER_IP): src = "203.0.113." + str(random.randint(1,250))
    if dst in (CLIENT_IP, SERVER_IP): dst = "198.51.100." + str(random.randint(1,250))

    noise_time = t0 + random.uniform(0, max(0.001, (t - t0)))
    if choice == "udp":
        sport = random.randint(1025, 65500)
        dport = random.randint(1, 65535)
        payload = os.urandom(random.randint(10, 200))
        pkt = Ether()/IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/Raw(load=payload)
    elif choice == "icmp":
        payload = os.urandom(random.randint(4, 100))
        pkt = Ether()/IP(src=src,dst=dst)/ICMP(type=8)/Raw(load=payload)
    elif choice == "tcp_syn":
        sport = random.randint(1025, 65500)
        dport = random.randint(1, 65535)
        pkt = Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="S",seq=random.randint(1000,1000000))
    else:  # tcp_data
        sport = random.randint(1025, 65500)
        dport = random.randint(1, 65535)
        payload = os.urandom(random.randint(5, 300))
        pkt = Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=random.randint(1000,1000000))/Raw(load=payload)

    pkt.time = noise_time
    noise_pkts.append(pkt)

# ------------- Fusionner, trier par timestamp et écrire le PCAP -------------
all_pkts = pkts + noise_pkts
all_pkts.sort(key=lambda p: getattr(p, "time", 0.0))

wrpcap(PCAP_PATH, all_pkts)
print(f"[OK] PCAP créé : {PCAP_PATH} ({len(all_pkts)} paquets : {len(pkts)} image-related, {len(noise_pkts)} noise)")
print("Pour extraire l'image : Wireshark -> Follow TCP Stream (flux ciblé) -> Show as raw bytes -> Save as .jpg")
