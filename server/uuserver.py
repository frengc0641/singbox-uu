import socket
import threading
import struct
import queue
import time
import select
import random
import os
import sys
import ctypes
import ctypes.util
import hashlib
DEBUG = 0
# 配置
LISTEN_ADDR = ('0.0.0.0', 8888)
lib_name = ctypes.util.find_library('sodium') or ctypes.util.find_library('libsodium')
if not lib_name: raise OSError("找不到 libsodium")
sodium = ctypes.cdll.LoadLibrary(lib_name)

KEY_BYTES, NONCE_BYTES = 32, 8
def chacha20_sodium(data, key, nonce):
    ciphertext = ctypes.create_string_buffer(len(data))
    # 呼叫 crypto_stream_chacha20_xor
    res = sodium.crypto_stream_chacha20_xor(
        ciphertext, data, ctypes.c_ulonglong(len(data)), nonce, key
    )
    if res != 0: raise RuntimeError("加密/解密失敗")
    return ciphertext.raw

class RemoteServer:
    def __init__(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(LISTEN_ADDR)
        self.udpqueRX = {}  # {session_id: tcp_socket}
        self.udpqueRXraw = queue.Queue()
        self.tcpsock_l = {}
        self.client_addr = None
        self.udpqueTX = queue.Queue()
        self.udptx_c = queue.Queue()
        self.tcprx_lock = threading.Lock()
        self.udpTX_Byte = 1
        self.udpRX_Byte = 1
        self.udpTX_seq = 0
        self.udpRX_seq = 0
        self.udpTX_buffer = {}
        self.udprecv_pack = {}
        self.udpTX_readyseq = 0
        self.lose_pack_seq = 0
        self.last_seq = 0
        self.loss_request_grace = 0.18
        self.loss_retry_base = 0.45
        self.loss_retry_max = 3.0
        self.loss_max_retry = 6
        self.loss_skip_after = 8.0
        self.loss_batch_size = 160
        self.Client_change = 1

        self.mtu_udp = 1380
        self.tcpbuf = self.mtu_udp * 100
        self.Min_speed = 1 * 1000000
        self.Init_speed = 4.5 * 1000000 # setting speed
        self.Byte_Bit = 8
        self.UDP_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit
        self.windows = 4
        self.speedCtr_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit * self.windows
        self.tt = 0
        self.chacha_key = hashlib.sha256('ch0641ng'.encode()).digest()

        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.mtu_udp*1000000)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.mtu_udp*1000000)

    def send_to_client(self, session_id, msg_type, payload):
        #msg_type 0:Start VPN 1:New session 2:Data 3:Close 4:Ack 5: Resend
        with self.tcprx_lock:
            if self.client_addr != None:
                if msg_type == 2:
                    self.udpTX_buffer[self.udpTX_seq] = [session_id, msg_type, payload]
                    current_seq = self.udpTX_seq
                    #print(f'[{session_id}]  [{payload[:10]}]')
                    if len(self.udpTX_buffer) > 150000:
                        self.udpTX_buffer.pop(self.udpTX_readyseq, None)
                        self.udpTX_readyseq += 1
                    self.udpTX_seq += 1
                    if 0:#msg_type == 2 and random.randint(1, 500) == 25:
                        pass
                    else:
                        self.encrypt_send_to_client(current_seq, session_id, msg_type, payload)
                elif msg_type == 0 or msg_type == 1 or msg_type == 3 or msg_type == 4 or msg_type == 5:
                    current_seq = 0
                    self.encrypt_send_to_client(current_seq, session_id, msg_type, payload, False)
                elif msg_type == 6: # Resend 
                    payload_list = []
                    while len(payload) > 0:
                        lose_seq = struct.unpack('!I', payload[:4])[0]
                        if lose_seq in self.udpTX_buffer:
                            current_seq = lose_seq
                            session_id, msg_type, resend_payload = self.udpTX_buffer[current_seq]
                            self.encrypt_send_to_client(current_seq, session_id, msg_type, resend_payload, False)
                        elif DEBUG:
                            print(f'[Resend miss]\t{lose_seq}')

                        payload_list.append(lose_seq)
                        payload = payload[4:]
                    if DEBUG: print(f'[Resend] {payload_list}')
            else:
                time.sleep(1)
    def encrypt_send_to_client(self, current_seq, session_id, msg_type, payload, rate_limit=True):
        if rate_limit:
            self.udptx_c.get()
        try:
            nonce = os.urandom(8)
            header = struct.pack('!IHB', current_seq, session_id, msg_type)
            checksum = hashlib.blake2b(header, digest_size=1).digest()
            encrypt_header =  chacha20_sodium(header + checksum, self.chacha_key, nonce)
            packet = nonce + encrypt_header + chacha20_sodium(payload, self.chacha_key, nonce)
            self.udp_sock.sendto(packet, self.client_addr)
            self.udpTX_Byte += len(packet)
        except Exception as e:
            if DEBUG: print(f"encrypt_send_to_client: {e}")
            pass


    def handle_client(self, session_id, payload):
        address_type = payload[0] # 網域
        if address_type == 3:
            domain_len = payload[1]
            target_ip = payload[2:2+domain_len].decode()
            target_port = struct.unpack('!H', payload[2+domain_len:4+domain_len])[0]
        elif address_type == 1: # IP # 簡單解析 IPv4 位址: [4b IP][2b Port]
            target_ip = socket.inet_ntoa(payload[1:5])
            target_port = struct.unpack('!H', payload[5:7])[0]

        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(2)
        try:
            tcp_sock.connect((target_ip, target_port))
            self.send_to_client(session_id, 0x02, b"\x05\x00" + os.urandom(random.randint(64, 1188)))
        except Exception as e:
            if DEBUG: print(f"handle_client: {e}")
            self.send_to_client(session_id, 0x02, b"\x05\x01" + os.urandom(random.randint(64, 1188)))
            print(f"[{session_id}]\t[連線失敗]")
            return
        if DEBUG: print(f"[{session_id}]\t[Open] {target_ip}:{target_port}")
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.tcpbuf)
        self.udpqueRX[session_id] = queue.Queue()
        self.tcpsock_l[tcp_sock] = session_id
        self.Client_change = 1
        while True:
            try:
                payload = self.udpqueRX[session_id].get(block=True, timeout=600)
                if payload == None or session_id not in self.udpqueRX: break
                tcp_sock.sendall(payload)
                self.udpTX_Byte += len(payload)
            except Exception as e:
                if DEBUG: print(f"handle_client 2: {e}")
                self.send_to_client(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                if DEBUG: print (f'[{session_id}]\t[Close Timeout 1]')
                break
        self.udpqueRX.pop(session_id, None)
        self.Client_change = 1        
        return

    def handle_to_Local(self):
        """讀取目標網站回傳的資料，轉發回 Client"""
        while True:
            if len(self.tcpsock_l) > 0:
                if self.Client_change == 1:
                    self.Client_change = 0
                    for sock, session_id in list(self.tcpsock_l.items()):
                        if session_id not in self.udpqueRX:
                            sock.close()
                            self.tcpsock_l.pop(sock, None)
                            if DEBUG: print (f'[{session_id}]\t[Close Client]')

                tcprx_list = list(self.tcpsock_l.keys())
                if len(tcprx_list) > 0:
                    tcpR_ready, tcpW_ready, tcp_error = select.select(tcprx_list, [], tcprx_list, self.UDP_delay)
                    for i_sock in tcpR_ready:
                        session_id = self.tcpsock_l[i_sock]
                        try:
                            if random.random() < 0.8:
                                mtu_random = int(random.gauss(self.mtu_udp-50,49))
                                if mtu_random > self.mtu_udp:
                                    mtu_random = self.mtu_udp
                            else:
                                mtu_random = int(random.gauss(self.mtu_udp-800,50))
                            data = i_sock.recv(mtu_random)
                            if not data:
                                i_sock.close()
                                self.tcpsock_l.pop(i_sock, None)
                                if session_id in self.udpqueRX:
                                    self.udpqueRX[session_id].put(None)
                                self.send_to_client(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                                if DEBUG: print (f'[{session_id}]\t[Close Remote]')
                            else:
                                self.send_to_client(session_id, 0x02, data)
                        except Exception as e:
                            print(f"handle_to_Local: {e}")
                            self.send_to_client(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                            i_sock.close()
                            self.tcpsock_l.pop(i_sock, None)
                            if session_id in self.udpqueRX:
                                self.udpqueRX[session_id].put(None)
                            if DEBUG: print (f'[{session_id}]\t[Close Timeout]')
                            pass
            else:
                time.sleep(0.1)

    def handle_speed_udptx(self):
        while True:
            time.sleep(self.speedCtr_delay)

            for i in range(self.windows - self.udptx_c.qsize()):
                self.udptx_c.put(0)
            #if self.udptx_c.qsize() <= self.windows:
            #    self.udptx_c.put(0)

    def handle_status(self):
        last_time = time.time()
        while True:
            time.sleep(1)
            if self.tt >= 10:
                time_w = time.time() - last_time
                last_time = time.time()
                print ()
                print (f'[Status][{len(self.udpqueRX)}]\t[{self.udpRX_seq}][{self.udpTX_seq}]\tTX={self.udpTX_Byte*self.Byte_Bit/time_w/1000:,.0f} Kbs RX={self.udpRX_Byte*self.Byte_Bit/time_w/1000:,.0f} Kbs [ {self.Init_speed/1000:.2f} Kbs ]  ')
                print ()

                self.UDP_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit
                self.speedCtr_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit * self.windows
                self.udpTX_Byte = 1
                self.udpRX_Byte = 1
                self.tt = 0
            self.tt += 1
    def handle_lose(self):
        lose_seq = {}
        while True:#self.client_addr != None:
            lose_seq_list = b''
            now = time.time()
            if self.udpRX_seq < self.last_seq:
                grace = max(self.loss_request_grace, self.UDP_delay * 80)
                for i_seq in range(self.udpRX_seq, self.last_seq):
                    if i_seq < self.udpRX_seq or i_seq in self.udprecv_pack:
                        continue
                    if i_seq not in lose_seq:
                        lose_seq[i_seq] = [now, 0, 0]
                    first_seen, last_sent, retry_count = lose_seq[i_seq]
                    retry_count = min(retry_count, self.loss_max_retry)
                    retry_delay = min(self.loss_retry_max, self.loss_retry_base * (2 ** min(retry_count, 6)))
                    if retry_count == 0 and now - first_seen < grace:
                        continue
                    if retry_count > 0 and now - last_sent < retry_delay:
                        continue
                    if retry_count >= self.loss_max_retry:
                        if i_seq == self.udpRX_seq and now - first_seen >= self.loss_skip_after:
                            self.udpRX_seq += 1
                            lose_seq.pop(i_seq, None)
                            if DEBUG: print(f'[Resend skip]\t{i_seq} -> {self.udpRX_seq}')
                            while self.udpRX_seq in self.udprecv_pack:
                                session_id, payload = self.udprecv_pack[self.udpRX_seq]
                                self.udprecv_pack.pop(self.udpRX_seq)
                                self.udpRX_seq += 1
                                if session_id in self.udpqueRX:
                                    self.udpqueRX[session_id].put(payload)
                                elif session_id == 0:
                                    self.tt = 500000
                                    self.send_to_client(0, 0x02, os.urandom(random.randint(64, 1188)))
                                else:
                                    self.send_to_client(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                        continue
                    lose_seq_list += struct.pack('!I', i_seq)
                    lose_seq[i_seq] = [first_seen, now, retry_count + 1]
                    if len(lose_seq_list) >= self.loss_batch_size * 4:
                        break
                if len(lose_seq_list) > 0:
                    self.send_to_client(0, 0x05, lose_seq_list)
                    if DEBUG: print(f'[Resend ack]\t{int(len(lose_seq_list)/4)} pack', self.udpRX_seq, self.last_seq)
                lose_list = list(lose_seq.keys())
                for i_seq in lose_list:
                    if i_seq < self.udpRX_seq or i_seq in self.udprecv_pack:
                        del lose_seq[i_seq]
                time.sleep(max(0.03, min(0.2, self.UDP_delay * 20)))
            else:
                time.sleep(max(0.05, self.UDP_delay*10))
    def recv_que(self):
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(self.mtu_udp + 16)
                if len(data) >= 16:
                    self.udpqueRXraw.put([data, addr])
            except Exception as e:
                print(f"recv_que: {e}")
    def run(self):
        print(f"Remote Server 啟動於 UDP {LISTEN_ADDR[1]}...")
        threading.Thread(target=self.handle_speed_udptx, daemon=True).start()
        threading.Thread(target=self.handle_status, daemon=True).start()
        threading.Thread(target=self.handle_to_Local, daemon=True).start()
        threading.Thread(target=self.handle_lose, daemon=True).start()
        threading.Thread(target=self.recv_que, daemon=True).start()        

        skip_lose_t = time.time()
        last_back = None
        while True:
            data, addr = self.udpqueRXraw.get()            
            self.udpRX_Byte += len(data)

            nonce = data[:8]
            encrypt_header = data[8:16]
            header = chacha20_sodium(encrypt_header, self.chacha_key, nonce)
            checksum = header[7]

            if checksum == hashlib.blake2b(header[0:7], digest_size=1).digest()[0]:
                seq, session_id, msg_type = struct.unpack('!IHB', header[0:7])  # 解析 Header
                payload = chacha20_sodium(data[16:], self.chacha_key, nonce)
            else:
                msg_type = 0xFF
            if last_back != addr and msg_type != 0x00:
                if self.client_addr is not None and msg_type in (0x01, 0x02, 0x03, 0x04, 0x05):
                    self.client_addr = addr
                    last_back = addr
                    if DEBUG: print(f'[Client addr update]\t[{self.client_addr}]')
                else:
                    msg_type = 0xFF
            if msg_type == 0x01: # New Connect
                threading.Thread(target=self.handle_client, args=(session_id, payload), daemon=True).start()
            elif msg_type == 0x02: # Data
                if seq >= self.udpRX_seq:
                    self.udprecv_pack[seq] = [session_id,payload]
                if self.udpRX_seq not in self.udprecv_pack:
                    if self.udpRX_seq != self.lose_pack_seq:
                        self.lose_pack_seq = self.udpRX_seq
                        skip_lose_t = time.time()
                    #if time.time() - skip_lose_t > self.UDP_delay * 2000:
                    #    self.udpRX_seq += 1
                while self.udpRX_seq in self.udprecv_pack:
                    session_id, payload = self.udprecv_pack[self.udpRX_seq]
                    self.udprecv_pack.pop(self.udpRX_seq)
                    self.udpRX_seq += 1
                    if session_id in self.udpqueRX:
                        self.udpqueRX[session_id].put(payload)
                    elif session_id == 0:
                        self.tt = 500000
                        self.send_to_client(0, 0x02, os.urandom(random.randint(64, 1188)))
                    else:
                        self.send_to_client(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                        pass
                self.last_seq = max(self.last_seq, seq)
            elif msg_type == 0x03: # Close
                if session_id in self.udpqueRX:
                    self.udpqueRX[session_id].put(None)
            elif msg_type == 0x04: # Speed
                self.Init_speed = struct.unpack('I', payload)[0]
                print(self.Init_speed, self.UDP_delay)
            elif msg_type == 0x05: # Resend pack
                if int(len(payload) / 4) >= 20:
                    self.UDP_delay = self.mtu_udp / self.Min_speed * self.Byte_Bit
                    self.speedCtr_delay = self.mtu_udp / self.Min_speed * self.Byte_Bit * self.windows
                self.send_to_client(0, 0x06, payload) #  Resend
            elif msg_type == 0x00: # link Start
                password = struct.unpack('6s',header[:6])[0]
                if password == b'040588':
                    self.client_addr = addr
                    last_back = addr
                    self.udpTX_seq = 0
                    self.udpRX_seq = 0
                    self.udpTX_buffer = {}
                    self.udprecv_pack = {}
                    self.udpTX_readyseq = 0
                    self.lose_pack_seq = 0
                    self.last_seq = 0
                    udpqueR = list(self.udpqueRX.keys())
                    for sid in udpqueR:
                        if sid in self.udpqueRX:
                            self.udpqueRX[sid].put(None)
                    self.send_to_client(0, 0x00, os.urandom(random.randint(64, 1188)))
                    print(f'[Client link]\t[{self.client_addr}]')
if __name__ == "__main__":
    RemoteServer().run()
