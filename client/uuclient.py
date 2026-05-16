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
DEBUG = 1
# 配置
LOCAL_ADDR = ('127.0.0.1', 1080)
SERVER_ADDR1 = ('192.168.2.1', 8888) # 測試時可改為伺服器 IP
SERVER_ADDR2 = ('45.207.206.163', 8888) # 測試時可改為伺服器 IP
SERVER_ADDR3 = ('118.150.217.142', 8888) # 測試時可改為伺服器 IP
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

objname = 'v'
try:
    objname = sys.argv[1]
except:
    pass
if objname == 'v':
    SERVER_LIST = [SERVER_ADDR2]
elif objname == 'h':
    SERVER_LIST = [SERVER_ADDR3]
elif objname == 't':
    SERVER_LIST = [SERVER_ADDR1]

class LocalClient:
    def __init__(self):
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.bind(LOCAL_ADDR)
        self.SERVER_ADDR = None
        self.udp_sock = None
        self.link_connect = 0
        self.udpqueRX = {} # {session_id: browser_conn}
        self.udpqueRXraw = queue.Queue()
        self.tcpsock_l = {}
        self.session_list = queue.Queue()
        for i in random.sample(range(1, 65500), 1000):
            self.session_list.put(i)
        self.udpqueTX = queue.Queue()
        self.udptx_c = queue.Queue()
        self.tcprx_lock = threading.Lock()
        self.mtu_udp = 1380
        self.tcpbuf = self.mtu_udp * 1
        self.Init_speed = 4.5 * 1000000.0
        self.Min_speed = 1 * 1000000
        self.Byte_Bit = 8
        self.UDP_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit
        self.windows = 4
        self.speedCtr_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit * self.windows
        self.udpTX_Byte = 0
        self.udpRX_Byte = 0
        self.udpTX_seq = 0
        self.udpRX_seq = 0
        self.udpTX_buffer = {}
        self.udpTX_readyseq = 0
        self.lose_pack_seq = 0
        self.last_seq = -1
        self.udprecv_pack = {}
        self.loss_request_grace = 0.18
        self.loss_retry_base = 0.45
        self.loss_retry_max = 3.0
        self.loss_max_retry = 6
        self.loss_skip_after = 8.0
        self.loss_batch_size = 160
        self.Client_change = 1
        self.chacha_key = hashlib.sha256('ch0641ng'.encode()).digest()

    def encrypt_send_to_server(self, current_seq, session_id, msg_type, payload, rate_limit=True):
        if rate_limit:
            self.udptx_c.get()
        try:
            nonce = os.urandom(8)
            header = struct.pack('!IHB', current_seq, session_id, msg_type)
            checksum = hashlib.blake2b(header, digest_size=1).digest()
            encrypt_header =  chacha20_sodium(header + checksum, self.chacha_key, nonce)
            packet = nonce + encrypt_header + chacha20_sodium(payload, self.chacha_key, nonce)
            self.udp_sock.sendto(packet, self.SERVER_ADDR)
            self.udpTX_Byte += len(packet)
        except:
            pass

    def send_to_server(self, session_id, msg_type, payload):
        #msg_type 0:Start VPN 1:New session 2:Data 3:Close 4:Ack 5: Resend
        with self.tcprx_lock:
            if self.link_connect == 1:
                if msg_type == 2:
                    self.udpTX_buffer[self.udpTX_seq] = [session_id, msg_type, payload]
                    current_seq = self.udpTX_seq
                    #print(f'[{session_id}]  [{payload[:10]}]')
                    if len(self.udpTX_buffer) > 20000:
                        self.udpTX_buffer.pop(self.udpTX_readyseq, None)
                        self.udpTX_readyseq += 1
                    self.udpTX_seq += 1
                    if 0:#msg_type == 2 and random.randint(1, 50) == 25:
                        pass
                    else:
                        self.encrypt_send_to_server(current_seq, session_id, msg_type, payload)
                elif msg_type == 0 or msg_type == 1 or msg_type == 3 or msg_type == 4 or msg_type == 5:
                    current_seq = 0
                    self.encrypt_send_to_server(current_seq, session_id, msg_type, payload, False)
                elif msg_type == 6: # Resend 
                    payload_list = []
                    while len(payload) > 0:
                        lose_seq = struct.unpack('!I', payload[:4])[0]
                        if lose_seq in self.udpTX_buffer:
                            current_seq = lose_seq
                            session_id, msg_type, resend_payload = self.udpTX_buffer[current_seq]
                            self.encrypt_send_to_server(current_seq, session_id, msg_type, resend_payload, False)
                        elif DEBUG:
                            print(f'[Resend miss]\t{lose_seq}')
                        payload_list.append(lose_seq)
                        payload = payload[4:]
                    if DEBUG: print(f'[Resend] {payload_list}')
            else:
                time.sleep(1)

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
                                    print(f"[Recv Server]  ")
                        continue
                    lose_seq_list += struct.pack('!I', i_seq)
                    lose_seq[i_seq] = [first_seen, now, retry_count + 1]
                    if len(lose_seq_list) >= self.loss_batch_size * 4:
                        break
                if len(lose_seq_list) > 0:
                    self.send_to_server(0, 0x05, lose_seq_list)
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
            if self.udp_sock != None:
                try:
                    data, addr = self.udp_sock.recvfrom(self.mtu_udp + 16)
                    if len(data) >= 16:
                        self.udpqueRXraw.put([data, addr])
                except Exception as e:
                    print(f"recv_que: {e}")
                    self.udpqueRXraw.put([None, None])
                    time.sleep(2)
            else:
                time.sleep(1)

    def udp_listener(self):
        """監聽從 Server 回傳的 UDP 封包"""
        while True:
            self.udpTX_seq = 0
            self.udpRX_seq = 0
            self.udpTX_buffer = {}
            self.udpTX_readyseq = 0
            self.lose_pack_seq = 0
            self.last_seq = -1
            self.udprecv_pack = {}
            udpqueR = list(self.udpqueRX.keys())
            for sid in udpqueR:
                if sid in self.udpqueRX:
                    self.udpqueRX[sid].put(None)

            skip_lose_t = time.time()
            while self.udp_sock != None:
                try:
                    data, addr = self.udpqueRXraw.get()
                    if data == None and addr == None:
                        break
                    self.udpRX_Byte += len(data)
                    nonce = data[:8]
                    encrypt_header = data[8:16]
                    header = chacha20_sodium(encrypt_header, self.chacha_key, nonce)
                    checksum = header[7]

                    if checksum == hashlib.blake2b(header[:7], digest_size=1).digest()[0]:
                        seq, session_id, msg_type = struct.unpack('!IHB', header[:7])  # 解析 Header
                        payload = chacha20_sodium(data[16:], self.chacha_key, nonce)
                    else:
                        msg_type = 0xFF

                    if msg_type == 0x00: # Restart server
                        self.udp_sock.settimeout(10)
                        self.link_connect = 1
                        print('[Start server] ',self.SERVER_ADDR )
                    elif self.link_connect == 0:
                        pass
                    elif msg_type == 0x02: # Data
                        if seq >= self.udpRX_seq:
                            self.udprecv_pack[seq] = [session_id,payload]
                        if self.udpRX_seq not in self.udprecv_pack:
                            if self.udpRX_seq != self.lose_pack_seq:
                                self.lose_pack_seq = self.udpRX_seq
                                skip_lose_t = time.time()
                                #print(f'[Lose pack]\t[{session_id}]\t[{self.udpRX_seq}]\t[{seq}]')
                            if time.time() - skip_lose_t > self.UDP_delay * 2000:
                                self.udpRX_seq += 1
                        while self.udpRX_seq in self.udprecv_pack:
                            session_id, payload = self.udprecv_pack[self.udpRX_seq]
                            self.udprecv_pack.pop(self.udpRX_seq)
                            self.udpRX_seq += 1
                            if session_id in self.udpqueRX:
                                self.udpqueRX[session_id].put(payload)
                            elif session_id == 0:
                                print(f"[Recv Server]  ")
                        self.last_seq = max(self.last_seq, seq)
                    elif msg_type == 0x03: # Clolose session
                        if session_id in self.udpqueRX:
                            self.udpqueRX[session_id].put(None)
                            #print(f"[{session_id}]\t[Remote Close]  ")
                    elif msg_type == 0x05: # Resend pack
                        if int(len(payload) / 4) >= 20:
                            self.UDP_delay = self.mtu_udp / self.Min_speed * self.Byte_Bit
                            self.speedCtr_delay = self.mtu_udp / self.Min_speed * self.Byte_Bit * self.windows
                        self.send_to_server(0, 0x06, payload) #  Resend
                except socket.timeout:
                    break
            self.udp_sock = None
            self.link_connect = 0
            time.sleep(1)

    def handle_browser(self, client_conn):
        client_conn.settimeout(30)
        data = client_conn.recv(1024)
        if not data or data[0] != 5:  # SOCKS5 協議版本
            client_conn.close()
            return  
        # 響應瀏覽器：無認證
        client_conn.sendall(b"\x05\x00")

        # 接收目標地址請求
        request = client_conn.recv(1024)
        addr_type = request[3]

        if addr_type == 1:  # IPv4
            address = socket.inet_ntoa(request[4:8])
            port = struct.unpack(">H", request[8:10])[0]
            conn_data = b"\x01" + socket.inet_aton(address) + struct.pack(">H", port)

        elif addr_type == 3:  # 域名
            addr_len = request[4]
            address = request[5:5 + addr_len].decode("utf-8")
            port = struct.unpack(">H", request[5 + addr_len:7 + addr_len])[0]
            conn_data = b"\x03" + bytes([len(address.encode("utf-8"))]) + address.encode("utf-8") + struct.pack(">H", port)

        session_id = self.session_list.get()
        self.udpqueRX[session_id] = queue.Queue()
        self.Client_change = 1
        if DEBUG: print(f"[{session_id}]\t[Open] {address}:{port}")

        self.send_to_server(session_id, 0x01, conn_data)
        try:
            data = self.udpqueRX[session_id].get(block=True, timeout=5)
            if data[1] == 0: 
                #print(f'[{session_id}]\t[Return ok] ')
                client_conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.tcpbuf)
                self.tcpsock_l[client_conn] = session_id
                client_conn.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") # 告訴瀏覽器連線已成功建立
                while True:
                    try:
                        payload = self.udpqueRX[session_id].get(block=True, timeout=600)
                        if payload == None or session_id not in self.udpqueRX: break
                        client_conn.sendall(payload)
                    except:
                        self.send_to_server(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                        if DEBUG: print (f'[{session_id}]\t[Close Timeout 1]')
                        break
        except:
            client_conn.close()
        self.udpqueRX.pop(session_id, None)
        self.Client_change = 1
        self.session_list.put(session_id)
        return

    def handle_to_remote(self):
        """讀取目標網站回傳的資料，轉發回 Client"""
        while True:
            if len(self.tcpsock_l) > 0:
                if self.Client_change == 1:
                    self.Client_change = 0
                    for sock, session_id in list(self.tcpsock_l.items()):
                        if session_id not in self.udpqueRX:
                            sock.close()
                            self.tcpsock_l.pop(sock, None)
                            if DEBUG: print (f'[{session_id}]\t[Close Server]')

                tcprx_list = list(self.tcpsock_l.keys())
                if len(tcprx_list) > 0:
                    tcpR_ready, tcpW_ready, tcp_error = select.select(tcprx_list, [], tcprx_list, self.UDP_delay)
                    for i_sock in tcpR_ready:
                        session_id = self.tcpsock_l[i_sock]
                        try:
                            data = i_sock.recv(self.mtu_udp)
                            if not data:
                                i_sock.close()
                                self.tcpsock_l.pop(i_sock, None)
                                if session_id in self.udpqueRX:
                                    self.udpqueRX[session_id].put(None)
                                self.send_to_server(session_id, 0x03, os.urandom(random.randint(64, 1188)))
                                if DEBUG: print (f'[{session_id}]\t[Close Brower]')
                            else:
                                self.send_to_server(session_id, 0x02, data)
                        except:
                            self.send_to_server(session_id, 0x03, os.urandom(random.randint(64, 1188)))
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
        tt = 0
        last_time = time.time()
        while True:
            if self.link_connect == 0:
                self.SERVER_ADDR = SERVER_LIST[0]
                try:
                    if self.udp_sock == None:
                        u_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        u_sock.settimeout(20)
                        u_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.mtu_udp*1000000)
                        u_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.mtu_udp*1000000)
                    nonce = os.urandom(8)
                    checksum = hashlib.blake2b(b"040588" + b"\x00", digest_size=1).digest()
                    encrypt_header =  chacha20_sodium(b"040588" + b"\x00" + checksum, self.chacha_key, nonce)
                    pack_time = struct.pack('d',time.time())
                    packet = nonce + encrypt_header + chacha20_sodium(pack_time, self.chacha_key, nonce)
                    u_sock.sendto(packet, self.SERVER_ADDR)
                    self.udp_sock = u_sock
                except:
                    pass
            if tt >= 3:
                time_w = time.time() - last_time
                print (f'\r\n[Status][{len(self.udpqueRX)}]\t[{self.udpRX_seq}][{self.udpTX_seq}]\tTX={self.udpTX_Byte/time_w/1000:,.0f} KB/s RX={self.udpRX_Byte/time_w/1000:,.0f} KB/s \r\n  ')
                last_time = time.time()
                self.UDP_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit
                self.speedCtr_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit * self.windows

                if self.link_connect == 1:
                    self.send_to_server(0, 0x02, os.urandom(random.randint(64, 1188)))
                self.udpTX_Byte = 0
                self.udpRX_Byte = 0
                tt = 1
            time.sleep(3)
            tt += 1
    def key_cmd(self):
        time.sleep(2)
        while 1:
            try:
                cmd = input('input cmd : \n')
                if cmd == 'q':
                    self.tcp_sock.close()
                elif cmd == 's':
                    sp = input('input speed (MB): ')
                    try:
                        sp = float(sp)
                    except:
                        sp = 5
                    if sp > 100 or sp == 0:
                        sp = 2.8
                    self.Init_speed = int(sp * 1000000)
                    self.UDP_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit
                    self.speedCtr_delay = self.mtu_udp / self.Init_speed * self.Byte_Bit * self.windows
                    self.send_to_server(0, 0x04, struct.pack('I', self.Init_speed))
                    print(self.Init_speed, self.UDP_delay)
                elif cmd == 'r':
                    print(f"Restart Server")
                    self.link_connect = 0
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    addr = self.udp_sock.getsockname()
                    target_address = ('127.0.0.1' if addr[0] == '0.0.0.0' else addr[0], addr[1])                    
                    print('target_address',target_address)
                    temp_sock.sendto(b'0'*20, target_address)
                    self.udp_sock = None
            except Exception as e:
                print(f"Error in key_cmd: {e}")
    def run(self):
        threading.Thread(target=self.udp_listener, daemon=True).start()
        threading.Thread(target=self.recv_que, daemon=True).start()
        threading.Thread(target=self.handle_to_remote, daemon=True).start()
        threading.Thread(target=self.handle_speed_udptx, daemon=True).start()
        threading.Thread(target=self.handle_lose, daemon=True).start()
        threading.Thread(target=self.handle_status, daemon=True).start()
        threading.Thread(target=self.key_cmd, daemon=True).start()

        self.tcp_sock.listen(5)
        self.tcp_sock.settimeout(1)
        print(f"Local SOCKS5 Client 啟動於 {LOCAL_ADDR}...")
        while True:
            try:
                while self.link_connect == 0:
                #while self.udp_sock == None:
                    time.sleep(1)
                conn, _ = self.tcp_sock.accept()
                threading.Thread(target=self.handle_browser, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break
if __name__ == "__main__":
    LocalClient().run()
