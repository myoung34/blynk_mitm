import socket
import struct
from pprint import pprint

def parse_response(rsp_data, msg_buffer):
    msg_args = []
    msg_head_length = 5
    try:
        msg_type, msg_id, h_data = struct.unpack('!BHH', rsp_data[:msg_head_length])
    except struct.error:
        return None
    if msg_type in [0, 6, 16, 19, 29]: # dataless packets (redirect, ping, etc)
        pass
    elif msg_type in [20, 15, 17, 41]:
        msg_body = rsp_data[msg_head_length: msg_head_length + h_data]
        msg_args = [itm.decode('utf-8') for itm in msg_body.split(b'\0')]
    else:
        raise Exception("Unknown message type: '{}'".format(msg_type))
    return msg_type, msg_id, h_data, msg_args



socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('0.0.0.0', 80))
socket.listen(1)
conn, addr = socket.accept()
with conn:
    while True:
        try:
            rsp_data =  conn.recv(1024)
            data = parse_response(rsp_data, 1024)
            if data:
                print('received: ')
                pprint(data)
                if data[0] == 29: # auth?
                    print('sending auth success \\x00\\x00\\x01\\x00\\xc8') # -> .hex() => '00000100c8'
                    conn.sendall(b'\x00\x00\x01\x00\xc8') # -> .hex() => '00000100c8'
        except Exception as e:
            socket.close()
            raise e
