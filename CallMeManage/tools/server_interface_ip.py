import socket
import fcntl
import struct

def get_interface_ip(interface_name):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  
            struct.pack('256s', bytes(interface_name[:15], 'utf-8'))
        )[20:24])
    except IOError:
        return None