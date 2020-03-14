import socket
from struct import *
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_rq(filename, mode):
    """
    This function constructs the request packet in the format below.
    Demonstrates how we can construct a packet using bytearray.

        Type   Op #     Format without header

               2 bytes    string   1 byte     string   1 byte
               -----------------------------------------------
        RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
        WRQ    -----------------------------------------------


    :param filename:
    :return:
    """
    request = bytearray()
    # First two bytes opcode - for read request
    request.append(0)
    request.append(1)
    # append the filename you are interested in
    filename = bytearray(filename.encode('utf-8'))
    request += filename
    # append the null terminator
    request.append(0)
    # append the mode of transfer
    form = bytearray(bytes("octet".encode('utf-8')))
    request += form
    # append the last byte
    request.append(0)

    print(f"Request {request}")
    sent = client_socket.sendto(request, server_address)


server_address = ("127.0.0.1", 69)

# Note that sockets accept data as "bytes"
# Sending a string will fail because the socket
# can't assume an "encoding" that transforms this
# string to the equivalent set of bytes.

# client_socket.sendto("Hello".encode("ascii"), server_address)
# on the other side, the server must call "decode" to convert
# the received bytes to a human readable string.

client_socket.sendto(b"Hello", server_address)
##send_rq("test.txt","2")
print("[CLIENT] Done!")
# The buffer is the size of packet transit in our OS.
server_packet, add = client_socket.recvfrom(516)
print("[CLIENT] IN", server_packet)

unpacking = unpack("!hh", server_packet[:4])
print(unpacking)
print("[CLIENT] IN", server_packet)

