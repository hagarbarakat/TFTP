import socket
# Make a new socket object.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Note that this address must be specified in the client.
server_address = ("127.0.0.1", 45002)

# Bind tells the OS to allocate this address for this process.
# Clients don't need to call bind since the server doesn't
# care about their address. But clients must know where the
# server is.
server_socket.bind(server_address)
print("[SERVER] Socket info:", server_socket)
print("[SERVER] Waiting...")
# This line of code will "Block" the execution of the program.

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ("127.0.0.1", 45002)

# Note that sockets accept data as "bytes"
# Sending a string will fail because the socket
# can't assume an "encoding" that transforms this
# string to the equivalent set of bytes.

# client_socket.sendto("Hello".encode("ascii"), server_address)
# on the other side, the server must call "decode" to convert
# the received bytes to a human readable string.
client_socket.sendto(b"Hello", server_address)
print("[CLIENT] Done!")
# The buffer is the size of packet transit in our OS.


packet = server_socket.recvfrom(4096)
data, client_address = packet
print("[SERVER] IN", data)

server_packet = client_socket.recvfrom(2048)
print("[CLIENT] IN", server_packet)