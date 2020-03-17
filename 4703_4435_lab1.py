# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from struct import *


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet **returns the first item in
    the packets to be sent.**
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        # read -> 1, write -> 2, data -> 3, ack -> 4, error -> 5
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.blocknumber = 1
        self.last = -1
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line

        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_byte):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        # pull // pack -> data, wrq // unpack -> acq

        # PACK OR UNPACK
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        self.last = self.packet_buffer.pop(0)
        print("self.last = ", self.last)
        return self.last

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        # PACKING
        format = "!h" + str(len(file_path_on_server)) + "sB5sB"
        packing = pack(format, self.TftpPacketType.RRQ.value, bytes(file_path_on_server, "ascii"), 0,
                       bytes("octet", "ascii"), 0)
        return packing

    def upload_file(self, file_path_on_server):
        '''2 bytes string 1 byte string 1 byte
        --------------------------------------
        | Opcode | Filename | 0 | Mode | 0 |
        --------------------------------------
         WRQ -> 02'''
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        # PACKING
        format = "!h" + str(len(file_path_on_server)) + "sB5sB"
        packing = pack(format, self.TftpPacketType.WRQ.value, bytes(file_path_on_server, "ascii"), 0,
                       bytes("octet", "ascii"), 0)
        return packing

    def read(self, server_packet):
        opcode = server_packet[:2]
        unpacking = unpack("!h", opcode)
        if unpacking[0] == 3:
            return self.data(server_packet)
        else:
            self.error(server_packet)
            return 0

    def write(self, server_packet):
        '''
        2 bytes 2 bytes string 1 byte
        -----------------------------------------
        | Opcode | ErrorCode | ErrMsg | 0 |
        -----------------------------------------
        Figure 5-4: ERROR packet
        '''
        opcode = server_packet[:2]
        unpacking = unpack("!h", opcode)
        if unpacking[0] == 4:
            self.ack(server_packet)
            return 0
        else:
            self.error(server_packet)
            return 1

    def data(self, server_packet):
        unpacking = unpack("!hh512s", server_packet)
        block_number = unpacking[1]
        data = unpacking[2]
        print("block number = ", block_number)
        return block_number, data

    def ack(self, server_packet):
        unpacking = unpack("!hh", server_packet)
        block_number = unpacking[1]
        print("block number = ", block_number)
        return block_number

    def error(self, server_packet):
        unpacking = unpack("!hh", server_packet[:4])
        if unpacking[2] == 0:
            print("Not defined, see error message (if any).")
        elif unpacking[2] == 1:
            print("File not found.")
        elif unpacking[2] == 2:
            print("Access violation.")
        elif unpacking[2] == 3:
            print("Disk full or allocation exceeded.")
        elif unpacking[2] == 4:
            print("Illegal TFTP operation.")
        elif unpacking[2] == 5:
            print("Unknown transfer ID.")
        elif unpacking[2] == 6:
            print("File already exists.")
        elif unpacking[2] == 7:
            print("No such user.")

    def send_ack(self, blocknumber):
        print(type(blocknumber))
        packking = pack("!hh", self.TftpPacketType.ACK.value, blocknumber)
        return  packking

    def send(self, data):
        return self.parse(data)

    def parse(self, data):
        """
        2 bytes 2 bytes n bytes
        ----------------------------------
        | Opcode | Block # | Data |
        ----------------------------------
        Figure 5-2: DATA packet

        :param data:
        :return:
        """
        format = "!hh512s"
        packing = pack(format, self.TftpPacketType.DATA.value, self.blocknumber, data)
        #print("block number = ", self.blocknumber)
        self.blocknumber = self.blocknumber + 1
        self.packet_buffer.append(packing)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(client_socket)
    return client_socket


def do_socket_logic(address, operation, client_socket, file_name):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    #
    server_address = (address, 69)
    if operation == "push":
        upload(address, operation, client_socket, file_name, server_address)
    else:
        download(address, operation, client_socket, file_name, server_address)


def upload(address, operation, client_socket, file_name, server_address):
    tftp = TftpProcessor()
    wrq = tftp.upload_file(file_name)
    client_socket.sendto(wrq, server_address)
    (server_packet, (add, p)) = client_socket.recvfrom(516)
    print(server_packet)
    print("[CLIENT] IN", server_packet, p)
    print(add[1])
    port_add = (address, p)
    print("[CLIENT] IN", server_packet)
    print(add[1])
    uploading = tftp.write(server_packet)
    print(uploading)
    if uploading == 0:
        try:
            file = open(file_name, "rb")
            for chunk in iter(lambda: file.read(512), b''):
                tftp.send(chunk)
            while tftp.has_pending_packets_to_be_sent():
                client_socket.sendto(tftp.get_next_output_packet(), port_add)
                try:
                    (packet, (address, port)) = client_socket.recvfrom(516)
                    tftp.write(packet)

                except:
                    client_socket.sendto(tftp.last, port_add)
                    try:
                        (packet, (address, port)) = client_socket.recvfrom(516)
                        tftp.write(packet)
                    except:
                        print("Timeout")
        except IOError:
            print("File not accessible")
            pass

    else:
        exit(-1)
    tftp.blocknumber = 1
    print("last", tftp.blocknumber)


def download(address, operation, client_socket, file_name, server_address):
    tftp = TftpProcessor()
    rrq = tftp.request_file(file_name)
    client_socket.sendto(rrq, server_address)
    (server_packet, add) = client_socket.recvfrom(516)
    print(server_packet)
    print(len(server_packet))
    print("[CLIENT] IN", server_packet)
    print("[CLIENT] IN", server_packet)
    uploading = tftp.read(server_packet)
    file = open("demofile2.txt", "ab")
    file.write(uploading[1])
    packed = tftp.send_ack(uploading[0])
    if uploading[0] > 0:
        while 1:
            client_socket.sendto(packed, add)
            packet, address = client_socket.recvfrom(516)
            print(packet)
            if len(packet) < 516:
                break
            uploading = tftp.read(packet)
            file.write(uploading[1])
            packed = tftp.send_ack(uploading[0])




def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    print(operation)
    client_socket = setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic(address, operation, client_socket, file_name)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic(address, operation, client_socket, file_name)


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        print(sys.argv[param_index])
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()