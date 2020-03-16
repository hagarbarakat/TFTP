# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from sys import argv
import math
import struct


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

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
        RRQ = 1
        WRQ = 2
        DAT = 3
        ACK = 4
        ERR = 5

    def __init__(self):
        """
        Add and initialize the internal fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source, operation):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line

        print(f"[TFTP] Received a packet from {packet_source}")
        if operation == 'push':
            response = self._parse_udp_packet(packet_data, operation)
            opcode = response[0]
            if opcode == 'ACK':
                block_no = response[1]
                print('[TFTP - Upload] Recieved packet type: ', opcode, ' Block #', block_no)
                return opcode, block_no
            elif opcode == 'ERR':
                error_no = response[1]
                error_msg = response[2]
                print('[TFTP - Upload] Recieved packet type: ', opcode, ' Error Code #', error_no, ':', error_msg)
                return opcode, error_no, error_msg
            else:
                print('[TFTP - Upload] Recieved undefined packet type')
                return opcode
        else:
            response = self._parse_udp_packet(packet_data, operation)
            opcode = response[0]
            if opcode == 'DAT':
                block_no = response[1]
                data = response[2]
                print('[TFTP - Download] Recieved packet type: ', opcode, ' Block #', block_no)
                return opcode, block_no, data
            # in_packet = self._parse_udp_packet(packet_data,operation)
            # out_packet = self._do_some_logic(in_packet)

            # This shouldn't change.
            # self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes, operation):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        if operation == 'push':
            # Return the opcode of the response and other fields
            no = struct.unpack('!h', packet_bytes[0:2])[0]
            if no == 4:
                no, block_no = struct.unpack('!hh', packet_bytes)
                return 'ACK', block_no
            elif no == 5:
                error_no = struct.unpack('!h', packet_bytes[2:4])[0]
                packet_len = len(packet_bytes)
                error_msg = struct.unpack(str(packet_len - 5) + 's', packet_bytes[4:packet_len - 1])[0]
                return 'ERR', error_no, error_msg.decode("ascii")
            else:
                return no, 'Undefined packet'
        elif operation == 'pull':
            # Return the opcode of the response and other fields
            no = struct.unpack('!h', packet_bytes[0:2])[0]
            if no == 3:
                # no, block_no, buffer= struct.unpack('!hh512s', packet_bytes)
                blocks = struct.unpack('!hh512s', packet_bytes)
                block_no = blocks[1]
                data = blocks[2]
                #self.packet_buffer.append(data)
                return 'DAT', block_no, data
            elif no == 5:
                error_no = struct.unpack('!h', packet_bytes[2:4])[0]
                packet_len = len(packet_bytes)
                error_msg = struct.unpack(str(packet_len - 5) + 's', packet_bytes[4:packet_len - 1])[0]
                return 'ERR', error_no, error_msg.decode("ascii")
            else:
                return no, 'Undefined packet'

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
        return self.packet_buffer.pop(0)

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
        # pack packet in a struct
        mode_bytes = bytearray('octet', 'ascii')
        file_name_bytes = bytearray(file_path_on_server, 'ascii')
        frmt = '!h' + str(len(file_name_bytes)) + 's' + '?' + str(len(mode_bytes)) + 's' + '?'
        packet = struct.pack(frmt, 1, file_name_bytes, 0, mode_bytes, 0)
        self.packet_buffer.append(packet)


    def resend(self, packet):
        self.packet_buffer.insert(0, packet)

    def send_Ack(self, block_no):
        print("block = ", block_no)
        packet = struct.pack("!hh", self.TftpPacketType.ACK.value, block_no)
        return packet
    def upload_file(self, file_name):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        try:
            # Open file
            f = open(file_name)
            print('[TFTP - Upload] File opened succesfully')
            # Read the file
            file_content = f.read()
        except IOError:
            print("[TFTP - Upload] File not accessible")
            exit(-1)  # Program execution failed.

        no_packets = math.floor(1.0 * len(file_content) / 512)
        mode_bytes = bytearray('octet', 'ascii')
        file_name_bytes = bytearray(file_name, 'ascii')
        # pack packet in a struct
        frmt = '!h' + str(len(file_name_bytes)) + 's' + '?' + str(len(mode_bytes)) + 's' + '?'
        packet = struct.pack(frmt, 2, file_name_bytes, 0, mode_bytes, 0)
        self.packet_buffer.append(packet)
        i = 0

        for i in range(no_packets + 1):
            start = i * 512
            end = min(len(file_content), (i + 1) * 512)
            frmt = '!hh' + str(end - start) + 's'
            packet = struct.pack(frmt, 3, i + 1, bytearray(file_content[start:end], 'ascii'))
            self.packet_buffer.append(packet)

        print('[TFTP - Upload] to send ', len(self.packet_buffer))
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets():
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    # Create client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Address is the local host : The TFTP port
    return client_socket


def do_socket_logic(tftp, sock, address, operation):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    if operation == "push":
        # Send WRQ
        print('[UDP] Send WRQ...')
        WRQ = tftp.get_next_output_packet()
        # Recieve response from server
        try:
            sock.sendto(WRQ, address)
            response, tftp_address = sock.recvfrom(2096)
        except socket.error:
            try:
                # Resend one more time
                sock.sendto(WRQ, address)
                response, tftp_address = sock.recvfrom(2096)
            except socket.error:
                # Terminate
                print('[UDP - Upload] Timeout - No response from server')
                exit(-1)
            pass
        # Pass the response to the TFTP processor
        tftp_response = tftp.process_udp_packet(response, tftp_address, operation)
        response_type = tftp_response[0]
        if response_type != 'ACK':
            return

        curr_block_id = 0
        while tftp.has_pending_packets_to_be_sent():
            packet = tftp.get_next_output_packet()
            curr_block_id += 1
            try:
                print('[UDP - Upload] Send block no  ', curr_block_id, ' of length ', len(packet))
                sock.sendto(packet, tftp_address)
                response, new_tftp_address = sock.recvfrom(2096)
            except socket.error:
                try:
                    # Resend one more time
                    print('[UDP - Upload] Resend block no  ', curr_block_id)
                    sock.sendto(packet, tftp_address)
                    response, new_tftp_address = sock.recvfrom(2096)
                except socket.error:
                    # Terminate
                    print('[UDP - Upload] Timeout - Lost connection with server')
                    exit(-1)

            if new_tftp_address != tftp_address:
                print('[UDP - Upload] Recieved wrong packet !')
                curr_block_id -= 1
                tftp.resend(packet)
            else:
                tftp_response = tftp.process_udp_packet(response, tftp_address, operation)
                response_type = tftp_response[0]
                if response_type != 'ACK':
                    break
                if curr_block_id != tftp_response[1]:
                    curr_block_id -= 1
                    tftp.resend(packet)
    else:
        print('[UDP] Send RRQ...')
        RRQ = tftp.get_next_output_packet()
        # Recieve response from server
        try:
            sock.sendto(RRQ, address)
            response, tftp_address = sock.recvfrom(2096)  # data block 1 initially or error
            r = response.decode()
            print("response:  ", r)
        except socket.error:
            try:
                # Resend one more time
                sock.sendto(RRQ, address)
                response, tftp_address = sock.recvfrom(2096)
            except socket.error:
                # Terminate
                print('[UDP - Download] Timeout - No response from server')
                exit(-1)

        # Pass the response to the TFTP processor
        tftp_response, block_no, data = tftp.process_udp_packet(response, tftp_address, operation)
        f = open("yarabb.txt", "ab")
        f.write(data)
        response_type = tftp_response
        print(response_type)
        if response_type != 'DAT':
            return
        print("omar")
        packet = tftp.send_Ack(block_no)
        print("packet = ",packet)
        while 1:
            #packet = tftp.send_Ack(tftp_response[1])
            try:
                print('[UDP - Download] Send block no  ', block_no)
                sock.sendto(packet, tftp_address)
                response, new_tftp_address = sock.recvfrom(516)
            except socket.error:
                try:
                    # Resend one more time
                    print('[UDP - Upload] Resend block no  ', block_no)
                    sock.sendto(packet, tftp_address)
                    response, new_tftp_address = sock.recvfrom(516)
                except socket.error:
                    # Terminate
                    print('[UDP - Upload] Timeout - Lost connection with server')
                    exit(-1)
            print(response)
            if len(response) < 516:
                break
            tftp_response, block_no, data = tftp.process_udp_packet(response, tftp_address, operation)
            f.write(data)
            packet = tftp.send_Ack(block_no)
            print(tftp_response)



pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        # Set up client socket
        server_address = (address, 69)
        client_socket = setup_sockets()
        # Create TFTP Packet
        tftp = TftpProcessor()
        # Prepare all packets
        tftp.upload_file(file_name)
        # Upload
        do_socket_logic(tftp, client_socket, server_address, operation)

    elif operation == "pull":
        # Set up client socket
        server_address = (address, 69)
        client_socket = setup_sockets()
        # Create TFTP Packet
        tftp = TftpProcessor()
        # Prepare all packets
        tftp.request_file(file_name)
        # Download
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic(tftp, client_socket, server_address, operation)


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
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
