import logging
from sys import stdout
import select
from datetime import datetime
import serial
import socket
import binascii
import serial.tools.list_ports
from pydnp3_master.DNP3_SC.dnp3_frame import *
# import sys
# import os

# application_name = os.path.basename(sys.executable)
# if application_name == 'python.exe':        # if this is running in python script mode
#     top_dir = os.path.dirname(sys.modules['__main__'].__file__)
#     this_script_dir = os.path.dirname(os.path.abspath(__file__))
#     if this_script_dir != top_dir and top_dir in this_script_dir:
#         from DNP3_SC.dnp3_frame import *
#     else:
#         from dnp3_frame import *
# else:                                       # if this is running in executable mode
#     appplication_path = os.path.dirname(sys.executable)
#     sys.path.insert(0, appplication_path)
#     from dnp3_frame import *

class dnp3master(object):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stdout)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    def __init__(self, dnp_address=52, 
                 client_ip="192.168.52.2", 
                 client_port=20000, 
                 master_ip='192.168.52.201', 
                 master_port=20001, 
                 buffer_size=2048, 
                 method="udp", 
                 com_port_name=None, 
                 baud_rate=None):
        '''
        ## There are three types of communication protocols that could be used and therefore supported for DNP3 communications between master and outstation
        ## when comm method is selected to be either 'tcp' or 'udp' the first set of input parameters are used that includes ip address and port number
        ## when serial connection is used, the last two input parameters are used to set com port name and baudrate value
        ## the methods for get() and send() bytes are differet between these two types of protocols
        '''
        self.dnp_address = dnp_address
        self.buffer_size = buffer_size
        self.client_socket = None
        self.method = method
        self.open = False
        if method in {'udp', 'tcp'}:
            self.client_ip = client_ip
            self.client_port = client_port
            self.client_address = (client_ip, client_port)
            self.master_ip = master_ip
            self.master_port = master_port
            self.master_address = (master_ip, master_port)
        else:
            self.com_port_name = com_port_name
            self.baud_rate = baud_rate

    def run(self, conn_status_val):
        init_all()
        indicator_color = ''
        if self.client_socket:
            if self.method in {'tcp', 'udp'}:
                logging_info_str = f'[RTU {self.dnp_address}] - DNP3 master already connected to outstation \
                    ({self.client_ip}:{self.client_port}) with {self.method.upper()} connection'
            else:
                logging_info_str = f'[RTU {self.dnp_address}] - DNP3 master already connected to outstation \
                    ({self.com_port_name}:{self.baud_rate}) with {self.method.capitalize()} connection'
            self.logger.info(logging_info_str)
            self.open = True
        else:
            try:
                # Connect to outstation
                if self.method in {'tcp', 'udp'}:
                    if self.method == 'tcp':
                        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    elif self.method == 'udp':
                        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self.client_socket.bind(self.master_address)
                    self.client_socket.connect(self.client_address)
                    logging_info_str = f'[RTU {self.dnp_address}] - DNP3 master successfully connected to outstation \
                        ({self.client_ip}:{self.client_port}) with {self.method.upper()} connection'
                else:
                    self.client_socket = serial.Serial()
                    self.client_socket.port = self.com_port_name
                    self.client_socket.baudrate = self.baud_rate
                    self.client_socket.timeout = 1
                    self.client_socket.open()
                    logging_info_str = f'[RTU {self.dnp_address}] - DNP3 master successfully connected to outstation \
                        ({self.client_socket.port}:{self.client_socket.baudrate}) with {self.method.capitalize()} connection'
                self.logger.info(logging_info_str)
                conn_status_val.set(logging_info_str)
                indicator_color = 'green'
            except Exception as e:
                if self.method in {'tcp', 'udp'}:
                    logging_err_str = f'[RTU {self.dnp_address}] - Error while connecting to ({self.client_ip}:{self.client_port}'
                else:
                    logging_err_str = f'[RTU {self.dnp_address}] - Error while connecting to ({self.com_port_name}:{self.baud_rate}'
                self.logger.error(logging_err_str)
                self.logger.error(str(e))
                conn_status_val.set(logging_err_str)
                indicator_color = 'yellow'
            else:
                self.open = True
                indicator_color = 'green'
            return indicator_color            

    def send(self, address_tuple, applCtrlVal, datalinkCtrlVal, objDefVal, notPrint=False):
        """
        Send a command to the outstation
        :return: NoneType
        """
        if self.open:
            dnp_frame = TransmitFrame(address_tuple, applCtrlVal, datalinkCtrlVal, objDefVal)
            # PRM=1 is for request and PRM=0 is for response. In both cases DIR=1, FCB=0
            sent_bytes = dnp_frame.convert2bytes()
            if objDefVal['Function Codes'] == Function_Code.CONFIRM:
                titleStr = 'Confirmation'
            elif f'{datalinkCtrlVal:08b}'[::-1][6] == '0':
                titleStr = 'Response'
            else:
                titleStr = 'Request'
            if not notPrint:
                print(f'{titleStr} to outstation: {binascii.hexlify(sent_bytes)}')
            if self.method in {'tcp', 'udp'}:
                self.client_socket.sendall(sent_bytes)
            else:
                self.client_socket.write(sent_bytes)
            cat_seqBytes = ReceivedFrame.categorize_receivedBytes([sent_bytes])
            seq_num_str = f", seq#{cat_seqBytes['Sequence Number']}" if cat_seqBytes['Sequence Number'] not in [253, 254] else ''
            table_title = f"[{datetime.now().strftime('%m/%d/%Y %I:%M:%S.%f')[:-3]}] {titleStr} to RTU[{self.dnp_address}]{seq_num_str}"
            return (ReceivedFrame.convert2frame(dnp_frame.convert2bytes(), True, True).__dict__, table_title)
        else:
            return ('', '')

    def get(self):
        """
        Decoding received messages from outstation
        :return: DNPFrame
        Keep receiving if 
        1. first two bytes are 0x0564
        2. total packet length (less the CRC bytes) is equal to value of the thid byte
        3. No CRC error from either data link or data block bypes
        4. The last fragment is received
        """
        received_data = b""
        if self.method in {'tcp', 'udp'}:
            self.client_socket.setblocking(0)
            timeout_in_seconds = 5.0
            ready = select.select([self.client_socket], [], [], timeout_in_seconds)
            if ready[0]:
                received_data = self.client_socket.recv(self.buffer_size)
        else:       # this is for reading data via serial connection, first we try to read three bytes where #3 is for byte length
            first_three_bytes = self.client_socket.read(3)
            if len(first_three_bytes) == 3:
                bytes_length = ReceivedFrame.getDataBlockLength(first_three_bytes)[1]
                received_data = first_three_bytes + self.client_socket.read(bytes_length-3)            
        return received_data 

    def quit(self, conn_status_val):
        """
        Close connection to DNP Client
        :return: String type
        """
        self.client_socket.close()
        if self.method in {'tcp', 'udp'} and self.open:
            logging_info_str = f'[RTU {self.dnp_address}] - Connection to outstation closed \
                ({self.client_ip}:{self.client_port}) with {self.method.upper()}'
        elif self.client_socket.is_open:
            logging_info_str = f'[RTU {self.dnp_address}] - Connection to outstation closed \
                ({self.com_port_name}:{self.baud_rate}) with {self.method.capitalize()}'
        self.logger.info(logging_info_str)
        conn_status_val.set(logging_info_str)
        self.open = False
        return 'red'