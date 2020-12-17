#server

import socket
import enum
import sys
import os
import struct
import time



class Tftp(object):
    """
    Реализует логику для клиента TFTP.
    Входом в этот объект является полученный пакет UDP, выходом - пакеты, которые должны быть записаны в сокет.
    Этот класс НЕ ДОЛЖЕН ничего знать о существующих сокетах, его входные и выходные данные являются ТОЛЬКО байтовыми массивами.
    Сохраните выходные пакеты в буфере (некотором списке) в этом классе, функция get_next_output_packet
    возвращает первый элемент в пакетах, которые должны быть отправлены.
    Этот класс также отвечает за чтение / запись файлов на жесткий диск.
    Несоблюдение этих требований аннулирует вашу заявку.
    Не стесняйтесь добавлять в этот класс дополнительные функции, если эти функции не взаимодействуют с сокетами
    или входами от пользователя / сокетов. Например, вы можете добавить функции, которые, по вашему мнению, являются
    только «частными». Частные функции в Python начинаются с символа «_», см. Пример ниже.
    """


    class TftpPacketType(enum.Enum):
        """
        Представляет тип пакета TFTP,
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):

        opcode = Tftp.TftpPacketType.RRQ
        self.port = 69  ### 69 порт от сервера
        self.root_path = '//'
        self.client_address = None
        self.client_port = 0
        self.file_path = ''
        self.file_block_count = 0
        self.last_block_num = 0  # занимает 2 байта

        self.fail = False
        self.sent_last = False # отправлено последним
        self.ignore_current_packet = False  # игнорировать его, если источником полученных пакетов является другой порт
        self.tftp_mode = 'octet'  # режим по умолчанию
        self.request_mode = None  # 'RRQ' or 'WRQ'
        self.server_address = ('127.0.0.1', 69)
        self.file_bytes = []
        self.reached_end = False # достиг конца
        self.packet_buffer = []

    def set_client_address(self, client_address):
        self.client_address = client_address
        #  порт клиента, необходимый для проверки случайных пакетов
        self.client_port = client_address[1]  # адрес клиента-это кортеж ip  и номера порта

    def process_udp_packet(self, packet_data, packet_source):
        """
        packet data представляют собой массив байтов,
        packet source содержит адресную информацию отправителя.
        """
        #print(f"Received a packet from {packet_source}")
        #print('rec:',packet_data)
        self.ignore_current_packet = False
        in_packet = self._parse_udp_packet(packet_data)
        if self.ignore_current_packet:  # не добавлять текущий пакет в буфер
            return
        out_packet = self._do_some_logic(in_packet)
        if out_packet == []:  # последний пакет в файле подтвержден
            return
        #print('sending:',out_packet)
        self.packet_buffer.append(out_packet)
        #print('packet_buffer:',self.packet_buffer)

    def _parse_udp_packet(self, packet_bytes):
        return packet_bytes

    def _generate_error_packet(self, error_code, error_message=''):
        # error packet format 2bytes opcode(5), 2 bytes error code, error_msg, a 0byte at the end
        # error packet формат пакета 2 байта код операции (5), 2 байта кода ошибки, error_msg, 0 байт в конце
        error_packet = struct.pack('!HH', Tftp.TftpPacketType.ERROR.value, error_code)
        error_packet += struct.pack('!{}sB'.format(len(error_message)), error_message.encode(), 0)

        return error_packet

    def _do_some_logic(self, input_packet):
        """
        """
        # input_packet - это байты данных в пакете udp
        opcode = struct.unpack('!H', input_packet[0:2])[0]
        packetTypes = {1: 'RRQ', 2: 'WRQ', 3: 'DATA', 4: 'ACK', 5: 'ERROR'}
        curr_pack_type = packetTypes[opcode]
        filename = ''
        try:
            packet_type = Tftp.TftpPacketType(opcode)
        except ValueError:  # Незаконная операция TFTP означает недопустимый код операции
            self.reached_end = True
            err_msg = 'Illegal TFTP OPERATION'
            print(err_msg)
            # return ERROR Packet with opcode = 5, error code = 4, error message encoded, and a 0 byte
            # вернуть пакет ERROR с opcode = 5, error code = 4, закодированным сообщением об ошибке и нулевым байтом
            return self._generate_error_packet(error_code=4, error_message=err_msg)

        if packet_type == Tftp.TftpPacketType.RRQ or packet_type == Tftp.TftpPacketType.WRQ:  # HERE***************************
            # Обработка общей логики между пакетом RRQ и WRQ
            # очистить байты файла
            self.file_bytes = []
            self.request_mode = packetTypes[opcode]
            seperator_idx = 2 + input_packet[2:].find(0)
            filename_bytes = input_packet[2:seperator_idx]

            fmt_str = '!{}s'.format(len(filename_bytes))
            # распаковать байты и получить путь к файлу из кортежа
            self.file_path = struct.unpack(fmt_str, filename_bytes)[0]
            # запрещен доступ к файлам сервера!
            if str(self.file_path, encoding='ascii') == os.path.basename(__file__):
                self.reached_end = True
                self.fail = True
                return self._generate_error_packet(error_code=0, error_message="Access Forbidden")

            # режим всегда кодируется ascii
            self.tftp = str(input_packet[seperator_idx + 1:-1], 'ascii').lower()
            # print(self.tftp_mode)

        if packet_type == Tftp.TftpPacketType.ACK and self.sent_last:  # последний пакет подтвержден

            self.sent_last = False
            # конец передачи
            self.reached_end = True
            # вернуть известное значение, чтобы функция process_udp_ знала, что делать
            return []

        if packet_type == Tftp.TftpPacketType.RRQ:  ##RRQ
            err = self.read_file()  # возвращает True, если файл не существует на сервере
            if err:
                ## error code =1 opcode = 5
                err_msg = 'File not found.'

                self.reached_end = True
                print(err_msg)
                return self._generate_error_packet(error_code=1, error_message=err_msg)

        if packet_type == Tftp.TftpPacketType.WRQ:  ##WRQ
            # ответ с подтверждением с номером блока = 0, если файл не существует на сервере
            if os.path.exists(self.file_path):  # проверяет, существует ли файл на сервере
                error_code = 6
                err_msg = 'File already exists'
                self.reached_end = True
                print(err_msg)
                return self._generate_error_packet(error_code=error_code, error_message=err_msg)

            out_packet = struct.pack('!HH', Tftp.TftpPacketType.ACK.value, 0)
        elif packet_type == Tftp.TftpPacketType.DATA:  # Data
            # print('in',input_packet)
            block_num = struct.unpack('!H', input_packet[2:4])[0]

            if len(input_packet) > 4:  # последний пакет данных может иметь 0 байтов
                len_data = len(input_packet[4:])
                if len_data != 512:
                    self.sent_last = True
                    self.reached_end = True
                if self.tftp_mode == 'octet':
                    fmt_str = '!{}B'.format(len_data)
                else:  # netascii
                    fmt_str = '!{}s'.format(len_data)
                unpacked_data_bytes = struct.unpack(fmt_str, input_packet[4:])

                # print('db',len(unpacked_data_bytes),'--', unpacked_data_bytes)
                # добавить байты полученного блока к байтам файла, чтобы их можно было записать после окончания передачи
                self.file_bytes.extend(unpacked_data_bytes)
            else:  # достиг конца передачи
                self.reached_end = True

            out_packet = struct.pack('!HH', Tftp.TftpPacketType.ACK.value, block_num)

        elif packet_type == Tftp.TftpPacketType.ERROR:
            self.reached_end = True
            err_msg = 'Not defined :' + str(input_packet[4:-1], encoding='ascii')
            print(err_msg)
            # вернуть пакет ERROR с opcode = 5, error code = 0, закодированным сообщением об ошибке и 0 байтом
            return self._generate_error_packet(error_code=0, error_message=err_msg)
            # struct.pack('!HH', 5, 0) + struct.pack('!{}sB'.format(len(err_msg)), err_msg.encode(), 0)

        if packet_type == Tftp.TftpPacketType.ACK or packet_type == Tftp.TftpPacketType.RRQ:
            # ответить на RRQ с первым блоком и ACK с другими блоками
            if packet_type == Tftp.TftpPacketType.RRQ:
                block_num = 1
            else:
                block_num = struct.unpack('!H', input_packet[2:4])[0] + 1
            # print('bno',block_num)
            # get data block after the one in the acknowledge packet , or the first 1 if its a rrq
            # получить блок данных после блока подтверждения, или первый 1, если это RRQ
            data_blocks = self.get_next_data_block(block_num)

            len_data = len(data_blocks)
            if len_data > 0:  # проверьте, не пустые ли данные (есть еще заблокированные для отправки)
                format_char = ''
                if self.tftp_mode == 'octet':
                    format_char = '!B'
                elif self.tftp_mode == 'netascii':
                    format_char = '!s'
                ### data_blocks преобразовать в требуемый тип данных
                out_packet = struct.pack('!HH', Tftp.TftpPacketType.DATA.value, block_num)
                for byte in list(data_blocks):
                    out_packet += struct.pack(format_char, byte)
            else:  # if file size %512 == 0 тогда последний пакет данных не будет иметь блоков данных
                out_packet = struct.pack('!HH', Tftp.TftpPacketType.DATA.value, block_num)
            # print('outdata:',out_packet)
        return out_packet

    def ignore_current(self):
        return self.ignore_current_packet

    def get_next_data_block(self, block_num):
        # индексировать массив файловых блоков, поскольку номер блока начинается с 1, поэтому вычитаем
        start_idx = (block_num - 1) * 512
        end_idx = start_idx + 512

        if end_idx > (self.file_block_count):  # если последний блок меньше 512
            # конец передачи
            self.sent_last = True
            # self.reached_end = True
            return self.file_bytes[start_idx:]
        elif end_idx == self.file_block_count:  # отправить пустой блок данных в конце (конец передачи), если размер файла кратен 512
            self.sent_last = True
            return []
        return self.file_bytes[start_idx: end_idx]

    def get_next_output_packet(self):
        """
        Возвращает следующий пакет, который необходимо отправить.
        Эта функция возвращает массив байтов, представляющий следующий пакет для отправки.
        """

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self): # ожидется отправка пакетов
        """
        Возвращает, если доступны какие-либо пакеты для отправки.
        """
        return len(self.packet_buffer) != 0

    def save_file(self):
        if not self.fail:
            with open(self.file_path, 'wb') as up_file:
                up_file.write(bytes(self.file_bytes))

    def read_file(self):
        try:
            with open(self.file_path, 'rb') as f:
                self.file_bytes = list(f.read())
                self.file_block_count = len(self.file_bytes)
            return False
        except FileNotFoundError:  # файл не существует. верните True, чтобы указать, что произошла ошибка
            return True

    def get_request_mode(self):
        return self.request_mode

    def transmission_ended(self):  # возвращает True, если переданный блок последний
        return self.reached_end

    def set_client_address(self, client_address):
        self.client_address = client_address
        # порт клиента, необходимый для проверки случайных пакетов
        self.client_port = client_address[1]  # адрес клиента - это набор IP и номера порта

    def get_file_path(self):
        return str(self.file_path, encoding='ascii')

    def get_file_size(self):
        return len(self.file_bytes)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

def setup_sockets(address):
    """
    Возвращает socket
    """
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.bind(address)
    return my_socket



def get_arg(param_index, default=None):
    """
    Получает аргумент командной строки по индексу (примечание: индекс начинается с 1)
    Если аргумент не предоставлен, он пытается использовать значение по умолчанию.
    Если значение по умолчанию не указано, выводится сообщение об ошибке, и программа завершается.
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
            exit(-1)    # Ошибка выполнения программы.


def main():
    host = '127.6.0.1'
    ip_address = get_arg(1, "127.0.0.1")
    server_address = (ip_address, 69)
    s = setup_sockets(server_address)

    while True:
        print('Waiting for a connection...')
        tftp_proc = Tftp()
        # получить пакет, содержащий строку запроса (RRQ или WRQ)
        request_packet, client_address = s.recvfrom(2048)
        # путь к файлу может быть самым большим блоком в пакете, поэтому размер пакета не может превышать 2048 байт

        tftp_proc.set_client_address(client_address)
        print(client_address, "   ", request_packet)

        print('Connected to ', client_address)
        # print('REQUEST pack:', request_packet)
        tftp_proc.process_udp_packet(request_packet, client_address)
        request_mode = tftp_proc.get_request_mode()

        if request_mode == 'RRQ' or request_mode == 'WRQ':

            while tftp_proc.has_pending_packets_to_be_sent():  # продолжаем посылать "буферизованные" пакеты
                # отправить ответный пакет на ранее полученный пакет

                next_packet = tftp_proc.get_next_output_packet()
                s.sendto(next_packet, client_address)

                if not tftp_proc.transmission_ended():  # получить следующий пакет, если не дошли до конца передачи

                    received_packet, received_client = s.recvfrom(2048)
                    # print('PROCESSING')
                    tftp_proc.process_udp_packet(received_packet, received_client)


                else:
                    print('TRANSMISSION ENDED')
                while tftp_proc.ignore_current():  # если получен случайный пакет, игнорируя его получить другой пакет
                    received_packet, received_client = s.recvfrom(2048)
                    tftp_proc.process_udp_packet(received_packet, received_client)
            # print(tftp_proc.file_bytes)
            print('file path on server:', tftp_proc.get_file_path())
            print(tftp_proc.get_file_size(), ' bytes transmitted ')

            if request_mode == 'WRQ':
                # сохранить файл после получения файла
                tftp_proc.save_file()


        else:
            print('ERROR!')
        
        time.sleep(1)

if __name__ == '__main__':
    main()

