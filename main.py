import json
import zlib
import struct
import requests
import re

class Doc88Enc:
    def __init__(self):
        self.config = {}
        self.input_str = None  # 存储输入的字符串
        self.index = 0  # 当前读取位置
        self.end_of_input = -1  # 结束标记
        F0 = "U"
        rs = "g"
        self.client_base64_table = [
            "P", "J", "K", "L", "O", "N", "M", "I", "3", "x", "y", "z", "0", "1", "2", "w", "v", "p", "r", "q", "s",
            "t", "u", "o", "H", "B", "C", "D", "E", "F", "G", "A", "n", "h", "i", "j", "k", "l", "m",  rs, "f", "Z",
            "a", "b", "c", "d", "e", "Y", "X", "R", "S", "T",  F0, "V", "W", "Q", "!", "5", "6", "7", "8", "9", "+",
            "4"
        ]
        self.client_base64_table[4] = "M"
        self.client_base64_table[6] = "O"

        self.client_decode_base64_table = {v: k for k, v in enumerate(self.client_base64_table)}

        tmp = [
            "P", "J", "L", "K", "M", "N", "O", "I", "3", "x", "y", "z", "0", "2", "1", "w", "v", "r", "p", "q", "s",
            "t", "o", "u", "H", "C", "F", "B", "D", "E", "G", "A", "n", "h", "i", "k", "j", "l", "m", "g", "f", "Z",
            "b", "a", "c", "e", "d", "Y", "R", "X", "T", "S", "U", "V", "Q", "W", "!", "5", "6", "7", "8", "9", "+",
            "4"
        ]
        self.server_base64_table = {}
        for i in range(len(tmp)):
            self.server_base64_table[tmp[i]] = i

    def initialize_input(self, input_str):
        """初始化输入字符串和指针"""
        self.input_str = input_str
        self.index = 0

    def read_byte_with_server_base64_table(self):
        """从字符串中读取下一个字节（服务器数据解密）"""
        if not self.input_str or self.index >= len(self.input_str):
            return self.end_of_input
        byte_value = self.input_str[self.index]
        self.index += 1
        if self.server_base64_table.get(byte_value, None) is not None:
            return self.server_base64_table[byte_value]
        if byte_value == ord('P'):
            return 0
        return self.end_of_input

    def read_byte(self):
        """从字符串中读取下一个字节"""
        if not self.input_str or self.index >= len(self.input_str):
            return self.end_of_input
        byte_value = ord(self.input_str[self.index]) & 255
        self.index += 1
        return byte_value

    def encode_client_data_to_base64(self, input_str):
        """加密客户端数据"""
        self.initialize_input(input_str)
        encoded_str = ""
        buffer = [0] * 3
        done = False

        while not done:
            buffer[0] = self.read_byte()
            if buffer[0] == self.end_of_input:
                break
            buffer[1] = self.read_byte()
            buffer[2] = self.read_byte()

            encoded_str += self.client_base64_table[buffer[0] >> 2]
            if buffer[1] != self.end_of_input:
                encoded_str += self.client_base64_table[((buffer[0] << 4) & 48) | (buffer[1] >> 4)]
                if buffer[2] != self.end_of_input:
                    encoded_str += self.client_base64_table[((buffer[1] << 2) & 60) | (buffer[2] >> 6)]
                    encoded_str += self.client_base64_table[buffer[2] & 63]
                else:
                    encoded_str += self.client_base64_table[((buffer[1] << 2) & 60)]
                    encoded_str += "="
                    done = True
            else:
                encoded_str += self.client_base64_table[((buffer[0] << 4) & 48)]
                encoded_str += "=="
                done = True

        return encoded_str

    def decode_client_data_from_base64(self, encoded_str):
        """解码客户端数据"""
        self.initialize_input(encoded_str)
        decoded_bytes = bytearray()
        buffer = [0] * 4

        while True:
            # 读取四个字符，并将其转换为 Base64 表中的值
            for i in range(4):
                byte = self.read_byte()
                if byte == self.end_of_input:
                    buffer[i] = self.end_of_input
                else:
                    char = chr(byte)
                    buffer[i] = self.client_decode_base64_table.get(char, self.end_of_input)

            # 处理解码逻辑
            if buffer[0] == self.end_of_input:
                break

            # 解码第一个字节
            decoded_bytes.append((buffer[0] << 2) | (buffer[1] >> 4))

            # 解码第二个字节，如果有足够的数据
            if buffer[2] != self.end_of_input:
                decoded_bytes.append(((buffer[1] << 4) & 0xF0) | (buffer[2] >> 2))

                # 解码第三个字节，如果有足够的数据
                if buffer[3] != self.end_of_input:
                    decoded_bytes.append(((buffer[2] << 6) & 0xC0) | buffer[3])

        return decoded_bytes.decode()

    def decode_server_data_from_base64(self, encoded_str):
        """解密服务器返回数据"""
        self.initialize_input(encoded_str)
        decoded_str = bytearray()
        buffer = [0] * 4
        done = False
        while not done:
            buffer[0] = self.read_byte_with_server_base64_table()
            buffer[1] = self.read_byte_with_server_base64_table()
            if buffer[0] == self.end_of_input or buffer[1] == self.end_of_input:
                break
            buffer[2] = self.read_byte_with_server_base64_table()
            buffer[3] = self.read_byte_with_server_base64_table()

            decoded_str.append(((buffer[0] << 2) & 255) | buffer[1] >> 4)
            if buffer[2] != self.end_of_input:
                decoded_str.append(((buffer[1] << 4) & 255) | buffer[2] >> 2)
                if buffer[3] != self.end_of_input:
                    decoded_str.append(((buffer[2] << 6) & 255) | buffer[3])
                else:
                    done = True
            else:
                done = True

        return decoded_str.decode('utf8')

    def load_config(self, json_str):
        js = json.loads(json_str)
        headerInfo = js['headerInfo'].split(',')
        pages = {}
        for i in range(len(headerInfo)):
            pages[i] = int(headerInfo[i].replace('"', ''))
        p_code = js['p_code']
        p_swf = js['p_swf']
        page_info = self.decode_server_data_from_base64(js['pageInfo']).split(',')
        pageCount = js['pageCount']
        ebt_host = js['ebt_host']
        print(pages)
        print(p_code)
        print(p_swf)
        print(page_info)
        print(pageCount)
        print(ebt_host)
        print('preview:', js['mpp'])
        self.config = {
            'pageInfo': page_info,
            'pageCount': pageCount,
            'pages': pages,
            'p_code': p_code,
            'p_swf': p_swf,
            'ebt_host': ebt_host,
            'source': js
        }
        # ph = '/getebt-' + b64(page + '-0-' + pages[page - 1] + '-' + p_swf) + '.ebt'
        # pk = "/getebt-" + b64(page + "-" + _Ev + "-" + _jo + "-" + p_swf + "-" + _xF + "-" + Viewer._7I)

    def get_page(self, count):
        conf = self.config['pageInfo'][count - 1].split('-')
        ca = conf[0]
        ev = conf[3]
        jo = conf[4]
        j4 = conf[1]
        jd = conf[2]
        ph = self.config['ebt_host'] + '/getebt-' + self.encode_client_data_to_base64(ca + '-0-' + str(self.config['pages'][int(ca) - 1]) + '-' + self.config['p_swf']) + '.ebt'
        pk = self.config['ebt_host'] + '/getebt-' + self.encode_client_data_to_base64(ca + "-" + ev + "-" + jo + "-" + self.config['p_swf'] + "-" + str(count) + "-" + self.config['p_code']) + '.ebt'
        print(ph)
        print(pk)
        ph_b = requests.get(ph).content
        pk_b = requests.get(pk).content
        print(len(ph_b))
        print(len(pk_b))
        try:
            data = self.decrypt_ebt(ph_b, pk_b)
            with open('pages/' + str(count) + '.swf', "wb") as f:
                f.write(data)
        except Exception as e:
            print(e)
            with open('pages/' + str(count) + '-ph.ebt', "wb") as f:
                f.write(ph_b)
            with open('pages/' + str(count) + '-pk.ebt', "wb") as f:
                f.write(pk_b)

    def decrypt_ebt(self, ph, pk):
        # ph has to be explicitely declared as mutable bytearray because it will be modified later for file length below.
        ph = bytearray(zlib.decompress(ph[40:]))
        # This might not be necessary
        ph[4:8] = struct.pack('<I', len(ph))

        # ph has to be explicitely declared as mutable bytearray because it will be modified later for file length below.
        pk = bytearray(zlib.decompress(pk[32:]))

        out = ph + pk + bytearray([64]) + bytearray([0]) + bytearray([0]) + bytearray([0])
        out[4:8] = struct.pack('<I', len(out))

        return out

    def get_config(self, url):
        # https://www.doc88.com/p-09439572066792.html
        html = requests.get(url).text
        # find m_main.init("xxx");
        result = re.findall(r'm_main.init\("(.*?)"\)', html)
        return result[0]

print()

doc88 = Doc88Enc()

# encoder = CustomBase64Encoder()
# decoded_string = encoder.decode_from_base64("0rUU0jkR1Lsd0qvUzqsVzq3X0jvX0TOQzq3X0jvX0TOQ0LET0j3XoW8SpWFNsWvTzqvd0LkU0TkV1T3X1jHQ2q3=")
# print("解码后的原始字符串:", decoded_string)
# decoded_string = encoder.decode_from_base64("0rUU0jkS2Lkd0qHW1qHd1qsd0jPS1LPT0qEd0jPS1LPT0qEX1T0S0jJADTxIBUtqBL0d1rUX2qvT2qsQ0jPW1jE50n==")
# print("解码后的原始字符串:", decoded_string)

decoded_string = doc88.decode_server_data_from_base64(doc88.get_config('https://www.doc88.com/p-09439572066792.html'))
doc88.load_config(decoded_string)
doc88.get_page(4)
for i in range(1, doc88.config['pageCount']):
    print('download', i)
    doc88.get_page(i)
