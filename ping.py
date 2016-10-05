import os
import sys
from socket import socket, AF_INET, IPPROTO_IP, SOCK_RAW, IPPROTO_ICMP, IP_HDRINCL
from StringIO import StringIO

def checksum(buffer):
    print '--- checksum input ---'
    print str(buffer)
    print '----------------------'
    cksum = 0
    dbg = list()

    for i in range(0,len(buffer)/2 + 1):
        # checksum done in network order?
        high_byte = buffer[2*i]
        low_byte = 0
        dbg.append(high_byte)
        if 2*i + 1 < len(buffer):
            low_byte = buffer[2*i+1]

        dbg.append(low_byte)
        value = (high_byte & 0xFF) << 8 | (low_byte & 0xFF)

        cksum += value

    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    cksum += (cksum >> 16)

    print '---checksum---'
    print str(dbg)
    return (~cksum) & 0xFFFF

class icmp_pkt:

    HEADER_LENGTH = 8

    def __init__(self, t_type, t_code, t_id, t_seq, t_data):
        self._byte_type = t_type
        self._byte_code = t_code
        self._word_checksum = 0
        self._word_id = t_id
        self._word_seq = t_seq

        # this is a sequence
        self._data = t_data

    def length(self):
        return self.HEADER_LENGTH + len(self._data)

    def serialize(self):
        s = self._serialize()
        c = checksum(s)
        self._word_checksum = c
        return self._serialize()

    def _serialize(self):
        s = list()
        s.append(self._byte_type)
        s.append(self._byte_code)
        icmp_pkt._write_word(s, self._word_checksum)
        icmp_pkt._write_word(s, self._word_id)
        icmp_pkt._write_word(s, self._word_seq)

        for i in xrange(len(self._data)):
            s.append(ord(self._data[i]))

        return s
    
    @staticmethod
    def _write_word(buffer, value):
        t = list()
        t.append((value & 0xFF00) >> 8)
        t.append(value & 0xFF)
        print '_write_word({0}) = {1}'.format(value, str(t))
        buffer.extend(t)

    @staticmethod
    def create_request(id, seq, data):
        return icmp_pkt(8, 0, id, seq, data)


    def parse(self, data, total_size):
        i = 20; # 20 bytes of ip header
        self._byte_type = ord(data[i]) & 0xFF
        i += 1
        self._byte_code = ord(data[i]) & 0xFF
        i += 1
        self._word_checksum = self.parse_word(data,i)
        i += 2
        self._word_id = self.parse_word(data,i)
        i+= 2
        self._word_seq = self.parse_word(data,i)
        i += 2

        payload_size = total_size - 8 - 20

        payload = list()
        for j in xrange(payload_size):
            payload.append(data[i+j])

        self._data = payload

    def parse_word(self, data, index):

        upper = ord(data[index])
        index += 1
        lower = ord(data[index])

        value = ((upper & 0xFF) << 8) | (lower & 0xFF)

        return value

    def data(self):
        return self._data

    def __str__(self):
        return '-- {0} {1} {2} {3} {4} [{5}]'.format(
            self._byte_type,
            self._byte_code,
            hex(self._word_checksum),
            hex(self._word_id),
            hex(self._word_seq),
            self._data)



def main():
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 0)
    sock.bind(('127.0.0.1', 0))

    pkt = icmp_pkt(8,0,256,257, 'hello')
    #import pdb;pdb.set_trace()
    s = pkt.serialize()
    print '{' + str(pkt) + '}'
    print '[' + str(s) + ']'

    buffer = StringIO()
    for c in s:
        buffer.write(chr(c))

    print buffer.getvalue()
    retval = sock.sendto(buffer.getvalue(), ('127.0.0.1', 0))

    print retval

    (data, address) = sock.recvfrom(1024)

    print data
    print len(data)
    print address

    import pdb;pdb.set_trace()
    resp = icmp_pkt(None, None, None, None, None)
    resp.parse(data, len(data))

    print str(resp)
    print resp.data()


if __name__ == '__main__':
    main()

