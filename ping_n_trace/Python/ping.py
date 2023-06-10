import argparse
import socket
import struct
import time

ICMP_ECHO_REQUEST = 8
DEFAULT_TIMEOUT = 5
DEFAULT_COUNT = 1000
DEFAULT_PACKET_SIZE = 64

def checksum(packet):
    csum = 0
    countTo = (len(packet) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = packet[count+1] * 256 + packet[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(packet):
        csum = csum + packet[len(packet) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def ping(srcaddress, count=4, timeout=4, packet_size=56, wait=1):
    icmp_type = 8
    icmp_code = 0
    sequence = 0
    identifier = 42
    rtt_lst = []
    start = time.time()
    for i in range(count):
        # identifier +=1
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        icmp_packet = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, sequence)
        packet_checksum = checksum(icmp_packet + bytes(range(packet_size)))
        icmp_packet = struct.pack("!BBHHH", icmp_type, icmp_code, packet_checksum, identifier, sequence)
        send_time = time.time()
        sock.sendto(icmp_packet + bytes(range(packet_size)), (srcaddress, 1))
        sock.settimeout(timeout)
        try:
            data, address = sock.recvfrom(1024)
            recv_time = time.time()
            rtt = (recv_time - send_time) * 1000
            rtt_lst.append(rtt)
            print(f"{packet_size} bytes from {address[0]}: icmp_seq={sequence} ttl={data[8]} time={rtt:.3f} ms")
        except socket.timeout:
            print(f"Request timeout for icmp_seq {sequence}")
        sequence += 1
        sock.close()
        time.sleep(wait)
    print(f"\nPing statistics for {srcaddress}:")
    print(f"Packets: Sent = {count}, Received = {sequence-1}, Lost = {count - sequence+1} ({(count-sequence+1)/count*100:.1f}% loss),")
    print(f"Approximate round trip times in milli-seconds:\nMinimum = {min(rtt_lst):.3f}ms, Maximum = {max(rtt_lst):.3f}ms, Average = {sum(rtt_lst) / len(rtt_lst):.3f}ms")




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dest_addr", help="The destination address or hostname to ping.")
    parser.add_argument("-c", "--count", type=int, default=DEFAULT_COUNT,
                        help="Stop after sending count ECHO_RESPONSE packets.")
    parser.add_argument("-i", "--wait", type=float, default=1, help="Wait wait seconds between sending each packet.")
    parser.add_argument("-s", "--packetsize", type=int, default=DEFAULT_PACKET_SIZE,
                        help="Specify the number of data bytes to be sent.")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Specify a timeout, in seconds, before ping exits.")
    args = parser.parse_args()

    ping(args.dest_addr, args.count, args.timeout, args.packetsize, args.wait)

