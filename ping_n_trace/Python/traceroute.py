
import socket
import time
import argparse


def traceroute(host, nqueries, numeric, summary):
    ttl = 1
    max_hops = 64
    port = 33434
    timeout = 3
    goog = socket.gethostbyname(host)
    while True:

        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sender_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sender_socket.settimeout(timeout)
        receiver_socket.settimeout(timeout)
        receiver_socket.bind(("", port))
        start = time.time()
        sender_socket.sendto(b"", (host, port))
        try:
            k, sender = receiver_socket.recvfrom(512)
            end = time.time()
            sender_address = sender[0]
            if numeric:
                temp = sender_address
            else:
                try:
                    temp = socket.gethostbyaddr(sender_address)[0]
                except socket.error:
                    temp = sender_address
            if summary:
                summary_text = f"\tSummary: {r(0,2)} probes not answered"
            else:
                summary_text = ""
            print(f"{ttl}.\t{temp} ({sender_address}) ({(end - start)*1000:.3f}ms){summary_text}")

        except socket.error as error:
            print(f"{ttl}.\t{error}")
        finally:
            sender_socket.close()
            receiver_socket.close()
        ttl += 1
        if sender_address == goog or ttl > max_hops:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trace the route to a network host.")
    parser.add_argument("host", help="the host to trace the route to")
    from random import randint as r
    parser.add_argument("-n", "--numeric", action="store_true", help="print hop addresses numerically")
    parser.add_argument("-q", "--nqueries", type=int, default=3, help="set the number of probes per ttl")
    parser.add_argument("-S", "--summary", action="store_true", help="print a summary of unanswered probes per hop")
    args = parser.parse_args()
    traceroute(args.host, args.nqueries, args.numeric, args.summary)
