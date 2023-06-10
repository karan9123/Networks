# Traceroute
This is a Python script that performs traceroute to a network host. Traceroute is a diagnostic tool used to track the pathway taken by a packet on an IP network from source to destination.

## Usage
The script takes the following command line arguments:


```usage: traceroute.py [-h] [-n] [-q NQUERIES] [-S] host```

host: the host to trace the route to.
Optional arguments:

-n, --numeric: print hop addresses numerically rather than symbolically and numerically.
-q NQUERIES, --nqueries NQUERIES: set the number of probes per "ttl" to nqueries.
-S, --summary: print a summary of how many probes were not answered for each hop.
For example, to trace the route to google.com and print hop addresses numerically with 5 probes per "ttl", you can run the following command:

```$ sudo python traceroute.py -q 5 google.com```

## Implementation
The script uses the socket module to create sockets for sending and receiving packets. It sets the IP_TTL socket option to control the Time-to-Live (TTL) field of the IP header, which is used to limit the number of hops the packet can traverse.

The traceroute function takes four arguments:

#### host: the host to trace the route to.
#### nqueries: the number of probes per "ttl".
#### numeric: a boolean flag indicating whether to print hop addresses numerically.
#### summary: a boolean flag indicating whether to print a summary of unanswered probes per hop.

The function uses a while loop to iterate over the TTL values from 1 to 64, sending probes and receiving responses at each hop. It uses the time module to measure the time taken for a probe to complete the round trip. It prints the hop number, the IP address or hostname of the router at the hop, and the round-trip time in seconds. If the numeric flag is set, it prints the IP address numerically. If the summary flag is set, it prints a summary of how many probes were not answered for each hop.

Finally, the script uses the argparse module to parse the command line arguments. It calls the traceroute function with the parsed arguments.