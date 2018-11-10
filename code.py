import logging
import os
import sys
from scapy.all import rdpcap

LOG = logging.getLogger("main")

def main():
    if len(sys.argv) < 2:
        raise ValueError("Usage: %s <pcap file>" % os.path.basename(sys.argv[0]))

    pcap_filename = sys.argv[1]
    pcap_packets = rdpcap(pcap_filename)

    LOG.info("Loaded %s: %r", pcap_filename, pcap_packets)

    # define our variables for counts
    dns_payloads = 0
    answer_rrs = 0
    packet_sizes = []
    domains_by_ip = {}
    zones = {}
    rcodes = {}
    timings = {}

    for pkt in pcap_packets:
        
        #pkt is a dictionary

        # get the size of the packet
        packet_sizes = calculate_packet_size(packet=pkt, packet_sizes=packet_sizes)
   
        # find DNS packets (filter on TCP/UDP port 53 instead?)
        if 'DNS' in pkt:
            # dns is only UDP/TCP
            if 'TCP' in pkt or 'UDP' in pkt:
                # keep count of the number of dns payloads 
                dns_payloads += 1

                # keep count of RCODES
                # pkt['DNS'].rcode is int
                rcodes = calculate_rcodes(rcode=str(pkt['DNS'].rcode), rcodes=rcodes)
 
                # store timings for the DNS requests
                timings = store_timings(packet=pkt, timings=timings)

                # set domain we are working with                
                domain = pkt['DNSQR'].qname.decode('utf-8')

                # DNS query
                if pkt["DNS"].qr == 0:
                    # figure out the zones being requested
                    zones = calculate_zones(domain=domain, zones=zones)
                    
                    # store ip and domain combination
                    ip = pkt['IP']
                    domains_by_ip = calculate_domains_by_ip(ips=[ip.src, ip.dst], domain=domain, domains_by_ip=domains_by_ip)

                # DNS response
                else:
                    # figure out the response with the most answer resource records
                    ancount = pkt['DNS'].ancount
                    if ancount > answer_rrs:
                        answer_rrs = ancount
                        dns_response = pkt['DNS']
                        dns_response_domain = domain

    # results   
    # show average/median packet size
    LOG.info("Averge packet size is {}".format(sum(packet_sizes) / len(packet_sizes)))
    LOG.info("Median packet size is {}".format(calculate_median(packet_sizes)))
    
    # show number of dns payloads
    LOG.info("Number of DNS payloads is {}\n".format(dns_payloads))
    
    # show response with most resource records  
    LOG.info("The DNS response for '{}' has the greatest number answer RRs with {}\n".format(dns_response_domain, answer_rrs))
    LOG.info('The actual DNS response for it is %r', dns_response)

    # show histograms
    LOG.info(display_histogram(rcodes))

    # show top 5 zones
    LOG.info(display_top_zones(zones))

    # show top domains by ip
    LOG.info(display_top_domains_by_ip(domains_by_ip))
    
    # show latency timings
    LOG.info(display_latency_timings(timings))

    LOG.info("Done.")


def store_timings(**kwargs):
    """
    Keep the timestamps by request in a grouped manner so we can figure out the latency
    """
    pkt = kwargs['packet']
    timings = kwargs['timings']

    domain = pkt['DNSQR'].qname.decode('utf-8')
    dns_query_type = str(pkt['DNSQR'].qtype)
    dns_id = pkt['DNS'].id
    type = 'request'
    
    if pkt["DNS"].qr == 1:
        type = 'response'

    #domain - dns_id - request/response - query type like A record/ MX record etc - time
    timings.setdefault(domain, {}).setdefault(dns_id, {}).setdefault(type, {}).setdefault(dns_query_type, {}).setdefault('time', []).append(pkt.time)
    
    return timings


def display_latency_timings(timings):
    """
    Calculate average and 95th percentile latency timings of the requests based on the uniqueness of the domain, dns id, type of response and type of request built in 'store_timings'
    """
    
    #{'domain.com.': {45786: {'response': {'1': {'time': [1533764303.653304]}}, 'request': {'1': {'time': [1533764303.652825]}}}, 2002: {'response': {'28': {'time': [1533764303.758608]}}, 'request': {'28': {'time': [1533764303.652919]}}}}}
    total_times = []
    for domain, results in timings.items():
        for id, repsonses in results.items():
            request = repsonses['request']
            response = repsonses['response']
            for type in request:
                # times is an array to handle instances where there are multiple timestamps for the same type of request
                for index in range(len(request[type]['time'])):
                    request_timestamp = request[type]['time'][index]
                    response_timestamp = response[type]['time'][index]
                    
                    # subtract the response from the request to get the time taken
                    total_times.append(response_timestamp - request_timestamp)

    ## average latency
    number_of_timings = len(total_times)
    average_latency = sum(total_times) / number_of_timings
    output = "Average latency is {}\n".format(average_latency)
    
    # calculate 95th percentile
    total_times.sort()

    # calculate index and subtract 1 since arrays start at index 0
    index = round((95/100) * number_of_timings) - 1
    
    output += '95th percentile latency is {}'.format(total_times[index])
    
    return output
 
       
def calculate_packet_size(**kwargs):
    """
    Get the packet size using ip.len plus the ethernet header. len(packet) yielded correct results is most cases except for a few edge cases which I couldn't account for (really large/small packets)
    I was really torn on how to do this and landed on this approach.
    """
    packet = kwargs['packet']
    packet_sizes = kwargs['packet_sizes']

    # add 14 byte ethernet header?
    ethernet_header_size = 14

    packet_size = 0
    if 'IP' in packet:
        packet_size = packet['IP'].len + ethernet_header_size

    # ARP (other)
    # this size is just an educated guess based on some research
    else:
        packet_size = 28 + ethernet_header_size

    packet_sizes.append(packet_size)

    return packet_sizes


def calculate_rcodes(**kwargs):
    """
    Keep a running total of the rcodes
    """
    rcode = kwargs['rcode']
    rcodes = kwargs['rcodes']
    
    if rcode not in rcodes:    
        rcodes[rcode] = 1
    else:
        rcodes[rcode] += 1

    return rcodes


def calculate_domains_by_ip(**kwargs):
    """
    Keep a running total of domains per source/destination IP
    """
    ips = kwargs['ips']
    domains_by_ip = kwargs['domains_by_ip']
    domain = kwargs['domain']
    
    # group on just the domain name so strip off www if its there
    parts = domain.split('.')
    if parts[0] == 'www':
        parts.pop(0)
    domain = '.'.join(parts)
 
    for ip in ips:
        if ip not in domains_by_ip:
            domains_by_ip[ip] = {}
        else:
            if domain not in domains_by_ip[ip]:
                domains_by_ip[ip][domain] = 1
            else:
                domains_by_ip[ip][domain] += 1

    return domains_by_ip

   
def calculate_zones(**kwargs):
    """
    Keep a running total of the zones by splitting the domain and putting the pieces into a dictionary
    """
    zones = kwargs['zones']
    domain = kwargs['domain']

    # split on periods and discard the last element since its empty
    # ex: domain.com.
    split_domain = domain.split('.')
    split_domain.pop()
       
    # add the domain to the zone since its technically a zone
    if domain not in zones:
        zones[domain] = 1
    else:
        zones[domain] += 1
               
    for zone in split_domain:
        # ignore www since its not a dns zone OR ignore zone[0] entirely as the TLDs are most likely always the top of the most requested?
        if zone == 'www':
            continue

        # add the zones to the counts
        if zone not in zones:
            zones[zone] = 1
        else:
            zones[zone] += 1

    return zones


def calculate_median(sizes):
    """
    Calculate the median, this could be done using a library
    """
    sorted_sizes = sorted(sizes)
    length = len(sizes)
    index = (length - 1) // 2

    if (length % 2):
        return sorted_sizes[index]
    else:
        return (sorted_sizes[index] + sorted_sizes[index + 1])/2.0

    
def sort_by_size(domains):
    """
    Sort the domains dictionary by count then name
    """
    return sorted(domains.items(), key=lambda item: (item[1], item[0]), reverse=True)


def display_top_zones(zones):
    """
    Show the top 5 zones tallied from 'calculate_zones'
    """
    sorted_zones = sort_by_size(zones)

    output = "Top 5 requested zones:\n"
    for (zone, count) in sorted_zones[0:5]:
        output += "{} ({})\n".format(zone, count)

    return output

       
def display_top_domains_by_ip(ips):
    """
    Show the top requested domains by IP address tallied from 'calculate_rcodes'
    """

    output = "Top Requested Domains by IP\n"
    for ip in ips:
        domains = ips[ip]
        sorted_domains = sort_by_size(domains)

        output += "{}: {} ({})\n".format(ip, sorted_domains[0][0], sorted_domains[0][1])

    return output

 
def display_histogram(codes):
    """
    Creates a histogram of rcodes tallied from 'calculate_rcodes'
    """
    output = "Histogram of RCODEs\n"

    for code in codes:
        count = codes[code]
        stars = ('*' * count)
        output += 'RCODE:{}: {} ({})'.format(code, stars, count) + "\n";
    
    return output

if __name__ == "__main__":
    logging.basicConfig(
        format="[%(funcName)s] %(message)s",
        level=logging.INFO)
    main()
