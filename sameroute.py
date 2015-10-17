#############################################################################################################
#                                                                                                           #
#            Abertay University: Networking & Security 3 - Lab 8                                            #
#       -->  VISUAL TRACEROUTE - PYTHON 2.7 - NODE GEOLOCATION - PYTHON TO KML TO GOOGLE EARTH              #    
#            Written by Samantha Isabelle Beaumont                                                          #
#            LinkedIn: www.linkedin.com/in/sambeaumont                                                     #
#            Twitter: PANTH13R                                                                              #
#            Tag Name: PANTH13R                                                                             #
#                                                                                                           #
#############################################################################################################


import argparse, socket, sys, json, requests, simplekml, subprocess, platform, signal, errno, os, struct, time
from html import HTML

#################################################################################################GLOBAL VARIABLES#####################################################################################################################

# Returns JSON object w/ information about target IP
GEO_URL = "http://pablocrossa.appspot.com/ip-api.com/json/"
# "http://ip-api.com/json/"
# WHOIS 
WHOIS_URL = 'http://whois.domaintools.com/'
# UDP port 
UDP_PORT = 33434

# for platform display
if 'windows' in platform.system().lower(): WINDOWS = True
else: WINDOWS = False

# Get process ID for packet creation
own_id = os.getpid() & 0xFFFF

#rand values for packet creation
global seq_number
global packet_size
ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 2048 # Max size of incoming buffer

##################################################################################################NODE() CLASS########################################################################################################################
                                                             
#       - Holds information about each node in the route                       
#       - Can be built with only ip, other values will default     

class Node():
    # Constructor requires only IP, other values optional
    def __init__(self,
                 ip, 
                 host=None,
                 time=None,
                 city=None,
                 country=None,
                 countryCode=None,
                 lat=None,
                 lon=None,
                 region=None,
                 regionName=None):
        self.ip = ip
        self.host = host
        self.time = time
        self.city = city
        self.country = country
        self.countryCode = countryCode
        self.lat = lat
        self.lon = lon
        self.region = region
        self.regionName = regionName

    # Override the __str__ magic function for short and easy printing of node info
    def __str__(self):
        ret_str = ''
        if self.city: ret_str = ret_str+ self.city + ', ' 
        if self.region: ret_str = ret_str + self.region  + ', ' 
        if self.countryCode: ret_str = ret_str + self.countryCode
        return ret_str

    # Returns HTML formatted information about the node
    def html(self, n=None):
        html = HTML()
        if n: html.h3('Node #' + str(n))
        if self.host: 
            html.b(self.host)
            html.b('(' + self.ip + ')')
        else: html.b(self.ip)
        p = html.p('')
        if self.city: p += self.city + ', '
        if self.regionName: p += self.regionName + ', '
        elif self.region: p += self.region + ', '
        if self.country: p += self.country
        html.p
        html.a(WHOIS_URL + self.ip)
        return html

############################################################################################IP_CHECK() FUNCTION##########################################################################################################################
                                                      
#       - Returns True if parameter is a valid IPv4 address   

def ip_check(ip):
    # Split on dot and make sure we have exactly four bytes
    bytes = ip.split('.')
    if len(bytes) != 4:
        return False
    # Make sure each byte is an int between 0 and 255
    for byte in bytes:
        if not byte.isdigit():
            return False
        i = int(byte)
        if i < 0 or i > 255:
            return False
    return True

#############################################################################################GET_ARGS() FUNCTION##########################################################################################################################
                                            
#       - Parses and validates command line arguments                          
#       - Returns arguments                                                    

def get_args():
    parser = argparse.ArgumentParser(prog='sameroute')
    # Input file or directory is mandatory
    parser.add_argument('-d', '--destination', required=True, type=str, help='Destination host')
    # Output file or directory
    parser.add_argument('-o', '--output', type=str, default='route.kml', help='Output KML filename')
    # Maximum time-to-live
    parser.add_argument('-t', '--max-ttl', type=int, default=30, help='Maximum TTL to resolve destination')
    
    # The launchers are mutually exclusive
    launchers = parser.add_mutually_exclusive_group(required=False)   
    # Google Earth
    launchers.add_argument('-lG', '--launch-google', action='store_true', help='Launch Google Earth')
    # Linux Google Earth
    launchers.add_argument('-lU', '--launch-unix', action='store_true', help='Launch Linux Google Earth')
    # Linux Google Earth Windows
    launchers.add_argument('-lW', '--launch-win8', action='store_true', help='Launch Linux Google Earth')

    # Parse args
    args = parser.parse_args()

    print '\n [ i ] Max TTL value: ' + str(args.max_ttl)
    print '\n [ i ] Output KML file value: ' + str(args.output)

    # If target is not a valid IPv4 address, try to resolve it
    if not ip_check(args.destination):
        print '\n [ i ] Attempting to resolve destination host... ' + args.destination
        try:
            ip = socket.gethostbyname(args.destination)
            print '\n [ i ] Host ' + args.destination + ' resolvement calculation: ' + ip
            args.destination = ip
        except:
            # If we can't resolve, we quit
            print '\n [ i ] Resolve Unseccessful; check internet connection or input? ' + args.destination
            print '\n [ i ] Terminating ' + sys.argv[0]
            sys.exit(1)
        
    print '\n [ i ] Destination resolving as:',
    try:
        print socket.gethostbyaddr(args.destination)[0] + ' (' + args.destination + ')'
    except:
        print args.destination

    return args

##############################################################################################PROBE(TARGET_IP, TTL) FUNCTION###########################################################################################################
                                        
#       - Sends a crafted ICMP packet over ICMP with set TTL                          
#       - Listens for ICMP error response and returns node's address           
#       - Each probe is run in it's own process    

def probe(params):

    ttl = params[0]
    # Create send and recv sockets
    # Send over ICMP
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    
    # Set socket's time to live
    s_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    s_sock.settimeout(1) 
    addr = ''
    
    #crafted packet to send on ICMP port
    #begin time taken
    start_timer = time.time()
    sendPing(s_sock)

    try:
        # Response is a tuple containing response and another tuple containing address
        # The remote address is the first element of the nested tuple
        addr = s_sock.recvfrom(512)[1][0]
    except: pass
    finally:
        s_sock.close()

    #print time taken to ping, rounded to 2 decimal places
    print("%.2fs" % (time.time() - start_timer))
    return addr

##############################################################################################CALCULATE_CHECKSUM & CRAFT ICMP > (DESTINATION) FUNCTION###################################################################################

#       - Function to create a checksum of the header

def calculate_checksum(source_string):
    
    # acts on the string as a series of 16-bit ints (host
    # Network data is big-endian, hosts are typically little-endian
    
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string): # Check for odd length
        loByte = source_string[len(source_string) - 1]
        sum += ord(loByte)

    sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

#       - Header class, creates a struct from a dict

class HeaderInformation(dict):
    # received IP and ICMP header info
    # Pass in struct names, format and data
    def __init__(self, names, struct_format, data):
        unpacked_data = struct.unpack(struct_format, data)
        dict.__init__(self, dict(zip(names, unpacked_data)))

# Function to send one ping to server
def sendPing(sock):
    checksum = 0
    seq_number = 0
    packet_size = 55
    # Make a dummy header with a 0 checksum.
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, own_id, seq_number
    )

    # Pad the packet with values
    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + (packet_size)):
        padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)

    # Calculate the checksum on the data and the dummy header.
    checksum = calculate_checksum(header + data) # Checksum is in network order

    # insert correct checksum with rand values abnd header infor to complete craft
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, own_id, seq_number
    )
    packet = header + data
    try:
        sock.sendto(packet, (args.destination, UDP_PORT)) # Port number is irrelevant for ICMP
    except: pass
    return  

#############################################################################################TRACE(DESTINATION) FUNCTION##############################################################################################################
                                                   
#       - Traces the route to destination                                      
#       - Returns a list of Node objects                                       

def trace(dest):
    
    nodes = [] # all nodes found
    fail_count = 0 # Keep count unreachable nodes
    dest_reached = False # default destination being reached is false

    print '\n [ i ] Tracing route...\n'

    # display lines for Windows and Linux
    if WINDOWS: print '   #' + ' ' * 32 + 'HOST (IP)' + ' ' * 31 + 'TIME\n'
    else: print '\033[47m\033[30m' + '   #' + ' ' * 32 + 'HOST (IP)' + ' ' * 31 + 'TIME   ' + '\033[0m\n'

    start_time = time.time()
    for ttl in range(1, args.max_ttl + 1):
        result = probe((ttl, args.destination))
        #print result
        print '\n'
        print "%4s." % ttl,
        if result == '':
            node_ip = ''
        else:
            node_ip = result
        if len(node_ip) == 0 or node_ip == '':
            print "%66s" % str('--Trace not returned--'),
            fail_count = fail_count + 1
            nodes.append(Node(ip=None))
        else:    
            try:
                # gethostbyaddr() returns a triple, the first element is the hostname 
                node_host = socket.gethostbyaddr(node_ip)[0]
                print "%66s" % str(node_host + ' (' + node_ip + ')'),
                # append to list of nodes
                nodes.append(Node(ip=node_ip,host=node_host))
            except:
                print "%66s" % str(node_ip + ' (' + node_ip + ')'),
                # append to list of nodes (no hostname)
                nodes.append(Node(ip=node_ip))

        if node_ip == args.destination:
            dest_reached = True
            print '\n'
            print '\n\t\t [ ! ] Destination reached; halting script'            
            break

    if not dest_reached:
        print '\n'
        print '\n [ i ] Destination unreachable; increase max TTL'
    
    ttr = ("%.2fs" % (time.time() - start_time))
    print '\n\t\t [ i ] Time taken for trace to run: '+ttr
    print '\n [ i ] Traced ' + str(len(nodes)) + ' nodes,',
    if not fail_count: print 'all nodes located'
    else: print 'failed to trace ' + str(fail_count) + ' node(s) probed'

    return nodes

##############################################################################################GEOLOCATE_NODES(NODES_ FUNCTION)##########################################################################################################
                                      
#       - Geolocates all nodes in NODES                                        
#       - Returns list of geolocated nodes                                     

def geolocate_nodes(nodes):
    # The list of geolocated nodes returned
    ret_nodes = []
    # The number of nodes successfully located
    success_count = 0

    print '\n [ i ] Geolocating ' + str(len(nodes)) + ' nodes...\n'

    # Pretty display for Linux only, if it's Windows print out plain old boring line
    if WINDOWS: print '   #' + ' ' * 32 + 'HOST' + ' ' * 31 + '%\n'
    else: print '\033[47m\033[30m' + '   #  HOST' + ' ' * 61 + 'LOCATION ' + '\033[0m\n'

    i = 0
    for node in nodes:
        i = i+1
        if node.ip is None:
            print str("%4s. " % i) + str('--Trace Identification unsuccessful--')
            ret_nodes.append(node)
            continue
        # Using requests package for easy HTTP requests to a target IP
        req = requests.get(GEO_URL + node.ip)
        # IP-API website answers with a JSON object
        # we use JSON module for easy and clean handling of this object
        json = req.json()
        
        # Make sure it was successful it was successful
        if json['status'] == 'success':
            success_count += 1
            node.city = json['city']
            node.country = json['country']
            node.countryCode = json['countryCode']
            node.lat = json['lat']
            node.lon = json['lon']
            node.region = json['region']
            ret_nodes.append(node)
            if node.host: print str("%4s. " % i) + node.host.ljust(45),
            else: print str("%4s. " % i) + node.ip.ljust(45),
            print "%27s" % str(node)
        else:
            ret_nodes.append(node)
            print str("%4s. " % i) + str('--Geolocation unsucessful--')

    print '\n [ i ] Geolocated ' + str(success_count) + ' nodes (out of ' + str(len(nodes)) + ')'

    return ret_nodes

#############################################################################################EXPORT_KML(NODES) FUNCTION#################################################################################################################
                                                
#       - Generates a KML file plotting the location of each node in NODES     
#       - Outputs to args.output     

def export_kml(nodes):
    kml = simplekml.Kml(open=1)
    
    print '\n [ i ] KML File is being generated...please hold onto your seat!'

    # "Fill in the holes"
    # Go through the list of nodes once and improvise lat/lon for points that don't have any
    for i in range(0, len(nodes)):
        # Nodes that couldn't be traced
        if not nodes[i].ip:
            # Set the IP to a text that will be displayed
            nodes[i].ip = '--Trace Unsuccessful--'
            print '\n\t[ i ] Node ' + str(i+1) + ' could not be traced!\n\t      Location will be calculated as an assumption of the next node'
            # Find the next located node in the list
            for j in range(i+1, len(nodes)):
                if nodes[j].lat and nodes[j]:
                    nodes[i].lat = nodes[j].lat
                    nodes[i].lon = nodes[j].lon
                    nodes[i].country = 'Location is an assumption; original trace was unsuccessful'
                    break
            
        # Nodes that couldn't be located
        elif not nodes[i].lat and not nodes[i].lon:
            if nodes[i].host:
                print '\n\t[ i ] ' + nodes[i].host + ' ('+ nodes[i].ip +') could not be located!\n      Location will be calculated as an assumption of the next node'
            else:
                print '\n\t[ i ] ' + nodes[i].ip + ' could not be located!\n\t      Location will be calculated as an assumption of the next node'      
            # Find the next located node in the list
            for j in range(i+1, len(nodes)):
                if nodes[j].lat and nodes[j]:
                    nodes[i].lat = nodes[j].lat
                    nodes[i].lon = nodes[j].lon
                    nodes[i].country = 'Location is an assumption; original trace was unsuccessful'
                    break

    # Add points for each node and prepare list of (lat,long) tuple for LineString
    point_list = []
    ttl = 1

    # Create points while aggregating nodes that are at the same locations
    # Also prepare list of points to use for generating the LineString
    print '\n\t[ i ] Identical nodes and identical geolocations are being aggregated...'
    i = 0
    while i < len(nodes):
        # We keep each points location in a list for the LineString
        point_list.append((nodes[i].lon, nodes[i].lat))

        # Set initial point values
        point = kml.newpoint()
        if i == 0: point.name = '#1 (Origin)' 
        elif i == len(nodes)-1: point.name = '#' + str(i + 1) + ' (Destination) ' 
        else: point.name = '#' + str(i + 1) 
        point.description = str(nodes[i].html(i+1))
        point.coords = [(nodes[i].lon, nodes[i].lat)]

        
        # Check if any other points are at this location
        if i < len(nodes)-1 and nodes[i].lat == nodes[i+1].lat and nodes[i].lon == nodes[i+1].lon:
            print '\n     * Grouping nodes #' + str(i + 1),
            
            # While the following nodes are at the same location, group them
            while i < len(nodes)-1 and nodes[i].lat == nodes[i+1].lat and nodes[i].lon == nodes[i+1].lon:
                i += 1
                point.name += ' - #' + str(i + 1)
                point.description += '\n<br />\n\n' + str(nodes[i].html(i+1))
                print '- #' + str(i + 1),

            print ''

        i += 1

    # Add LineString, an actual line between each node
    linestring = kml.newlinestring()
    linestring.tessellate = 1
    linestring.coords = point_list
    linestring.altitudemode = simplekml.AltitudeMode.clamptoground
    # Set the LineString style
    linestring.extrude = 1
    linestring.style.linestyle.color = simplekml.Color.red 
    linestring.style.linestyle.width = 5

    kml.save(args.output)

    print '\n [ i ] KML saved in: ' + args.output

##########################################################################################___MAIN___ FUNCTION##########################################################################################################################

#       -  SIGNAL_HANGLER() FOR CTRL+C CLEAN EXIT   
#       -  Responsible for auto launching google
#       -  captures input from users & initiates process control   

def signal_handler(signal, frame):
    sys.exit(0)

if __name__ == "__main__":
    # Clean exit
    signal.signal(signal.SIGINT, signal_handler)

    args = get_args()

    nodes = trace(args.destination)
    nodes = geolocate_nodes(nodes)
    export_kml(nodes)

    # Auto launch Google Earth w/ KML  
    if args.launch_google:
        print '\n [ i ] Launching Google Earth with ' + args.output
        earthWin = 'C:\Program Files\Google\Google Earth\client\googleearth.exe'
        kmlFile = 'C:\Documents and Settings\Administrator\Desktop\\'+args.output
        subprocess.call([earthWin, kmlFile])
   
    if args.launch_unix: 
        print '\n [ i ] Launching Google Earth with ' + args.output
        kmlDir = '/home/theman/Documents/'+args.output
        subprocess.call(['google-earth', kmlDir], stderr=subprocess.PIPE)

    if args.launch_win8: 
        # print '\n [ i ] Launching Google Earth with ' + args.output
        # earthWin = 'C:\Program Files (x86)\Google\Google Earth Pro\googleearth.exe'
        # kmlFile = 'C:\Documents and Settings\Administrator\Desktop\\'+args.output
        # subprocess.call([earthWin, kmlFile])
        os.system("start {0}".format(args.output))
        
    print '\n [ i ] Fin... (do not fail me now Python....)'