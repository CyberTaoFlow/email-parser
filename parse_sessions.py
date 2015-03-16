#!/usr/bin/env python

import sys
import os
import struct
import time
from operator import attrgetter
import dpkt

DEFAULT_UDP_TIMEOUT = 60
DEFAULT_TCP_TIMEOUT = 301 # lengthy for NETBIOS keep alives
VERBOSE = True
DEBUG = True


def NotFiltered():
    """
    This function is used as a default filter for the SessionList.Search
    when none is provided.

    Returns 0 to signal we are not filtering and to not add payloads
"""
    return 0


class DataPayload(object):
    """
    This class contains a single packet payload of the data portion of tcp/udp
    packets.

    source is the ip that sent the packet

    sequence (optional) is the TCP sequence number for the purpose of re-ordering
    tcp packets received out of order (not implemented at this time).
"""

    def __init__(self, timestamp, source, payload, sequence=0):
        self.timestamp = timestamp
        self.source = source
        self.sequence = sequence
        self.payload = payload


class Session(object):
    """
    This class contains all of the information we want to track about each
    session.

    The session source and dest IPs will always reflect the sender and recipient
    for the first packet processed in the session.

    All of the count variables refer to packet counts and sizes to the combined
    size of payloads.

    ip_proto refers to the numeric field in the IP header identifying TCP/UDP.

    When a GetPayload method is called on a TCP session, the sequence numbers
    are checked and if an error is found, the payload is sanitized.
"""
    def __init__(self, pcap_filename, timestamp, ip_packet):
        self.filename = pcap_filename
        self.session_start = timestamp
        self.last_timestamp = timestamp
        self.source = ip_packet.src
        self.dest = ip_packet.dst
        self.source_init_seq = 0
        self.dest_init_seq = 0
        self.fragment_count = 0
        self.payloads = []        # DataPayload
        self.count = 1
        self.source_count = 1
        self.size = 0
        self.dest_size = 0
        self.dest_count = 0
        self.extracted = False
        self.filter_accepted = False

        # process tcp/udp distinctively in order to get the ports and IP protocol
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data
            self.sport = tcp_packet.sport
            self.dport = tcp_packet.dport
            self.ip_proto = dpkt.ip.IP_PROTO_TCP
            self.source_size = len(tcp_packet.data)

            # a SYN flag always indicates the start of a new session
            if tcp_packet.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK) == dpkt.tcp.TH_SYN:
                self.source_init_seq = tcp_packet.seq

        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            udp_packet = ip_packet.data
            self.sport = udp_packet.sport
            self.dport = udp_packet.dport
            self.ip_proto = dpkt.ip.IP_PROTO_UDP
            self.source_size = len(udp_packet.data)

        if self.source_size > 0:
            self.size = self.source_size
            self.AddPayload(timestamp, ip_packet)

    def SessionMatch(self, timestamp, ip_packet):
        """
    Returns true if the packet has the following in common with this session
    object: ip proctocol, source ip/port, destination ip/port and there have
    been fewer than DEFAULT_TCP/UDP_TIMEOUT seconds since the last packet in the
    session. SYN packets always return false because they indicate a new session
    by design.

"""
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data

            # a SYN flag always indicates the start of a new session
            if tcp_packet.flags == dpkt.tcp.TH_SYN:
                return False

            return (self.ip_proto & dpkt.ip.IP_PROTO_TCP) \
                and (timestamp - self.last_timestamp < DEFAULT_TCP_TIMEOUT) \
                and ((self.source == ip_packet.src and self.sport == tcp_packet.sport and self.dest == ip_packet.dst and self.dport == tcp_packet.dport)
                or (self.source == ip_packet.dst and self.sport == tcp_packet.dport and self.dest == ip_packet.src and self.dport == tcp_packet.sport))

        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            udp_packet = ip_packet.data
            return (self.ip_proto & dpkt.ip.IP_PROTO_UDP) \
                and (timestamp - self.last_timestamp < DEFAULT_UDP_TIMEOUT) \
                and ((self.source == ip_packet.src and self.sport == udp_packet.sport and self.dest == ip_packet.dst and self.dport == udp_packet.dport)
                or (self.source == ip_packet.dst and self.sport == udp_packet.dport and self.dest == ip_packet.src and self.dport == udp_packet.sport))

    def NormalizeSequence(self, ip_packet):
        """
        Returns the normalized sequence number. In order to normalize sequence
        numbers, we subtract the initial sequence number from it. The first
        normalized sequence number will always be 1.
"""
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data

            if ip_packet.src == self.source:
                init_seq = self.source_init_seq
            else:
                init_seq = self.dest_init_seq

            if init_seq == 0:
                return 0

            normalized_seq = (tcp_packet.seq - init_seq) & 0xffffffffL

            return normalized_seq



    def AddFragment(self, ip_packet):
        """
    Adds the IP fragmented payload to the last payload from the sender.

    *There is no error checking to detect or prevent misconfigurations or malicious fragmentation errors.
"""
        # iterate through the payloads in reverse to find the last payload from
        # the sender of the fragment
        for data in self.payloads[::-1]:
            if data.source == ip_packet.src:
                # calculate the fragmentation offset
                offset = (ip_packet.off & dpkt.ip.IP_OFFMASK) * 8
                # fragments after the first do not contain a header
                data_size = len(ip_packet.data)

                if offset == data_size:
                    data.payload += ip_packet.data.data
                    return

                # calculate if the new payload will be large than the current. This might not be
                # the case if packets arrived out of order.
                new_payload_size = offset + data_size
                # allocate an empty buffer to accomodate new_payload_size amount of bytes
                buf = bytearray(new_payload_size)
                # copy the old payload into the buffer
                buf[0:len(data.payload)] = data.payload
                # copy the payload fragment into the it's offset
                buf[offset:offset + data_size] = ip_packet.data.data
                # replace the old payload with the new payload created in the buffer
                data.payload = buf

        self.fragment_count += 1

    def AddPayload(self, timestamp, ip_packet):
        """
    Adds a DataPayload object to the list containing the timestamp, source IP,
    and normalized sequence number for tcp packets.
"""
        # determine if it is tcp packet
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data
            data_size = len(tcp_packet.data)

            normalized_seq = self.NormalizeSequence(ip_packet)

            self.payloads.append(DataPayload(timestamp, ip_packet.src, tcp_packet.data, normalized_seq))
        # udp pakcket
        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            udp_packet = ip_packet.data
            data_size = len(udp_packet.data)
            if data_size > 0:
                self.payloads.append(DataPayload(timestamp, ip_packet.src, udp_packet.data))

    def ExtractPayload(self):
        """
    Parses the PCAP file again and looks for all packets associated with this
    session and stores the data (payload) in a list of DataPayload objects.
"""
        # open the file, error checking should be done before-hand
        with open(self.filename, "r") as f:

            # dpkt loads the entire file at once into the pcap object
            pcap = dpkt.pcap.Reader(f)

            # timestamp is in epoch
            # buff contains the entire packet starting with ethernet header
            for timestamp, buf in pcap:

                # create an Ethernet class object to manipulate the packet
                eth_packet = dpkt.ethernet.Ethernet(buf)

                # confirm this frame is IP
                if isinstance(eth_packet.data, dpkt.ip.IP):
                    ip_packet = eth_packet.data

                    # SessionMatch actualy makes sure the session hasn't timed out, instead of only comparing
                    # credentials. Once a match is found, UpdateSession increments the packet counts, payload
                    # sizes and s the latest timestamp.
                    if self.SessionMatch(timestamp, ip_packet):

                        # AddPayload adds that payload to the DataPayload list
                        self.AddPayload(timestamp, ip_packet)

            # to avoid extracting the payload again
            self.extracted = True

    def GetPayload(self, sender):
        """
    Extracts the payload from the session if it hasn't already been done and
    gets the payload from GetTCPPayload or GetUDPPayload depending on the
    ip_proto.
"""
        # determine if the payload was previously extracted
        if self.extracted is False:
            self.ExtractPayload()

        # calls the appropriate method to get the payload based on ip_proto
        if self.ip_proto == dpkt.ip.IP_PROTO_TCP:

            # Maps out the entire session to memory based on normalized sequence numbers. This will fix
            # retransmitions and out of order packets.
            if sender == self.source:
                total_length = self.source_size
                init_seq = self.source_init_seq
            else:
                total_length = self.dest_size
                init_seq = self.dest_init_seq

            # if the initial sequence number is 0, the session handshake is missing from the pcap, so
            # no tcp re-ordering will be done
            if init_seq == 0:
                payload = ""
                # payloads is a list of DataPayload
                for udpdata in self.payloads:
                    # skip packets with no data portion
                    if (udpdata.source == sender) and (len(udpdata.payload) > 0):
                        payload += udpdata.payload
                return payload

            # allocate total_length bytes for the payload buffer
            buf = bytearray(total_length)

            for tcpdata in self.payloads:
                data_size = len(tcpdata.payload)
                if (tcpdata.source == sender) and (data_size > 0):

                    # position of the data in the session payload can be determined the normalized sequence
                    # number. We decrement the position by 1 since a normalized sequence number starts at 1
                    # for each direction of traffic and buf's first byte is at 0.
                    pos = tcpdata.sequence - 1
                    # copy the payload to buf at the right position
                    buf[pos:pos + data_size] = tcpdata.payload

            return buf

        elif self.ip_proto == dpkt.ip.IP_PROTO_UDP:

            payload = ""
            # payloads is a list of DataPayload
            for udpdata in self.payloads:
                # skip packets with no data portion
                if (udpdata.source == sender) and (len(udpdata.payload) > 0):
                    payload += udpdata.payload
            return payload

    def GetFullPayload(self):
        """
    Returns all payloads from the source and destination in the order
    they were processed.
"""
        # when the sessions are parsed, payloads are not collected to reduce unwanted memory allocation.
        if self.extracted is False:
            self.ExtractPayload()

        full_payload = ""
        # payloads is a list of DataPayload
        for data in self.payloads:
            # skip packets with no data portion
            if len(data.payload) > 0:
                full_payload += data.payload
        return full_payload

    def GetSourcePayload(self):
        """
    Returns the payload sent by the source IP of the session's first packet.
"""
        return self.GetPayload(self.source)

    def GetDestPayload(self):
        """
    Returns the payload sent by the destination IP of the session's first packet.
"""
        return self.GetPayload(self.dest)

    def GetFilterPayload(self):
        """
    Returns the payload sent by the source IP of the packet that triggered the
    FilterFunction to return True.
"""
        return self.GetPayload(self.filter_initiator)

    def UpdateSession(self, timestamp, ip_packet):
        """
    Updates the session information with the amount of data and packet count
    sent by the source or destination IP, the total amount of data and packet
    count and the last_timestamp. If it is the first packet of the session,
    the start_time is updated. Guess the protocol if it is the first data
    (payload) sent by the source or destination IP.
"""
        normalized_seq = None

        if ip_packet.off & dpkt.ip.IP_MF != 0:
            self.fragment_count += 1

        # determine if the packet is tcp/udp in order to extract the data at the right offset.
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data
            data_size = len(tcp_packet.data)

            # The sequence number on a SYN+ACK packet is the initial sequence number for the destination of
            # the session (usualy the server)
            if tcp_packet.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK) == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK:
                if ip_packet.dst == self.dest:
                    if self.dest_init_seq == 0:
                        self.dest_init_seq = tcp_packet.seq

            # normalize the sequence number for the sender of the packet
            normalized_seq = self.NormalizeSequence(ip_packet)

            # the larges combination of sequence number + payload size is the total size of the payloads
            if ip_packet.src == self.source:
                # no initial sequence number observed or this packet has an invalid sequence number
                # since it cannot have gone up more than 0xffff bytes (the maximum packet length)
                if (normalized_seq == 0) or (normalized_seq > self.source_size + 0xffff):
                    self.source_size += len(ip_packet.data.data)
                elif normalized_seq + data_size > self.source_size:
                    self.source_size = normalized_seq + data_size
                self.source_count += 1

            else:
                # no initial sequence number observed
                if (normalized_seq == 0) or (normalized_seq > self.dest_size + 0xffff):
                    self.dest_size += len(ip_packet.data.data)
                elif normalized_seq + data_size > self.dest_size:
                    self.dest_size = normalized_seq + data_size
                self.dest_count += 1

        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            udp_packet = ip_packet.data
            data_size = len(udp_packet.data)

            # if the packet came from the initiator of the session
            if ip_packet.src == self.source:
                self.source_size += data_size
                self.source_count += 1
            # this packet came from the destination IP
            else:
                self.dest_size += data_size
                self.dest_count += 1

        # this is the first packet for this session, so this timestamp is the start_time.
        if self.count == 0:
            self.start_time = timestamp

        self.count = self.source_count + self.dest_count
        self.size = self.source_size + self.dest_size
        self.last_timestamp = timestamp

    def Info(self):
        """
    Returns a string containing usefull metadata for the given session for easy
    output.
"""
        def ip_to_string(packed_ip):
            ip = struct.unpack("I", packed_ip)
            return str(str(ip[0] & 255)+'.'+str(ip[0] >> 8 & 255)+'.'+str(ip[0] >> 16 & 255)+'.'+str(ip[0] >> 24 & 255))

        source_info = ip_to_string(self.source)+":"+str(self.sport)
        if self.source_count > 0:
            source_info += " ("+str(self.source_count)
            if self.source_size > 0:
                source_info += " packets, "+str(self.source_size)+" bytes)"
            else:
                source_info += " empty packets)"
        else:
            source_info += " (no reply)"

        dest_info = ip_to_string(self.dest)+":"+str(self.dport)
        if self.dest_count > 0:
            dest_info += " ("+str(self.dest_count)
            if self.dest_size > 0:
                dest_info += " packets, "+str(self.dest_size)+" bytes)"
            else:
                dest_info += " empty packets)"
        else:
            dest_info += " (no reply)"

        time_delta = self.last_timestamp - self.session_start
        time_info = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(self.session_start))
        if time_delta > 1:
            time_info += " +"+str(int(round(time_delta)))+" sec"

        if self.ip_proto == dpkt.ip.IP_PROTO_TCP:
            protocol_info = 'TCP'
        elif self.ip_proto == dpkt.ip.IP_PROTO_UDP:
            protocol_info = 'UDP'
        elif self.ip_proto == dpkt.ip.IP_PROTO_ICMP:
            protocol_info = 'ICMP'
        else:
            protocol_info = str(ip_proto)

        return time_info + " " + protocol_info + " " + source_info + " -> " + dest_info


class SessionList(object):
    """
    This class contains a list of sessions and hash table to quickly look them
    up by source ip/port destination ip/port and IP protocol. The hash table's
    value contains the index within the session list. This index will get updated
    as sessions expire passed the DEFAULT_TCP/UDP_TIMEOUT.
"""
    def __init__(self, pcap_filename, keep_payloads=True, FilterFunction=NotFiltered):
        """
    If keep_payloads is true, sessions will include payloads.
    See the Search method for FilterFunction description.
"""
        self.sessions = []
        self.hash_table = {}
        self.filename = pcap_filename
        # AddPayload method does nothing if keep_payloads = False
        self.keep_payloads = keep_payloads

        self.Search(FilterFunction)

    def NewSession(self, timestamp, ip_packet):
        """
    Appends a session to the session list and then updates the
    hash table with the new index for the session within the session list.
    A second entry is made in the hash table in order to associate return
    tracking with the same session.

    If the same credentials are already in the hash table, we know that it has
    expired because it was checked by the SessionMatch method.
"""
        # this value will only be non-zero if the packet was tcp/udp
        if isinstance(ip_packet.data, dpkt.tcp.TCP) or isinstance(ip_packet.data, dpkt.udp.UDP):
            self.sessions.append(Session(self.filename, timestamp, ip_packet))

            session_index = len(self.sessions) - 1

            ip_proto = self.sessions[session_index].ip_proto
            source = self.sessions[session_index].source
            sport = self.sessions[session_index].sport
            dest = self.sessions[session_index].dest
            dport = self.sessions[session_index].dport

            self.hash_table[(ip_proto, source, sport, dest, dport)] = session_index
            # add a hash table entry for return traffic
            self.hash_table[(ip_proto, dest, dport, source, sport)] = session_index

            # if the new session starts out with a fragmented packet:
            if ip_packet.off & dpkt.ip.IP_MF:
                session_credentials = (ip_packet.src, ip_packet.dst, ip_packet.id)
                self.frag_hash_table[session_credentials] = session_index

            return session_index

    def Search(self, FilterFunction=NotFiltered):
        """
    Returns all sessions in a list of Session class objects.

    If FilterFunction (optional) is specified, only once the function returns
    true will a session's payloads start getting recorded and at the end, only
    those sessions are returned. In addition, GetFilterPayload() will return
    only the payload of the source IP for the packet that triggered the
    FilterFunction to return True.

    example code:

        def FilterSMTP(session):
            if session.current_payload.startswith("EHLO ") or session.current_payload.startswith("HELO"):
                return True
            else:
                return False

        session_list = parse_sessions.SessionList(pcap_filename, True, FilterSMTP)

        ...

        payload = session[0].GetFilterPayload()

    In the absense of a FilterFunction, all sessions will be returned.

"""
        self.sessions = []
        self.hash_table = {}
        self.frag_hash_table = {}

        # if the default filter is not changed, disable filtering
        if FilterFunction == NotFiltered:
            filter_enabled = False
        else:
            filter_enabled = True
            # stores the session list index of sessions identified as SMTP
            filtered_session_table = {}

        # open the file, error checking should be done before-hand
        with open(self.filename, "r") as f:

            # dpkt loads the entire file at once into the pcap object
            pcap = dpkt.pcap.Reader(f)

            # timestamp is in epoch
            # buff contains the entire packet starting with ethernet header
            for timestamp, buf in pcap:

                # create an Ethernet class object to manipulate the packet
                eth_packet = dpkt.ethernet.Ethernet(buf)

                session_found = False

                # confirm this frame is IP
                if isinstance(eth_packet.data, dpkt.ip.IP):
                    ip_packet = eth_packet.data

                    """
    Handle expected packet fragments.
"""
                    # check if there are any sessions with the same source and dest IP
                    # and IP identification waiting for a fragment in the frag hash table
                    session_credentials = (ip_packet.src, ip_packet.dst, ip_packet.id)
                    if session_credentials in self.frag_hash_table:
                        session_index = self.frag_hash_table[session_credentials]
                        session = self.sessions[session_index]
                        # the payload of this packet will be added to the
                        # last payload from that sender
                        if self.keep_payloads:
                            session.AddFragment(ip_packet)

                        # check if this is the last fragment
                        if ip_packet.off & dpkt.ip.IP_MF == 0:
                            # remove this session from the frag hash table
                            del self.frag_hash_table[ip_packet.src, ip_packet.dst, ip_packet.id]
                        # no further processing of this packet is wanted as it doesn't contribute to the
                        # TCP/UDP session beyond increasing the size of the last payload.
                        continue

                        """
    Handle TCP/UDP packets
"""
                    ip_proto = 0

                    # determine if the protocol is tcp or udp
                    if isinstance(ip_packet.data, dpkt.tcp.TCP):
                        ip_proto = dpkt.ip.IP_PROTO_TCP
                    if isinstance(ip_packet.data, dpkt.udp.UDP):
                        ip_proto = dpkt.ip.IP_PROTO_UDP

                    # only continue if it is tcp or udp
                    if ip_proto != 0:
                        # key list for the hash table
                        session_credentials = (ip_proto, ip_packet.src, ip_packet.data.sport, ip_packet.dst, ip_packet.data.dport)

                        """
    Handle existing sessions.
"""
                        # the hash table contains the index in the session list for every given session
                        # if a new session has the same credentials, the new session's index will get stored
                        # in the hash table
                        if session_credentials in self.hash_table:
                            session_index = self.hash_table[session_credentials]
                            session = self.sessions[session_index]

                            # SessionMatch actualy makes sure the session hasn't timed out, instead of only
                            # comparing credentials. Once a match is found, UpdateSession increments the
                            # packet counts, payload sizes and updates the latest timestamp.
                            if session.SessionMatch(timestamp, ip_packet):
                                session.UpdateSession(timestamp, ip_packet)
                                session_found = True

                                """
    Handle fragmentend packets in an existing sessions.
"""
                                # check for more fragments
                                if ip_packet.off & dpkt.ip.IP_MF != 0:
                                    # add this session to the frag hash table it will get removed once it
                                    # receives an ip packet with MORE FRAGMENTS set to 0
                                    session_credentials = (ip_packet.src, ip_packet.dst, ip_packet.id)
                                    self.frag_hash_table[session_credentials] = session_index

                        """
    Handle new sessions.
"""
                        if not session_found:
                            # cadd a session object to the list and update hash
                            # tables
                            session_index_ = self.NewSession(timestamp, ip_packet)
                            session = self.sessions[session_index_]

                        """
    Handle the filter
"""
                        # pass the session back to the filter function to evaluate the session and
                        # return true if they want it returned with payload or false to discard it.
                        if filter_enabled:
                            # store the current payload in the session in case the FilterFunction needs it
                            session.current_payload = ip_packet.data.data

                            # session already flagged for retention
                            """
    Handle sessions already accepted by the filter
"""
                            if session.filter_accepted:
                                # add the payload because we know it's needed
                                if self.keep_payloads:
                                    session.AddPayload(timestamp, ip_packet)

                            elif FilterFunction(session) is True:
                                """
    Handle session getting approval from the filter
"""
                                session.filter_accepted = True

                                # used by GetFilterPayload to determine which
                                # payload to return
                                session.filter_initiator = ip_packet.src

                                if self.keep_payloads:
                                    session.AddPayload(timestamp, ip_packet)
                                    # ensure GetPayload methods don't call ExtractPayload() for nothing
                                    session.extracted = True

                                # add to the the filtered session table in order to get quick retrival of relevent sessions
                                filtered_session_table[session_index] = True
                            """
    Handle unfiltered Search()
"""
                        else:
                            # keep all payloads if no filter is selected
                            if self.keep_payloads:
                                session.AddPayload(timestamp, ip_packet)
                                # ensure GetPayload methods don't call ExtractPayload() for nothing
                                session.extracted = True

        if filter_enabled:
            # temporary list to store SMTP sessions
            filtered_sessions = []

            # iterate through the list in filtered_session_table
            for session_index in filtered_session_table:
                filtered_sessions.append(self.sessions[session_index])

#            self.sessions = filtered_sessions
            self.sessions = sorted(filtered_sessions, key=attrgetter('session_start'))



if __name__ == '__main__':
    """
    Provides a simple command-line test that takes a pcap file as an argument
    and builds a list of all sessions contained within (tcp and udp).
"""
    def FragFilter(session):
        if session.fragment_count > 0:
            return True
        else:
            return False

    # checks to see if user supplied arguments
    if not sys.argv or len(sys.argv) < 2:
        print sys.arg[0], '<filename.pcap>'
        sys.exit()

    # first arg should be the filename of a pcap
    f = sys.argv[1]
    if os.path.isfile(f):

        session_list = SessionList(f, True)
        print len(session_list.sessions), "sessions total."
        for session in session_list.sessions:
            print session.Info()
            temp = session.GetFullPayload()

    else:
        print f, "is not a file"
