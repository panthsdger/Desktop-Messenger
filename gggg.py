#ALL BIGENDS ARE TRANSFERED TO ENDIAN

import dissect.formats.inet as ds_inet
from vstruct2.types import *

PCAP_LINKTYPE_ETHER = 1
PCAP_LINKTYPE_RAW = 101
PCAP_LINKTYPE_LINUX_SLL = 113
PCAP_DLT_RAW = 12

PCAPNG_BOM = 0x1A2B3C4D
OPT_ENDOFOPT = 0
OPT_COMMENT = 1

# PCAPNG_BLOCKTYPE_SECTION_HEADER options
OPT_SHB_HARDWARE = 2
OPT_SHB_OS = 3
OPT_SHB_USERAPPL = 4

# PCAPNG_INTERFACE_DESCRIPTION_BLOCK options
OPT_IF_NAME = 2
OPT_IF_DESCRIPTION = 3
OPT_IF_IPV4ADDR = 4
OPT_IF_IPV6ADDR = 5
OPT_IF_MACADDR = 6
OPT_IF_EUIADDR = 7
OPT_IF_SPEED = 8
OPT_IF_TSRESOL = 9
OPT_IF_TZONE = 10
OPT_IF_FILTER = 11
OPT_IF_OS = 12
OPT_IF_FCSLEN = 13
OPT_IF_TSOFFSET = 14

# options for PCAPNG_ENHANCED_PACKET_BLOCK
OPT_EPB_FLAGS = 2
OPT_EPB_HASH = 3
OPT_EPB_DROPCOUNT = 4

# values used in the blocktype field
PCAPNG_BLOCKTYPE_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_BLOCKTYPE_PACKET = 0x00000002
PCAPNG_BLOCKTYPE_SIMPLE_PACKET = 0x00000003
PCAPNG_BLOCKTYPE_NAME_RESOLUTION = 0x00000004
PCAPNG_BLOCKTYPE_INTERFACE_STATS = 0x00000005
PCAPNG_BLOCKTYPE_ENHANCED_PACKET = 0x00000006
PCAPNG_BLOCKTYPE_SECTION_HEADER = 0x0a0d0d0a


def pad4bytes(size):
    if (size % 4) == 0:
        return size
    return size + (4 - (size % 4))


class PCAP_FILE_HEADER(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self._vs_endian = 'big'
        self.magic = uint32()
        self.vers_maj = uint16()
        self.vers_min = uint16()
        self.thiszone = uint32()
        self.sigfigs = uint32()
        self.snaplen = uint32()
        self.linktype = uint32()


class PCAP_PACKET_HEADER(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.tvsec = uint32()
        self.tvusec = uint32()
        self.caplen = uint32()
        self.len = uint32()


class PCAPNG_GENERIC_BLOCK_HEADER(VStruct):
    '''
    Used to read the block type & size when parsing the file
    '''

    def __init__(self, endian = 'little'): #COMPLETED
        VStruct.__init__(self)
        self._vs_endian = endian
        self.blocktype = uint32()
        self.blocksize = uint32()


class PCAPNG_BLOCK_PARENT(VStruct):
    '''
    Used to inherit the weird parsing style where there's variable length
    options at the end, followed by the duplicate block total length
    '''

    def __init__(self, endian='little'): #COMPLETED
        VStruct.__init__(self)
        # non-vstruct field, set during checking BOM
        self.endian = endian

    def vsParse(self, bytez, offset=0, writeback=False):   ###### POSSIBLE TO REPLACE?
        self._vs_endian = 'big'
        startoff = offset
        roff = VStruct.vsParse(self, bytez, offset=offset, writeback=writeback)
        # (blocksize-4): because we still need the trailing blocksize2
        # apparently blocks can completely omit the options list and not
        # even have the OPT_ENDOFOPT entry
        while (roff < len(bytez)) and ((roff - startoff) < (self.blocksize - 4)):
            opt = PCAPNG_OPTION()
            roff = opt.vsParse(bytez, roff)
            if opt.code == OPT_ENDOFOPT:
                break
            self.options.vsAddElement(opt)  #############
        # append trailing blocksize2
        bs2 = uint32()
        self.vsAddField('blocksize2', bs2)
        roff = bs2.vsParse(bytez, roff)
        # pad, plus we skip
        return pad4bytes(roff)


class PCAPNG_SECTION_HEADER_BLOCK(PCAPNG_BLOCK_PARENT):
    def __init__(self, bigend = 'little'):  #COMPLETED
        PCAPNG_BLOCK_PARENT.__init__(self)
        self._vs_endian = bigend
        self.blocktype = uint32()
        self.blocksize = uint32()
        self.bom = uint32()
        self.vers_maj = uint16()
        self.vers_min = uint16()
        self.sectionsize = uint64()
        self.options = VArray([])


    def pcb_bom(self):
        bom = self.vsGetField('bom') #REPLACE
        if self.bom == PCAPNG_BOM:
            # if it matches, then the endian of bom is correct
            self.endian = bom.endian
        else:
            self.endian = not bom.endian


class PCAPNG_OPTION(VStruct):  #POSSIBLE COMPLETION
    def __init__(self, endian = 'little'):
        VStruct.__init__(self)
        self._vs_endian = endian
        self.code = uint16()
        self.optsize = uint16()
        self.bytes = bytes(0)

    def pcb_optsize(self):
        size = pad4bytes(self.optsize())  #  FIND REPLACE FOR OPTSIZE      #size = pad4bytes(self.optsize)##################
        self.vsGetField('bytes').vsSetLength(size) #REPLACE VSSETLENGTH


class PCAPNG_INTERFACE_DESCRIPTION_BLOCK(PCAPNG_BLOCK_PARENT):  #COMPLETED
    def __init__(self, endian = 'little'):
        PCAPNG_BLOCK_PARENT.__init__(self)
        self._vs_endian = endian
        self.blocktype = uint32()
        self.blocksize = uint32()
        self.linktype = uint16()
        self.reserved = uint16()
        self.snaplen = uint32()
        self.options = VArray([])


    def vsParse(self, bytez, offset=0, writeback=False):  #REPLACE
        '''
        We need the tsresol value to adjust timestamp values, so pull it
        out here
        '''
        ret = PCAPNG_BLOCK_PARENT.vsParse(self, bytez, offset=0, writeback=False)
        self.tsresol = None
        # default offset is 0
        self.tsoffset = 0
        # sys.stderr.write('PCAPNG_INTERFACE_DESCRIPTION_BLOCK: searching options')
        for i, opt in self.options:
            if opt.code == OPT_IF_TSRESOL:
                self.tsresol = ord(opt.bytes[0])
                # sys.stderr.write('Got tsresol: 0x%x\n' % self.tsresol)
            elif opt.code == OPT_IF_TSOFFSET:
                fmt = '<Q'
                if self.endian:
                    fmt = '>Q'
                self.tsoffset = VStruct.unpack_from(fmt, opt.bytes)[0] ################## NOT FULLY KNOWN
                # sys.stderr.write('Got tsoffset: 0x%x\n' % self.tsoffset)
        return ret


class PCAPNG_ENHANCED_PACKET_BLOCK(PCAPNG_BLOCK_PARENT): #COMPLETED
    def __init__(self, endian = 'little'):
        PCAPNG_BLOCK_PARENT.__init__(self)
        self._vs_endian = endian
        self.blocktype = uint32()
        self.blocksize = uint32()
        self.interfaceid = uint32()
        self.tstamphi = uint32()
        self.tstamplow = uint32()
        self.caplen = uint32()
        self.packetlen = uint32()
        self.data = bytes(0)
        self.options = VArray([])


    def pcb_caplen(self): #REPLACE
        size = pad4bytes(self.caplen.vsSize())#REPLACE VSSIZE
        self.vsGetField('data').vsSetLength(size)#REPLACE VSSETLENGTH AND VSGETFIELD

    def setPcapTimestamp(self, idb):#REPLACE
        '''
        Adds a libpcap compatible tvsec and tvusec fields, based on the pcapng timestamp
        '''
        # orange left off here
        self.snaplen = idb.snaplen #CHECK SNAPLEN VALIDITY

        tstamp = (self.tstamphi << 32) | self.tstamplow
        scale = 1000000
        if idb.tsresol is None:
            # if not set, capture assumes 10e-6 resolution
            pass
        elif (0x80 & idb.tsresol) == 0:
            # remaining bits are resolution, to a negative power of 10
            scale = 10 ** (idb.tsresol & 0x7f)
        else:
            # remaining bits are resolution, to a negative power of 2
            scale = 1 << (idb.tsresol & 0x7f)

        self.tvsec = (tstamp / scale) + idb.tsoffset
        self.tvusec = tstamp % scale


class PCAPNG_SIMPLE_PACKET_BLOCK(VStruct):
    '''
    Note: no variable length options fields, so inheriting from vstruct directly
    '''

    def __init__(self,endian = 'little'): #COMPLETED
        VStruct.__init__(self)
        self._vs_endian = endian
        self.blocktype = uint32()
        self.blocksize = uint32()
        self.packetlen = uint32()
        self.data = bytes(0)
        self.blocksize2 = uint32()

    def pcb_blocksize(self):
        self.caplen = pad4bytes(self.blocksize - 16)#REPLACE
        self.vsGetField('data').vsSetLength(self.caplen)#REPLACE

    def setPcapTimestamp(self, idb): #REPLACE
        # no timestamp in this type of block :(
        self.tvsec = idb.tsoffset
        self.tvusec = 0


def iterPcapFileName(filename, reuse=False):  #REPLACE reuse
    fd = open(filename, 'rb')
    for x in iterPcapFile(fd, reuse=reuse):
        yield x


def iterPcapFile(fd, reuse=False):
    '''
    Figure out if it's a tcpdump format, or pcapng
    '''
    h = PCAP_FILE_HEADER()
    b = fd.read(len(h))
    h.vsParse(b, writeback=True)
    fd.seek(0)
    if h.magic == PCAPNG_BLOCKTYPE_SECTION_HEADER:
        return _iterPcapNgFile(fd, reuse)
    return _iterPcapFile(fd, reuse)


def _iterPcapFile(fd, reuse=False):
    h = PCAP_FILE_HEADER()
    b = fd.read(len(h))
    h.vsParse(b, writeback=True)

    linktype = h.linktype

    if linktype not in (PCAP_LINKTYPE_ETHER, PCAP_LINKTYPE_RAW):
        raise Exception('PCAP Link Type %d Not Supported Yet!' % linktype)

    pkt = PCAP_PACKET_HEADER()
    eII = ds_inet.ETHERII()

    pktsize = len(pkt)
    eIIsize = len(eII)

    ipv4 = ds_inet.IPv4()
    ipv4size = 20
    tcp_hdr = ds_inet.TCP()
    udp_hdr = ds_inet.UDP()
    icmp_hdr = ds_inet.ICMP()

    go = True
    while go:

        hdr = fd.read(pktsize)
        if len(hdr) != pktsize:
            break

        pkt.vsParse(hdr, writeback=True)

        b = fd.read(pkt.caplen)

        offset = 0

        if linktype == PCAP_LINKTYPE_ETHER:

            if len(b) < eIIsize:
                continue

            eII.vsParse(b, 0, writeback=True)

            # No support for non-ip protocol yet...
            if eII.etype not in (ds_inet.ethp.ipv4, ds_inet.ETHERII.vvlan):
                continue

            offset += eIIsize

            if eII.etype == ds_inet.ETHERII.vvlan:
                offset += 4

        elif linktype == PCAP_LINKTYPE_RAW:
            pass

        # print eII.tree()
        if not reuse:
            ipv4 = ds_inet.IPv4()

        if (len(b) - offset) < ipv4size:
            continue

        ipv4.vsParse(b, offset, writeback=True)

        # Make b *only* the IP datagram bytes...
        b = b[offset:offset + ipv4.totlen]

        offset = 0
        offset += len(ipv4)
        tsize = len(b) - offset

        if ipv4.proto == ds_inet.ipproto.TCP:

            if tsize < 20:
                continue

            if not reuse:
                tcp_hdr = ds_inet.TCP()

            tcp_hdr.vsParse(b, offset, writeback=True)
            offset += len(tcp_hdr)
            pdata = b[offset:]

            yield pkt, ipv4, tcp_hdr, pdata

        elif ipv4.proto == ds_inet.ipproto.UDP:

            if tsize < 8:
                continue

            if not reuse:
                udp_hdr = ds_inet.UDP()

            udp_hdr.vsParse(b, offset, writeback=True)
            offset += len(udp_hdr)
            pdata = b[offset:]

            yield pkt, ipv4, udp_hdr, pdata

        elif ipv4.proto == ds_inet.ipproto.ICMP:
            if tsize < 4:
                continue

            if not reuse:
                icmp_hdr = ds_inet.ICMP()

            icmp_hdr.vsParse(b, offset, writeback=True)
            offset += len(icmp_hdr)
            pdata = b[offset:]

            yield pkt, ipv4, icmp_hdr, pdata

        else:
            pass
            # print 'UNHANDLED IP PROTOCOL: %d' % ipv4.proto


def _iterPcapNgFile(fd, reuse=False):
    header = PCAPNG_GENERIC_BLOCK_HEADER()
    ifaceidx = 0
    ifacedict = {}
    roff = 0
    endian = 'little'
    curroff = fd.tell()
    b0 = fd.read(len(header))
    fd.seek(curroff)
    while len(b0) == len(header):
        header.vsParse(b0, writeback=True)
        body = fd.read(header.blocksize)
        if header.blocktype == PCAPNG_BLOCKTYPE_SECTION_HEADER:
            shb = PCAPNG_SECTION_HEADER_BLOCK(endian)
            roff = shb.vsParse(body)
            endian = shb.endian
            # reset interface stuff since we're in a new section
            ifaceidx = 0
            ifacedict = {}
        elif header.blocktype == PCAPNG_BLOCKTYPE_INTERFACE_DESCRIPTION:
            idb = PCAPNG_INTERFACE_DESCRIPTION_BLOCK(endian)
            roff = idb.vsParse(body)
            # save off the interface for later reference
            ifacedict[ifaceidx] = idb
            ifaceidx += 1
        elif header.blocktype == PCAPNG_BLOCKTYPE_SIMPLE_PACKET:
            epb = PCAPNG_ENHANCED_PACKET_BLOCK(endian)
            iface = ifacedict.get(epb.interfaceid)
            spb = PCAPNG_SIMPLE_PACKET_BLOCK()
            roff = spb.vsParse(body)
            tup = _parsePcapngPacketBytes(iface.linktype, spb)
            if tup is not None:
                # if it is None, just fall through & read next block
                yield tup
        elif header.blocktype == PCAPNG_BLOCKTYPE_ENHANCED_PACKET:
            epb = PCAPNG_ENHANCED_PACKET_BLOCK()
            roff = epb.vsParse(body)
            iface = ifacedict.get(epb.interfaceid)
            epb.setPcapTimestamp(iface)
            tup = _parsePcapngPacketBytes(iface.linktype, epb)
            if tup is not None:
                # if tup is None, just fall through & read next block
                yield tup

        else:
            # print 'Unknown block type: 0x%08x: 0x%08x 0x%08x bytes' % (roff, header.blocktype, header.blocksize)
            pass
        curroff = fd.tell()
        b0 = fd.read(len(header))
        fd.seek(curroff)


def _parsePcapngPacketBytes(linktype, pkt):
    '''
    pkt is either a parsed PCAPNG_SIMPLE_PACKET_BLOCK or PCAPNG_ENHANCED_PACKET_BLOCK
    On success Returns tuple (pcapng_pkt, ipv4_vstruct, transport_vstruc, pdata)
    Returns None if the packet can't be parsed
    '''
    if linktype not in (PCAP_LINKTYPE_ETHER, PCAP_LINKTYPE_RAW):
        raise Exception('PCAP Link Type %d Not Supported Yet!' % linktype)

    # pkt = PCAP_PACKET_HEADER()
    eII = ds_inet.ETHERII()
    eIIsize = len(eII)

    offset = 0
    if linktype == PCAP_LINKTYPE_ETHER:
        if len(pkt.data) < eIIsize:
            return None
        eII.vsParse(pkt.data, 0, writeback=True)
        # No support for non-ip protocol yet...
        if eII.etype not in (ds_inet.ethp.ipv4, ds_inet.ethp.vlan):
            return None
        offset += eIIsize
        if eII.etype == ds_inet.ethp.vlan:
            offset += 4
    elif linktype == PCAP_LINKTYPE_RAW:
        pass

    ipv4 = ds_inet.IPv4()
    if (len(pkt.data) - offset) < len(ipv4):
        return None
    ipv4.vsParse(pkt.data, offset, writeback=True)

    # Make b *only* the IP datagram bytes...
    b = pkt.data[offset:offset + ipv4.totlen]

    offset = 0
    offset += len(ipv4)
    tsize = len(b) - offset

    if ipv4.proto == ds_inet.ipproto.TCP:
        if tsize < 20:
            return None
        tcp_hdr = ds_inet.TCP()
        tcp_hdr.vsParse(b, offset, writeback=True)
        offset += len(tcp_hdr)
        pdata = b[offset:]
        return pkt, ipv4, tcp_hdr, pdata
    elif ipv4.proto == ds_inet.ipproto.UDP:
        if tsize < 8:
            return None
        udp_hdr = ds_inet.UDP()
        udp_hdr.vsParse(b, offset, writeback=True)
        offset += len(udp_hdr)
        pdata = b[offset:]
        return pkt, ipv4, udp_hdr, pdata
    elif ipv4.proto == ds_inet.ipproto.ICMP:
        if tsize < 4:
            return None
        icmp_hdr = ds_inet.ICMP()
        icmp_hdr.vsParse(b, offset, writeback=True)
        offset += len(icmp_hdr)
        pdata = b[offset:]
        return pkt, ipv4, icmp_hdr, pdata
    else:
        pass
        # print 'UNHANDLED IP PROTOCOL: %d' % ipv4.proto
    return None



#class PCAP_FILE_HEADER(VStruct):
    #def __init__(self):
PCAP_FILE_HEADER.__init__(VStruct)

#class PCAP_PACKET_HEADER(VStruct):
    #def __init__(self):
PCAP_PACKET_HEADER.__init__(VStruct)

#class PCAPNG_GENERIC_BLOCK_HEADER(VStruct):
    #__init__
PCAPNG_GENERIC_BLOCK_HEADER().__init__()

#class PCAPNG_BLOCK_PARENT(VStruct):
#__init__ vsParse
pcape = PCAPNG_GENERIC_BLOCK_HEADER().__init__()
PCAPNG_GENERIC_BLOCK_HEADER().vsParse(100, 50, True)

#class PCAPNG_SECTION_HEADER_BLOCK(PCAPNG_BLOCK_PARENT):
    #def __init__(self):
    #pc_bom
pcapesec = PCAPNG_SECTION_HEADER_BLOCK().__init__()
PCAPNG_SECTION_HEADER_BLOCK().pcb_bom()

#class PCAPNG_OPTION(VStruct):
    #def __init__(self):
    #pcb_optsize
PCAPNG_OPTION().__init__()
PCAPNG_OPTION().pcb_optsize()

#class PCAPNG_INTERFACE_DESCRIPTION_BLOCK(PCAPNG_BLOCK_PARENT):
    #def __init__(self):
    #vs_parse
#PCAPNG_INTERFACE_DESCRIPTION_BLOCK().__init__()
#PCAPNG_INTERFACE_DESCRIPTION_BLOCK().vsParse(bytez=[1,2,3,4,5,6])

