#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
from scapy.all import *
from element_id import element_id
from pen import pen

template = {}



def main(raw):
    counter = 0
    #hexdump(raw)

    version,length,timestamp,seqnum,obid = struct.unpack(">HHIII", raw[0:16])
    counter += 16


    while True:

        if len(raw) < counter + 4:
            break

        setid,setlen = struct.unpack(">HH", raw[counter:counter + 4])
        counter += 4

        print("> Set", setid, setlen)

        if setid == 2:
            while counter < setlen:
                tempid, fldcount = struct.unpack(">HH", raw[counter:counter + 4])
                counter += 4
                print(">> Template", tempid, fldcount)

                template[tempid] = []


                for i in range(0, fldcount):
                    elmid,fldlen = struct.unpack(">HH", raw[counter:counter + 4])
                    counter += 4

                    if elmid & 0x8000:
                        enterprise = struct.unpack(">I", raw[counter:counter + 4])
                        counter += 4
                        print(">>> Enterprise", elmid, fldlen, pen[enterprise[0]])
                        template[tempid].append([elmid, fldlen, enterprise[0]])
                    else:
                        if elmid in element_id:
                            pass
                            print(">>>", element_id[elmid], fldlen)
                        else:
                            print("--", counter, elmid)
                            continue
                        template[tempid].append([elmid, fldlen])


        elif setid > 255:
            print(">> Data", "template:", setid)
            hexdump(raw[counter - 4:counter + 12])
            if setid in template:
                print(">>> template exists")
            else:
                print(">>> template no")
                break




p = rdpcap("/home/kouta/Desktop/ipfix3.pcap")


main(bytes(p[0][Raw]))
main(bytes(p[1][Raw]))
