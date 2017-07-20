#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
from scapy.all import *
from element_id import element_id
from pen import pen



class IPFIXDecoder(object):

    def __init__(self):
        self.template = {}
        #self.raw = raw
        #self.counter = 0


    def importTemplate(self, template):
        self.template = template


    def setRaw(self, raw):
        self.raw = raw
        self.counter = 0


    def decode(self):
        version, length, timestamp, seqnum, obid = struct.unpack(">HHIII", self.raw[0:16])
        self.counter += 16

        while True:
            if len(self.raw) < self.counter + 4:
                break

            setid, setlen = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
            self.counter += 4

            print("> Set", setid, setlen)

            if setid == 2:
                base = self.counter - 4
                print(base, base + setlen)
                while self.counter < base + setlen:
                    print(self.counter, base + setlen)
                    tempid, fldcount = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
                    self.counter += 4
                    print(">> Template", tempid, fldcount)

                    self.template[tempid] = []

                    self.decodeTemplate(tempid, fldcount)

            elif setid == 3:
                base = self.counter - 4
                print(base, base + setlen)

                while self.counter < base + setlen:
                    tempid, fldcount, scopecount = struct.unpack(">HHH", self.raw[self.counter:self.counter + 6])
                    self.counter += 6
                    print(">> Opt Template", tempid, fldcount, scopecount)
                    self.template[tempid] = []
                    self.decodeTemplate(tempid, fldcount)

            elif setid > 255:
                print("dat")
                pass
            else:
                print("[*] undefined setid")
                break


    def decodeTemplate(self, tempid, fldcount):
        for i in range(0, fldcount):
            elmid,fldlen = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
            self.counter += 4

            if elmid & 0x8000:
                enterprise = struct.unpack(">I", self.raw[self.counter:self.counter + 4])
                self.counter += 4

                #if not enterprise[0] in pen:
                #    hexdump(raw[counter - 12:counter + 12])
                #    return

                print(">>> Enterprise", elmid, fldlen, pen[enterprise[0]])
                self.template[tempid].append([elmid, fldlen, enterprise[0]])
            else:
                if elmid in element_id:
                    print(">>>", element_id[elmid], fldlen)
                    pass
                else:
                    print("--", counter, elmid)
                    continue
                self.template[tempid].append([elmid, fldlen])



#p = rdpcap("/home/kouta/Desktop/ipfix3.pcap")
p = rdpcap("/home/kouta/Desktop/IPFIX.pcap")




ipfix = IPFIXDecoder()
ipfix.setRaw(bytes(p[0][Raw]))
ipfix.decode()


