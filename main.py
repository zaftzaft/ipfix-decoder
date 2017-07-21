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


    # TODO fix method name
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
                base = self.counter - 4
                print(">> data")
                self.decode_data(setid)
                #break

            else:
                print("[*] undefined setid")
                hexdump(self.raw[self.counter - 4:self.counter + 100])
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


    def decode_data(self, template_id):
        if not template_id in self.template:
            print(">> template is not exists")
            return

        print(">> template exists")


        for temp in self.template[template_id]:
            name = element_id[temp[0]] if temp[0] in element_id else temp[0]

            if temp[0] in (291, 292, 293):
                print(">>+ list", temp[0])

                print(self.raw[self.counter:self.counter + 1])
                self.counter += 1 # skip fixed field 0xff
                attrLen = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                self.counter += 2
                semantic = struct.unpack(">B", self.raw[self.counter:self.counter + 1])[0]
                self.counter += 1

                print(">>@", "attrLen", attrLen, "semantic", semantic)

                sub_temp_id = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                self.counter += 2
                sub_temp_len = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                self.counter += 2

                print("sub_temp_id", sub_temp_id, "sub_temp_len", sub_temp_len)

                if sub_temp_id in self.template:
                    print(">>@ sub template exists")
                    self.decode_data(sub_temp_id)
                    print(">>@ sub template exists]")
                else:
                    print(">>@ sub template not exists")
                    break




                #break


            else:
                print(">>+", name, "[", temp[0], "]", temp[1], self.raw[self.counter:self.counter + temp[1]])
                self.counter += temp[1]
                #print(self.counter, setlen, base)
        print(">> data END")



p = rdpcap("/home/kouta/Desktop/ipfix3.pcap")
#p = rdpcap("/home/kouta/Desktop/IPFIX.pcap")




ipfix = IPFIXDecoder()

for i in range(0, 5):
    ipfix.setRaw(bytes(p[i][Raw]))
    ipfix.decode()



