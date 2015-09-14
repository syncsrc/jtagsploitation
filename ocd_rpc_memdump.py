#!/usr/bin/env python3
# Jtagsploitation helper script, covered by GNU GPLv3 or later
# Copyright (C) 2015 by @syncsrc (jtag@syncsrc.org)
# OpenOCD RPC example Copyright (C) 2014 by Andreas Ortmann (ortmann@finf.uni-hannover.de)

info = """
Dumps memory from OpenOCD target system into a binary file for offline analysis.
For use when dump_image doesn't work as expected (eg: due to limitations on how 
much memory can be read at once). Uses "mdw phys" or "mem2array" to read memory
contents in smaller chunks. May be faster than dump_image on some targets.
"""

import socket
import itertools
import sys
import struct
import time
import argparse

def strToHex(data):
    return map(strToHex, data) if isinstance(data, list) else int(data, 16)

def hexify(data):
    return "<None>" if data is None else ("0x%08x" % data)

def barehex(data):
    return "<None>" if data is None else ("%08x" % data)

def reversepack(a):
    retval = []
    for i in range(len(a)):
        s = a[i]
        retval.append(int(s[6:8], 16))
        retval.append(int(s[4:6], 16))
        retval.append(int(s[2:4], 16))
        retval.append(int(s[0:2], 16))
    return struct.pack('%dB' % len(retval), *retval)


class OpenOcd:
    COMMAND_TOKEN = '\x1a'
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.tclRpcIp       = "127.0.0.1"
        self.tclRpcPort     = 6666
        self.bufferSize     = 4096

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def __enter__(self):
        self.sock.connect((self.tclRpcIp, self.tclRpcPort))
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.send("exit")
        finally:
            self.sock.close()

    def send(self, cmd):
        """Send a command string to TCL RPC. Return the result that was read."""
        data = (cmd + OpenOcd.COMMAND_TOKEN).encode("utf-8")
        if self.verbose:
            print("<- ", data)

        self.sock.send(data)
        return self._recv()

    def _recv(self):
        """Read from the stream until the token (\x1a) was received."""
        data = bytes()
        while True:
            chunk = self.sock.recv(self.bufferSize)
            data += chunk
            if bytes(OpenOcd.COMMAND_TOKEN, encoding="utf-8") in chunk:
                break

        if self.verbose:
            print("-> ", data)

        data = data.decode("utf-8").strip()
        data = data[:-1] # strip trailing \x1a

        return data

    def readVariable(self, wordLen, address, n, cr0):
        raw = self.send("ocd_mdw phys 0x%x %d" % (address, n)).replace("\n", "").replace(":", "").split()
        if raw[1] == 'invalid':
            raise Exception("Error reading memory. Check OpenOCD logs.")
        filtered = [ v for v in raw if not v.startswith('0x') ]
        return None if (len(raw) < 2) else strToHex(filtered)

    def readMemory(self, wordLen, address, n, cr0):
        if cr0:
            value = self.send("ocd_reg cr0").split(": ")
            orig_value = strToHex(value[-1])
            if orig_value > 0x7fffffff:
                self.send("ocd_reg cr0 %s" % (hexify(orig_value & 0x7fffffff)))

        self.send("array unset output") # better to clear the array before
        self.send("mem2array output %d 0x%x %d" % (wordLen, address, n))
        output = self.send("ocd_echo $output").split(" ")
        if output[0] == "can't":
            raise Exception("Error reading memory. Check OpenOCD logs.")

        if cr0:
            self.send("reg cr0 %s" % (hexify(orig_value)))

        retval = [None for i in range(len(output)//2)]
        for i in range(len(output)//2):
            retval[int(output[2*i])] = int(output[2*i+1])
        return retval
        #return [int(output[2*i+1]) for i in range(len(output)//2)]


if __name__ == "__main__":

    def show(*args):
        print(*args, file=sys.stderr)

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description=info)
    parser.add_argument('-x', '--x86', action='store_true', 
                        help='disables paging via CR0 for mem2array on x86 systems')
    parser.add_argument('-m', '--mem2array', action='store_true',
                        help='use "mem2array" instead of "mdw phys" to read target memory')
    parser.add_argument('-o', '--out', default="ocd_mem.bin",
                        help='output file')
    parser.add_argument('-s', '--start', default=0, type=auto_int,
                        help='address to start dumping (default = 0x0)')
    parser.add_argument('-e', '--end', default=0xffffffff, type=auto_int,
                        help='address to stop dumping (default = 0xffffffff)')
    parser.add_argument('-w', '--wordsize', default=32,
                        help='target word size in bits (default = 32)')
    opts = parser.parse_args()

     
    with OpenOcd() as ocd:

        if opts.mem2array:
            ocdmem = ocd.readMemory
            n = 0x10000
        else:
            ocdmem = ocd.readVariable
            n = 0x1000
            
        if opts.x86 and opts.start == 0:
            show("WARNING: Accesses to address 0 may fail, consider starting at 0x4.")

        ocd.send("reset")
        show(ocd.send("capture \"ocd_halt\"")[:-1])

        wordlenbytes = opts.wordsize//8
        out = open(opts.out, "wb")

        if opts.start == 4:
            out.write(struct.pack('i', 0))

        begin = time.time()

        for addr in range(opts.start, opts.end, n * wordlenbytes):
            show("Reading %.1fkB starting from address %s. Total elapsed time: %.1f seconds." \
                 % ((n*wordlenbytes/1024), hexify(addr), time.time()-begin))
            read = ocdmem(opts.wordsize, addr, n, opts.x86)
            out.write(reversepack(list(map(barehex, read))))

        show("Dumped", "%.2f" % ((opts.end-opts.start)/0x100000), "MB of memory in", "%.1f" % (time.time()-begin), "seconds.")

        ocd.send("resume")
        out.close()
