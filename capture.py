import re
import multiprocessing
import subprocess
import json
import time

from grpc import Channel





class PacketCapture(multiprocessing.Process):
    def __init__(
        self, name, outQ
    ):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.outQ = outQ
        self.log = {}
        
        # This is a global foo_foo_ to foo. keymap that is shared across all packets
        self.keymap = {}

    def run(self):
    
        cmd = (
            "sudo "
            + "tshark"
            + " -V -i "
            + "wlp3s0"
            + " -l -T ek"
        )
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            shell=True,
            universal_newlines=True,
        )
        json_str = ""
        num_read = 0
        start_timer = time.perf_counter()

        # for line in p.stdout:
        while True:

            line = p.stdout.readline()
            if "layers" in line:
                num_read += 1
                #self.logger.debug("Working with line %s", line)
                json_obj = json.loads(line.strip())
                source_filter = json_obj["layers"]
                keyval = source_filter.items()
                #self.logger.debug("Working with dict %s", keyval)
                #a est le dictionnaire des packets
                a = self.unwrap(keyval)
                #self.logger.debug("Working with packet %s", a)
                self.send_data(a)
            else:
                # we get blank lines
                #self.logger.debug("Ignoring: %s", line)
                pass
            if not line and p.poll() is not None:
                # possible could delay here to let processing complete
                self.logger.debug("We're done - no input and tshark exited")
                self.send_data({})
                break
        end_timer = time.perf_counter()
        calc_rate = num_read / (end_timer - start_timer)
        print(self.outQ)
        p.stdout.close()
        p.wait()


    # saves each dictionary object into a Queue

    def send_data(self, dictionary):
        self.outQ.put(dictionary)

    # this function unwraps a multi level JSON object into a python dictionary with key value pairs

    def unwrap(self, keyval):

        newKeyval = {}
        for key1, value1 in keyval:

            if key1 not in self.keymap:
                # weirdness in the export format when using EK which we use because all on one line
                # The json has some with xxx.flags xxx.flags_tree xx.flags.yyy the _tree doesn't show up in this format
                # couldn't figure out how to convert 'xxx_xxx_' to 'xxx.' so converted 'xxx_xxx_' to 'xxx__' and then 'xxx.'
                # found src_ and dst_ in arp
                # found request_ record_ flags_ inside some keys.  Might want to tighten down record_ can be an inner key
                massagedKey1 = (
                    re.sub(r"(\w+_)(\1)+", r"\1_", key1)
                    .replace("__", ".")
                    .replace("request_", "request.")
                    .replace("record_", "record.")
                    .replace("tcp_flags", "tcp.flags")
                    .replace("flags_", "flags.")
                    .replace("src_", "src.")
                    .replace("dst_", "dst.")
                )
                # add the before and after to the map so we don't have to calculate again
                self.keymap[key1] = massagedKey1
                #self.logger.debug("Registered mapping: %s --> %s", key1, massagedKey1)

            if isinstance(value1, (str, bool, list)):
                newKeyval[self.keymap[key1]] = value1
            elif value1 is None:
                #self.logger.debug("Ignoring and tossing null value %s", key1)
                pass
            else:
                newKeyval.update(self.unwrap(value1.items()))
                
        return newKeyval


