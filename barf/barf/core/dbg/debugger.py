"""Generic Debugger Interface.
"""
from signal import SIGTRAP
from time import sleep

from run import createChild
from event import *
#from mm  import MemoryMaps
from ptrace.debugger import PtraceDebugger
from ptrace.error import PtraceError
from ptrace.ctypes_tools import (truncateWord, formatWordHex, formatAddress,
                                 formatAddressRange, word2bytes)

class Debugger(PtraceDebugger):
    pass

class ProcessControl(object):
    def __init__(self):
        self.dbg = Debugger()
        self.process = None
        self.last_signal = []

    def start_process(self, binary, args, ea_start, ea_end, hooked_functions = []):
        self.binary = binary

        self.filename = binary.filename
        self.args = list(args)

        if ea_start == 0x0:
            ea_start = self.binary.start_address

        self.ea_start = ea_start
        self.ea_end   = ea_end
        self.hooked_functions = dict()

        pid = createChild([self.filename]+self.args, 0)
        self.process = self.dbg.addProcess(pid, is_attached=1)

        self.breakpoint(ea_start)
        self.cont()

        for func in hooked_functions:
            if func in self.binary.plt:
                addr = self.binary.plt[func]
                self.breakpoint(addr)
                self.hooked_functions[addr] = func, self.filename
                print "[+] Hooking",func,"at",hex(addr)

        self.mm = self.process.readMappings()
        self.libs_start = dict()

        for m in self.mm:
            if m.pathname not in [None, "[vsyscall]", "[vdso]"] and 'x' in m.permissions:
                self.libs_start[m.pathname] = m.start

        #print self.libs_start

        for lib_filename,lib_binary in self.binary.libs.items():

            for func in hooked_functions:
                if func in lib_binary.plt:
                    addr = self.libs_start[lib_filename] + lib_binary.plt[func]
                    self.breakpoint(addr)
                    self.hooked_functions[addr] = func, lib_filename
                    print "[+] Hooking",func,"at",hex(addr), lib_filename

        #print map(str,self.libs_start.keys())
        #print map(hex,self.libs_start.values())
        return self.process

    def wait_event(self):
        event = self.dbg.waitProcessEvent()

        if not isinstance(event, ProcessExit):
            if self.process.getInstrPointer() == self.ea_end:
                return ProcessEnd(self.process, "Last instruction reached")

        return event

    def _continue_process(self, process, signum=None):
        if not signum and process in self.last_signal:
            signum = self.last_signal[process]

        if signum:
            error("Send %s to %s" % (signalName(signum), process))
            process.cont(signum)
            try:
                del self.last_signal[process]
            except KeyError:
                pass
        else:
            process.cont()

    def cont(self, signum=None):
        event = None
        process = self.process
        process.syscall_state.clear()
        if process == self.process:
            self._continue_process(process, signum)
        else:
            self._continueProcess(process)

        #print process.getInstrPointer()

        signal = self.dbg.waitSignals()
        if signal.signum == SIGTRAP:
            ip = process.getInstrPointer()
            ip = ip - 1

            if (ip) in self.hooked_functions:
                name, module = self.hooked_functions[ip]
                event = Call(name, module)
                event.detect_parameters(self.process)
                event.detect_return_address(self.process)

                return_address = event.get_return_address()
                self.breakpoint(return_address)

                self.process.cont()
                self.dbg.waitProcessEvent()
                event.detect_return_value(self.process)

                ip = process.getInstrPointer()
                ip = ip - 1

                breakpoint = self.process.findBreakpoint(ip)
                breakpoint.desinstall(set_ip=True)
            else:
                breakpoint = self.process.findBreakpoint(ip)
                breakpoint.desinstall(set_ip=True)

        return event

    def single_step(self,signum=None):
        event = None
        process = self.process
        process.syscall_state.clear()

        process.singleStep()

        event = self.wait_event()

        if isinstance(event, ProcessExit) or isinstance(event, ProcessEnd):
            return event

        ip = process.getInstrPointer()
        ip = ip - 1

        if ip in self.hooked_functions:
            print "ENTERING HOOK FUNCTION"
            name, module = self.hooked_functions[ip]
            event = Call(name, module)
            event.detect_parameters(self.process)
            event.detect_return_address(self.process)

            return_address = event.get_return_address()
            self.breakpoint(return_address)

            self.process.cont()
            self.dbg.waitProcessEvent()
            event.detect_return_value(self.process)

            ip = process.getInstrPointer()
            ip = ip - 1

            breakpoint = self.process.findBreakpoint(ip)
            breakpoint.desinstall(set_ip=True)
        else:
            breakpoint = self.process.findBreakpoint(ip)

            if breakpoint:
                breakpoint.desinstall(set_ip=True)

        return event

    def breakpoint(self, address):

        process = self.process
        # Create breakpoint
        size = None
        try:
            bp = process.createBreakpoint(address, size)
        except PtraceError, err:
            return "Unable to set breakpoint at %s: %s" % (
                formatAddress(address), err)
        #error("New breakpoint: %s" % bp)
        return bp

    def get_context(self, registers, mapper):
        context = {}
        #print "mapper:",mapper
        for reg in registers:
            # FIXME: Temporary ugly hack...
            if reg == 'rflags':
                continue

            #print "reg",reg
            if reg in mapper:
                base, offset = mapper[reg]
            else:
                base, offset = reg, 0

            value = self.process.getreg(base)
            # print "base-value-offset", base, value, offset
            context[reg] = self._extract_value(value, offset, 32)


        value = self.process.getreg('eflags')

        context['eflags'] = self._extract_value(value, 0, 32)

        return context

    def _extract_value(self, main_value, offset, size):
        return (main_value >> offset) & 2**size-1

    def _insert_value(self, main_value, value_to_insert, offset, size):
        main_value &= ~((2**size-1) << offset)
        main_value |= (value_to_insert & 2**size-1) << offset

        return main_value
