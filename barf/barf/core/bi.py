"""
Binary Interface Module.
"""

import subprocess
import re
import os

from pefile import PE
from pybfd.bfd import Bfd

import misc as misc
import barf.arch as arch

class Memory(object):

    """Generic Memory Interface.
    """

    def __init__(self, read_function, write_function):

        # Memory read function. It is implemented this way so it can be
        # used to read memory from GDB as well as a python array.
        self.read_function = read_function

        # Memory write function.
        self.write_function = write_function

    def __getitem__(self, key):
        """Get memory content by range or address.
        """
        val = ""

        if isinstance(key, slice):
            step = 1 if key.step is None else key.step

            try:
                # Read memory one byte at a time.
                for addr in range(key.start, key.stop, step):
                    val += self.read_function(addr, 0x1)[0]
            except IndexError as reason:
                print "[-] Index out of range : %s" % hex(addr)
                #raise IndexError(reason)
        elif isinstance(key, int):
            val += self.read_function(key, 0x1)[0]
        else:
            raise TypeError("Invalid argument type : %s" % type(key))

        return val


class BinaryFile(object):

    """Binary file representation.
    """

    def __init__(self, filename, deps = True):

        # File name of the binary file.
        self._filename = filename

        # Section .text.
        self._section_text = None

        # Start address of the section .text.
        self._section_text_start = None

        # End address of the section .text (last addressable byte
        # address).
        self._section_text_end = None

        # Underlying architecture.
        self._arch = None

        # Architecture mode.
        self._arch_mode = None

        self._deps = deps

        # Open file
        if filename:
            self._open(filename)


    @property
    def start_address(self):
        """Get start address of section .text.
        """
        return self._start_address

    @property
    def ea_start(self):
        """Get start address of section .text.
        """
        return self._section_text_start

    @property
    def ea_end(self):
        """Get end address of section .text (last addressable byte
        address).

        """
        return self._section_text_end

    @property
    def architecture(self):
        """Get architecture name.
        """
        return self._arch

    @property
    def architecture_mode(self):
        """Get architecture mode name.
        """
        return self._arch_mode

    @property
    def filename(self):
        """Get file name.
        """
        return self._filename

    @property
    def file_format(self):
        """Get file format.
        """
        pass

    @property
    def text_section(self):
        """Get section .text.
        """
        return self._section_text_memory


    def _open(self, filename):
        # # open file
        # bfd = Bfd(filename)

        # # get text section
        # stext = bfd.sections.get(".text")

        # self._section_text = stext.content
        # self._section_text_start = stext.vma
        # self._section_text_end = stext.vma + stext.size - 1
        # self._section_text_memory = Memory(self._text_section_reader, self._text_section_writer)

        # # get arch and arch mode
        # self._arch = self._map_architecture(bfd.architecture_name)
        # self._arch_mode = self._map_architecture_mode(bfd.arch_size)

        try:

            bfd = Bfd(filename)

            self._sections = bfd.sections
            self._start_address = bfd.start_address

            self._populate_plt_got(filename,0x0)

            # get text section
            stext = self._sections.get(".text")

            self._section_text = stext.content
            self._section_text_start = stext.vma
            self._section_text_end = stext.vma + stext.size - 1
            self._section_text_memory = Memory(self._text_section_reader, self._text_section_writer)

            # get arch and arch mode
            self._arch = self._map_architecture(bfd.architecture_name)
            self._arch_mode = self._map_architecture_mode(bfd.arch_size)
            self.libs = dict()

            if self._deps:
                self._populate_libraries_ldd()
                for lib in self._libs:
                    if "/" in lib:
                        lib = os.path.realpath(lib)
                        self.libs[lib] = BinaryFile(lib, deps=False)
        try:
            pe = PE(filename)

            section_idx = None

            for idx, section in enumerate(pe.sections):
                if section.Name.replace("\x00", ' ').strip() == ".text":
                    section_idx = idx
                    break

            if section_idx != None:
                self._section_text = pe.sections[section_idx].get_data()
                self._section_text_start = pe.OPTIONAL_HEADER.ImageBase + pe.sections[section_idx].VirtualAddress
                self._section_text_end = self._section_text_start + len(self._section_text) - 1
                self._section_text_memory = Memory(self._text_section_reader, self._text_section_writer)

                # get arch and arch mode
                IMAGE_FILE_MACHINE_I386 = 0x014c
                IMAGE_FILE_MACHINE_AMD64 = 0x8664

                if pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                    self._arch = arch.ARCH_X86
                    self._arch_mode = arch.ARCH_X86_MODE_32
                elif pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
                    self._arch = arch.ARCH_X86
                    self._arch_mode = arch.ARCH_X86_MODE_64
                else:
                    raise Exception("Machine not supported.")
        except:
            # print "PEFile could not open the file."
            pass

        if not self._section_text:
            raise Exception("Could not open the file.")


    def _populate_libraries_ldd(self):
        """
        from pwntools
        """
        try:
            cmd = '(ulimit -s unlimited; ldd %s > /dev/null && (LD_TRACE_LOADED_OBJECTS=1 %s || ldd %s)) 2>/dev/null'
            arg = misc.sh_string(self.filename)

            data = subprocess.check_output(cmd % (arg, arg, arg), shell = True)
            self._libs = misc.parse_ldd_output(data)
        except subprocess.CalledProcessError:
            self._libs = {}

    def _populate_plt_got(self, path, base):
        """
        from pwntools
        """
        plt, got = dict(), dict()

        cmd = ['/usr/bin/objdump', '-d', path]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        got32 = '[^j]*jmp\s+\*0x(\S+)'
        got64 = '[^#]*#\s+(\S+)'
        lines = re.findall('([a-fA-F0-9]+)\s+<([^@<]+)@plt>:(%s|%s)' % (got32, got64), out)

        for addr, name, _, gotaddr32, gotaddr64 in lines:
            addr = int(addr, 16)

            try:
               gotaddr = int(gotaddr32 or gotaddr64, 16)
            except ValueError:
               gotaddr = None

            plt[name] = base + addr
            got[name] = gotaddr

        self.plt = plt
        self.got = got

    def _map_architecture(self, bfd_arch):
        arch_map = {
            "Intel 386" : arch.ARCH_X86,
        }

        return arch_map[bfd_arch]

    def _map_architecture_mode(self, bfd_arch_mode):
        arch_mode_map = {
            32 : arch.ARCH_X86_MODE_32,
            64 : arch.ARCH_X86_MODE_64
        }

        return arch_mode_map[bfd_arch_mode]

    def _text_section_reader(self, address, size):
        start = address - self._section_text_start
        end = start + size

        return self._section_text[start:end]

    def _text_section_writer(self):
        raise Exception("section .text is readonly.")
