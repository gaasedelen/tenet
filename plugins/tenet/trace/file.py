import os
import time
import zlib
import array
import bisect
import ctypes
import struct
import zipfile
import binascii
import itertools
import collections

# -----------------------------------------------------------------------------
# file.py -- Trace File
# -----------------------------------------------------------------------------
#
#    NOTE/PREFACE: Please be aware, this is a 100% prototype implementation
#    of a basic trace log file specification. It has not been designed with
#    exhaustive attention to scalability + performance for use-cases that
#    exceed the recommended 'maximum' of 10,000,000 (10m) instructions.
#
#    There are no dependencies. There is no multiprocessing. This is will
#    be a nightmare to maintain or scale further. It is 100% meant to be
#    thrown away in favor of a native backend.
#
#    --------------
#
#    This file contains the 'trace file' implementation for the plugin. It
#    is responsible for the loading / processing of raw text traces, providing
#    a few 'low level' APIs for querying information out of the lifted trace.
#
#    When loading a text trace, this code will also do some basic compression
#    of the trace to reduce both its on-disk and in-memory footprint. It will
#    also perform some basic 'indexing' of the trace and its contents to make
#    it more performant to search and query by the 'high level' trace reader.
#
#    Upon completion, the indexed+compressed trace file is saved to disk
#    alongside the original trace, with the '.tt' (Tenet Trace) file
#    extension. This original trace can be discarded by the user.
#
#    The processed trace can be loaded and used in a fraction of the time
#    versus the raw text trace. The trace file implementation will also seek
#    out a matching file name with the '.tt' file extension, and prioritize
#    loading that over a raw text trace.
#

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------

#
# attempt plugin imports, assuming this file is being run / loaded in
# the context of the plugin running within a disassembler
#

try:
    from tenet.util.log import pmsg
    from tenet.trace.arch import ArchAMD64, ArchX86, ArchArm32
    from tenet.trace.types import TraceMemory

#
# this script can technically be run in a standalone mone to process / digest
# a trace outside of a disassembler / the normal integration. so if the above
# fails, use the following imports to operate independently
#

except ImportError:
    from arch import ArchAMD64, ArchX86, ArchArm32
    from .types import TraceMemory

    pmsg = print

# -----------------------------------------------------------------------------
# Definitions
# -----------------------------------------------------------------------------

BYTE_MAX = (1 << 8) - 1
USHRT_MAX = (1 << 16) - 1
UINT_MAX = (1 << 32) - 1
ULLONG_MAX = (1 << 64) - 1

TRACE_MEM_READ = 0
TRACE_MEM_WRITE = 1

#
# NOTE: some of this stuff is probably broken / cannot be easily toggled
# anymore, so I wouldn't actually suggest playing around with them as things
# will probably break or behave erratically
#

TRACE_STATS = False

# DEFAULT_COMPRESSION = zipfile.ZIP_BZIP2
# DEFAULT_COMPRESSION = zipfile.ZIP_LZMA
DEFAULT_COMPRESSION = zipfile.ZIP_DEFLATED

# DEFAULT_SEGMENT_LENGTH = 250_000
# DEFAULT_SEGMENT_LENGTH = 1_000_000
DEFAULT_SEGMENT_LENGTH = USHRT_MAX
REG_OFFSET_CACHE_SIZE = 16
REG_OFFSET_CACHE_INTERVAL = 4096

# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def hash_file(filepath):
    """
    Return a CRC32 of the file at the given path.
    """
    crc = 0
    with open(filepath, "rb", 65536) as ins:
        for x in range(int((os.stat(filepath).st_size / 65536)) + 1):
            crc = zlib.crc32(ins.read(65536), crc)
    return crc & 0xFFFFFFFF


def number_of_bits_set(i):
    """
    Count the number of bits set in the given 32bit integer.
    """
    i = i - ((i >> 1) & 0x55555555)
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333)
    return (((i + (i >> 4) & 0xF0F0F0F) * 0x1010101) & 0xFFFFFFFF) >> 24


def width_from_type(t):
    """
    Return the byte width of a python 'struct' type definition.
    """
    if t == "B":
        return 1
    elif t == "H":
        return 2
    elif t == "I":
        return 4
    elif t == "Q":
        return 8
    raise ValueError(f"Invalid type '{t}'")


def type_from_width(width):
    """
    Return an appropriate integer type for the given byte width.
    """
    if width == 1:
        return "B"
    elif width == 2:
        return "H"
    elif width == 4:
        return "I"
    elif width == 8:
        return "Q"
    raise ValueError(f"Invalid type width {width}")


def type_from_limit(limit):
    """
    Return an appropriate integer type for the maximum given value.
    """
    if limit <= BYTE_MAX:
        return "B"
    elif limit <= USHRT_MAX:
        return "H"
    elif limit <= UINT_MAX:
        return "I"
    elif limit <= ULLONG_MAX:
        return "Q"
    raise ValueError(f"Limit {limit:,} exceeds maximum type")


# -----------------------------------------------------------------------------
# Serialization Structures
# -----------------------------------------------------------------------------


class TraceInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("arch_magic", ctypes.c_uint32),
        ("ip_num", ctypes.c_uint32),
        ("mem_addrs_num", ctypes.c_uint32),
        ("mask_num", ctypes.c_uint32),
        ("mem_idx_width", ctypes.c_uint8),
        ("mem_addr_width", ctypes.c_uint8),
        ("original_hash", ctypes.c_uint32),
    ]


class SegmentInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("base_idx", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("ip_num", ctypes.c_uint32),
        ("ip_length", ctypes.c_uint32),
        ("reg_mask_num", ctypes.c_uint32),
        ("reg_mask_length", ctypes.c_uint32),
        ("reg_data_length", ctypes.c_uint32),
        ("mem_read_num", ctypes.c_uint32),
        ("mem_read_data_length", ctypes.c_uint32),
        ("mem_write_num", ctypes.c_uint32),
        ("mem_write_data_length", ctypes.c_uint32),
    ]


class MemValue(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("mask", ctypes.c_uint8), ("value", ctypes.c_uint8 * 8)]


# -----------------------------------------------------------------------------
# Trace File
# -----------------------------------------------------------------------------


class TraceFile(object):
    """
    An interface to load and query data directly from a trace file.
    """

    def __init__(self, filepath, arch=None):
        self.filepath = filepath
        self.arch = arch

        #
        # TODO: really, the trace file should auto-detect arch imo but i'll
        # do that at a later date...
        #

        if not self.arch:
            raise ValueError("TraceFile requires an arch")

        # a sorted array of all unique PC / IP (eg, EIP, or RIP) that appear in the trace
        self.ip_addrs = None

        #
        # mem_addrs: a sorted array of all unique memory addresses referenced
        # in the trace (8-byte aligned)
        #
        # mem_masks: a sorted array of byte masks that correspond with the addrs
        # array described above. each entry in this array is a single 8bit mask,
        # where each bit specifies if that memory address was accessed over the
        # course of the entire trace
        #
        #   e.g:
        #           mem_addrs[924] = 0x401448 (an 8-byte aligned memory address)
        #           mem_masks[924] = 0x0F     (a 'mask' of what bytes exist in the trace)
        #                             |
        #                             |_ a bit mask of 00001111
        #
        # In this example, we know that 0x401448 --> 0x40144C were either read
        # or written at some point in this trace.
        #
        # The alignment of pointers helps with basic id-based compression as
        # these pointer id / 'mapped addresses' are used across the segments.
        #
        # The masks effectively create a global bitmap of all addresses that
        # actually appear in the trace, allowing certain addresses to be
        # immediately discarded from memory queries. This can dramatically
        # reduce search complexity.
        #

        self.mem_addrs = None
        self.mem_masks = None

        #
        # register data is stored in a contiguos blob for each trace segment.
        #
        # for each step / 'instruction' of the trace, we create a 32bit
        # register mask that defines which registers changed. each bit in
        # the mask defines 1 unique CPU register, and its position in the
        # mask specifies which one it is.
        #
        # this will contain a list of each unique register delta mask that
        # appears in the trace. instead of storing 32bit mask for each step
        # of the trace, we use this table to translate a 8bit ID (an index)
        # into this table of unique register masks (self.masks)
        #

        self.masks = []  # TODO: rename to register_masks or something...

        # an O(1) lookup table for the 'byte size' of each register mask
        self.mask_sizes = []

        #
        # a trace is broken up into segments of 64k instructions. each of
        # theses segments will have small indexes / summaries embedded in
        # them to make them easier to search or ignore as applicable
        #
        # for more information, look at the TraceSegments class
        #

        self.segments = []

        # the number of timestamps / 'instructions' for each trace segment
        self.segment_length = DEFAULT_SEGMENT_LENGTH

        # the hash of the original / source log file
        self.original_hash = None

        #
        # now that you have some idea of how the trace file is going to be
        # organized... let's actually go and try to load one
        #

        self._load_trace()

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def name(self):
        """
        Return the name of the trace.
        """
        return os.path.basename(self.filepath)

    @property
    def packed_name(self):
        """
        Return the packed trace filename.
        """
        root, ext = os.path.splitext(self.name)
        return f"{root}.tt"

    @property
    def packed_filepath(self):
        """
        Return the packed trace filepath.
        """
        directory = os.path.dirname(self.filepath)
        return os.path.join(directory, self.packed_name)

    @property
    def length(self):
        """
        Return the length of the trace. (e.g, # instructions executed)
        """
        if not self.segments:
            return 0
        return self.segments[-1].base_idx + self.segments[-1].length

    # -------------------------------------------------------------------------
    # Public
    # -------------------------------------------------------------------------

    #
    # I should really define this somewhere more notable... but throughout
    # this project you will see the term 'idx', this is a simple abbreviation
    # of 'index' that I used early on and kind of stuck with.
    #
    # an idx is simply an integer, that repersents a unique 'timestamp' in
    # the trace file. eg, idx 0 is the start of the trace, idx 100 is
    # equivalent to 100 steps into the trace, etc...
    #
    # an idx label attached to any sort of variable / definition in this
    # codebase suggest that variable is a trace 'timestamp' / position!
    #

    def get_reg_delta(self, idx):
        """
        Return the register delta for a given timestamp.
        """
        seg = self.get_segment(idx)
        if not seg:
            return {}
        return seg.get_reg_delta(idx)

    def get_read_delta(self, idx):
        """
        Return the memory read delta for a given timestamp.
        """
        seg = self.get_segment(idx)
        if not seg:
            return {}
        return seg.get_read_delta(idx)

    def get_write_delta(self, idx):
        """
        Return the memory write delta for a given timestamp.
        """
        seg = self.get_segment(idx)
        if not seg:
            return {}
        return seg.get_write_delta(idx)

    def get_segment(self, idx):
        """
        Return the trace segment for a given timestamp.
        """
        for seg in self.segments:
            if seg.base_idx <= idx < seg.base_idx + seg.length:
                return seg
        return None

    def get_reg_mask_ids_containing(self, reg_name):
        """
        Return a set of reg mask ids containing the given register name.
        """
        reg_id = self.arch.REGISTERS.index(reg_name.upper())
        reg_mask = 1 << reg_id

        found = set()
        for i, current_mask in enumerate(self.masks):
            if current_mask & reg_mask:
                found.add(i)

        return found

    # -------------------------------------------------------------------------
    # Save / Serialization
    # -------------------------------------------------------------------------

    def _save(self):
        """
        Save the packed trace to disk.
        """

        with zipfile.ZipFile(
            self.packed_filepath, "w", compression=DEFAULT_COMPRESSION
        ) as zip_archive:
            self._save_header(zip_archive)
            self._save_segments(zip_archive)

        self.filepath = self.packed_filepath

    def _save_header(self, zip_archive):
        """
        Save the trace header to the packed trace.
        """

        # populate the trace header
        header = TraceInfo()
        header.arch_magic = self.arch.MAGIC
        header.ip_num = len(self.ip_addrs)
        header.mem_addrs_num = len(self.mem_addrs)
        header.mask_num = len(self.masks)
        header.mem_idx_width = width_from_type(self.mem_idx_type)
        header.mem_addr_width = width_from_type(self.mem_addr_type)
        header.original_hash = self.original_hash
        mask_data = (ctypes.c_uint32 * len(self.masks))(*self.masks)

        # save the global trace data / header to the zip
        with zip_archive.open("header", "w") as f:
            f.write(bytearray(header))
            f.write(bytearray(self.ip_addrs))
            f.write(bytearray(self.mem_addrs))
            f.write(bytearray(self.mem_masks))
            f.write(bytearray(mask_data))

    def _save_segments(self, zip_archive):
        """
        Save the trace segments to the packed trace.
        """
        for segment in self.segments:
            with zip_archive.open(f"segments/{segment.id}", "w") as f:
                segment.dump(f)

    # -------------------------------------------------------------------------
    # Load / Deserialization
    # -------------------------------------------------------------------------

    def _load_trace(self):
        """
        Load a trace from disk.

        NOTE: THIS ROUTINE WILL ATTEMPT TO LOAD A PACKED TRACE INSTEAD OF A
        SELECTED RAW TEXT TRACE IF IT FINDS ONE AVAILABLE!!!
        """

        # the user probably selected a '.tt' trace
        if zipfile.is_zipfile(self.filepath):
            self._load_packed_trace(self.filepath)
            return

        #
        # the user selected a '.txt' trace, but there is a '.tt' packed trace
        # beside it, so let's check if the packed trace matches the text trace
        #

        if zipfile.is_zipfile(self.packed_filepath):
            packed_crc = self._fetch_hash(self.packed_filepath)
            text_crc = hash_file(self.filepath)

            #
            # the crc in the packed file seems to match the selected text log,
            # so let's just load the packed trace as it should be faster
            #

            if packed_crc == text_crc:
                self._load_packed_trace(self.packed_filepath)
                return

        #
        # no luck loading / side-loading packed traces, so simply try to
        # load the user selected trace as a normal text Tenet trace
        #

        self._load_text_trace(self.filepath)

    def _load_packed_trace(self, filepath):
        """
        Load a packed trace from disk.
        """

        with zipfile.ZipFile(filepath, "r") as zip_archive:
            self._load_header(zip_archive)
            self._load_segments(zip_archive)

        self.filepath = filepath

    def _select_arch(self, magic):
        """
        TODO: Select the trace CPU arch based on the given magic value.
        """
        if ArchAMD64.MAGIC == magic:
            self.arch = ArchAMD64()
        elif ArchArm32.MAGIC == magic:
            self.arch = ArchArm32()
        elif ArchX86.MAGIC == magic:
            self.arch = ArchX86()

        raise ValueError(f"Invalid arch magic 0x{magic:08X}")

    def _fetch_hash(self, filepath):
        """
        Return the original file hash (CRC32) from the given packed trace filepath.
        """
        header = TraceInfo()
        with zipfile.ZipFile(filepath, "r") as zip_archive:
            with zip_archive.open("header", "r") as f:
                f.readinto(header)
                return header.original_hash

    def _load_header(self, zip_archive):
        """
        Load the trace header from a packed trace.
        """
        header = TraceInfo()

        with zip_archive.open("header", "r") as f:

            # read the main trace info from the packed trace header
            f.readinto(header)

            # select the cpu / arch for this trace
            # print(f"Loading magic 0x{header.arch_magic:08X}")
            self._select_arch(header.arch_magic)

            # load the (sorted) ip address table from disk
            self.ip_addrs = array.array(type_from_width(self.arch.POINTER_SIZE))
            self.ip_addrs.fromfile(f, header.ip_num)

            # ('mem_idx_width',   ctypes.c_uint8),
            # ('mem_addr_width',  ctypes.c_uint8),
            self.mem_idx_type = type_from_width(header.mem_idx_width)
            self.mem_addr_type = type_from_width(header.mem_addr_width)
            # self.mem_mask_width = type_from_width(header.mem_mask_width)

            # load the (sorted, aligned) mem table from disk
            self.mem_addrs = array.array(type_from_width(self.arch.POINTER_SIZE))
            self.mem_addrs.fromfile(f, header.mem_addrs_num)
            self.mem_masks = array.array("B")
            self.mem_masks.fromfile(f, header.mem_addrs_num)

            # ('mask_num',   ctypes.c_uint32),
            self.masks = array.array("I")
            self.masks.fromfile(f, header.mask_num)
            self.mask_sizes = [
                number_of_bits_set(mask) * self.arch.POINTER_SIZE for mask in self.masks
            ]

            # source file hash
            self.original_hash = header.original_hash

    def _load_segments(self, zip_archive):
        """
        Load the trace segments from the packed trace.
        """

        for path in zip_archive.namelist():

            # skip anything that is not a trace segment
            if not (path.startswith("segments/") and path[-1] != "/"):
                continue

            # load a trace segment from the packed trace file
            with zip_archive.open(path, "r") as f:
                segment = TraceSegment(self)
                segment.from_file(f)

            # save the segment to the trace
            self.segments.append(segment)

        # sort the loaded segments by id (just in case)
        self.segments.sort(key=lambda x: x.id)

    def _load_text_trace(self, filepath):
        """
        Load a text trace from disk.
        """
        idx = 0

        # mappings of address/mask and their mapped (compressed) id
        # - NOTE: these are only used when converting traces from text to binary
        self.ip_map = collections.OrderedDict()
        self.mem_map = collections.OrderedDict()
        self.mask2mapped = {}
        self.masks = []

        # TODO: detect arch based on reg / lines in file
        # if not self.arch:
        #   self._select_arch(0)

        # hash (CRC32) the source / text filepath before loading it
        self.original_hash = hash_file(filepath)

        # load / parse a text trace into trace segments
        with open(filepath, "r") as f:

            # loop until all of the lines in the file have been processed
            while True:

                # select a chunk of N lines from the file
                lines = itertools.islice(f, self.segment_length)
                lines = list(lines)
                if not lines:
                    break

                segment_id = len(self.segments)

                # create a new trace segment from the given lines of text
                segment = TraceSegment(self, segment_id, idx)
                segment.from_lines(lines)
                idx += segment.length

                # save the segment
                self.segments.append(segment)
                # break # for debugging...

        self._finalize()
        self._save()

    def get_ip(self, idx):
        """
        Return the fully qualified IP for the given timestamp.
        """
        seg = self.get_segment(idx)
        if not seg:
            raise ValueError("Invalid IDX %u" % idx)
        return seg.get_ip(idx)

    def get_mapped_ip(self, ip):
        """
        Return the 'mapped' (compressed) id for the given instruction address.
        """
        index = bisect.bisect_left(self.ip_addrs, ip)

        try:
            if ip == self.ip_addrs[index]:
                return index
        except IndexError:
            pass

        raise ValueError(f"Address {ip:08X} does not have a mapped ID")

    #
    # TODO: note, uh.. these should all be refactored... gross
    #

    def get_aligned_address(self, address):
        return (address >> 3) << 3

    def get_mapped_address(self, address):
        """
        Return the 'mapped' (compressed) id for the given memory address.
        """

        #
        # TODO: use pointer size/alignment?? eg, this might make mem lookups faster
        # if we tune it to 32bit vs 64bit (at the cost of possible trace size inflation)
        #

        aligned_address = (address >> 3) << 3
        index = bisect.bisect_left(self.mem_addrs, aligned_address)

        if index == len(self.mem_addrs):
            return -1

        if aligned_address != self.mem_addrs[index]:
            return -1

        return index

    def get_aligned_address_mask(self, address, length=8):
        """
        TODO: ugh hopefully we'll have a native backend before i have to try
        and write a comment to describe the mess we're in
        """
        mask_offset = address % 8
        aligned_address = (address >> 3) << 3
        aligned_mask = (((1 << length) - 1) << mask_offset) & 0xFF
        return aligned_mask

    def _finalize(self):
        """
        Bake a parsed text trace into its final, compressed form.
        """

        if TRACE_STATS:
            self._init_stats()

        # a 32 or 64 bit array.array type code, depending on the trace arch pointer size
        pointer_type = type_from_width(self.arch.POINTER_SIZE)

        # bake the master ip address table
        ip_map = self.ip_map
        ip_addrs = sorted(list(self.ip_map.keys()))
        self.ip_addrs = array.array(pointer_type, ip_addrs)

        remapped_ip = {ip_map[address]: i for i, address in enumerate(ip_addrs)}

        # bake the master (aligned) memory address table
        mem_map = self.mem_map
        mem_map_len = len(mem_map)
        mem_addrs = sorted(list(mem_map.keys()))
        self.mem_addrs = array.array(pointer_type, mem_addrs)
        self.mem_masks = array.array("B", [0] * len(mem_addrs))

        # generate a temporary mem re-mapping map...
        remapped_mem = {mem_map[address]: i for i, address in enumerate(mem_addrs)}

        # pre-compute the 'size' of the data represented by a register mask
        self.mask_sizes = [number_of_bits_set(mask) * self.arch.POINTER_SIZE for mask in self.masks]

        assert self.segment_length <= UINT_MAX
        assert mem_map_len <= UINT_MAX

        self.mem_idx_type = type_from_limit(self.segment_length)
        self.mem_addr_type = type_from_limit(mem_map_len)

        # finish packing the trace
        for segment in self.segments:
            segment.finalize(remapped_ip, remapped_mem)

            if TRACE_STATS:
                self._harvest_stats(segment)

        # dispose of stuff we don't need anymore
        del self.ip_map
        del self.mem_map
        del remapped_mem

        if TRACE_STATS:
            self._finalize_stats()

    # -------------------------------------------------------------------------
    # Trace Statistics
    # -------------------------------------------------------------------------

    def _init_stats(self):
        self.unique_mem_addr = set()
        self.avg_unique_mem_addr = 0
        self.min_unique_mem_addr = 999999999
        self.max_unique_mem_addr = -1

        self.avg_unique_ip = 0
        self.min_unique_ip = 999999999999
        self.max_unique_ip = -1

        self.num_bytes_read = 0
        self.num_bytes_written = 0
        self.num_bytes_read_info = 0
        self.num_bytes_written_info = 0

        self.num_bytes_ips = 0
        self.num_bytes_reg_data = 0
        self.num_bytes_reg_masks = 0

        self.raw_size = 0

        self.unique_ip = 0
        self.num_bytes_unique_ip = 0

        self.unique_mem = 0
        self.num_bytes_unique_mem = 0

    def _harvest_stats(self, seg):
        unique_mem_addr = seg.read_addresses | seg.write_addresses
        self.unique_mem_addr |= unique_mem_addr

        num_unique_mem_addr = len(unique_mem_addr)
        self.avg_unique_mem_addr += num_unique_mem_addr
        self.min_unique_mem_addr = min(self.min_unique_mem_addr, num_unique_mem_addr)
        self.max_unique_mem_addr = max(self.max_unique_mem_addr, num_unique_mem_addr)

        num_unique_ip = seg.num_unique_ip
        self.avg_unique_ip += num_unique_ip
        self.min_unique_ip = min(self.min_unique_ip, num_unique_ip)
        self.max_unique_ip = max(self.max_unique_ip, num_unique_ip)

        self.num_bytes_read += seg.num_bytes_read
        self.num_bytes_written += seg.num_bytes_written
        self.num_bytes_read_info += seg.num_bytes_read_info
        self.num_bytes_written_info += seg.num_bytes_written_info

        self.num_bytes_ips += seg.num_bytes_ips
        self.num_bytes_reg_data += seg.num_bytes_reg_data
        self.num_bytes_reg_masks += seg.num_bytes_reg_masks

        self.raw_size += seg.raw_size_bytes
        # self.length += seg.length

    def _finalize_stats(self):
        self.avg_unique_ip = self.avg_unique_ip // len(self.segments)
        self.avg_unique_mem_addr = self.avg_unique_mem_addr // len(self.segments)

        self.unique_ip = len(self.ip_addrs)
        self.num_bytes_unique_ip = len(self.ip_addrs) * self.arch.POINTER_SIZE
        self.raw_size += self.num_bytes_unique_ip

        self.unique_mem = len(self.mem_addrs)
        self.num_bytes_unique_mem = len(self.mem_addrs) * self.arch.POINTER_SIZE
        self.raw_size += self.num_bytes_unique_mem

    def print_stats(self):
        output = []
        output.append(f"+- Trace Stats")
        output.append("")
        output.append(f" -- {self.length:,} timestamps")
        output.append(f" -- {len(self.segments):,} segments")
        output.append("")
        output.append(f" - Address Stats")
        output.append("")
        output.append(f" -- {self.unique_ip:,} total unique ip addresses")
        output.append(f" ---- {self.avg_unique_ip} avg")
        output.append(f" ---- {self.min_unique_ip} min")
        output.append(f" ---- {self.max_unique_ip} max")
        output.append("")
        output.append(f" -- {len(self.unique_mem_addr):,} total unique mem addresses")
        output.append(f" ---- {self.avg_unique_mem_addr} avg")
        output.append(f" ---- {self.min_unique_mem_addr} min")
        output.append(f" ---- {self.max_unique_mem_addr} max")
        output.append("")
        output.append(f" - Memory / Disk Footprint")
        output.append("")
        output.append(f" -- {self.raw_size/(1024*1024):0.2f}mb - raw size")
        output.append("")
        output.append(
            f" ---- {self.num_bytes_unique_ip / (1024*1024):0.2f}mb ({(self.num_bytes_unique_ip / self.raw_size) * 100 :3.2f}%) - ip addrs"
        )
        output.append(
            f" ---- {self.num_bytes_unique_mem / (1024*1024):0.2f}mb ({(self.num_bytes_unique_mem / self.raw_size) * 100 :3.2f}%) - mem addrs"
        )
        output.append(
            f" ---- {self.num_bytes_ips / (1024*1024):0.2f}mb ({(self.num_bytes_ips / self.raw_size) * 100 :3.2f}%) - ip trace"
        )
        output.append(
            f" ---- {self.num_bytes_reg_data / (1024*1024):0.2f}mb ({(self.num_bytes_reg_data / self.raw_size) * 100 :3.2f}%) - reg data"
        )
        output.append(
            f" ---- {self.num_bytes_reg_masks / (1024*1024):0.2f}mb ({(self.num_bytes_reg_masks / self.raw_size) * 100 :3.2f}%) - reg masks"
        )
        output.append("")
        output.append(
            f" ---- {self.num_bytes_read / (1024*1024):0.2f}mb ({(self.num_bytes_read / self.raw_size) * 100 :3.2f}%) - bytes read"
        )
        output.append(
            f" ---- {self.num_bytes_written / (1024*1024):0.2f}mb ({(self.num_bytes_written / self.raw_size) * 100 :3.2f}%) - bytes written"
        )
        output.append(
            f" ---- {self.num_bytes_read_info / (1024*1024):0.2f}mb ({(self.num_bytes_read_info / self.raw_size) * 100 :3.2f}%) - read pointers"
        )
        output.append(
            f" ---- {self.num_bytes_written_info / (1024*1024):0.2f}mb ({(self.num_bytes_written_info / self.raw_size) * 100 :3.2f}%) - write pointers"
        )
        print("".join(output))


class TraceSegment(object):
    """
    A segment of trace data.
    """

    def __init__(self, trace, id=0, base_idx=0):
        self.id = id
        self.arch = trace.arch
        self.trace = trace

        self.base_idx = base_idx
        self.length = 0

        self.reg_data = None
        self.reg_masks = None

        self.read_data = None
        self.read_idxs = None
        self.read_addrs = None
        self.read_masks = None
        self.read_offsets = []

        self.write_data = None
        self.write_idxs = None
        self.write_addrs = None
        self.write_masks = None
        self.write_offsets = []

        self.mem_delta = collections.defaultdict(MemValue)

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def read_set(self):
        return set(self.read_addrs)

    @property
    def write_set(self):
        return set(self.write_addrs)

    @property
    def num_unique_ip(self):
        return len(set(self.ips))

    @property
    def num_unique_mem_addresses(self):
        return len(self.read_set | self.write_set)

    @property
    def num_bytes_read(self):
        return len(self.read_data)

    @property
    def num_bytes_written(self):
        return len(self.write_data)

    # @property
    # def num_bytes_read_info(self):
    #    return ctypes.sizeof(self._mem_read_info)

    # @property
    # def num_bytes_written_info(self):
    #    return ctypes.sizeof(self._mem_write_info)

    @property
    def num_bytes_reg_data(self):
        return len(self.reg_data)

    @property
    def num_bytes_ips(self):
        return ctypes.sizeof(self.ips)

    @property
    def num_bytes_reg_masks(self):
        return ctypes.sizeof(self.reg_masks)

    @property
    def raw_size_bytes(self):
        size = 0

        # reg data storage costs
        size += self.num_bytes_ips
        size += self.num_bytes_reg_data
        size += self.num_bytes_reg_masks

        # memory data storage costs
        size += self.num_bytes_read
        size += self.num_bytes_written
        size += self.num_bytes_read_info
        size += self.num_bytes_written_info

        return size

    @property
    def raw_size_mb(self):
        return self.raw_size_bytes / (1024 * 1024)

    def __str__(self):
        output = []
        output.append(f"Trace Segment -- IDX {self.base_idx}")
        output.append(
            f" -- Reg Data {len(self.reg_data)} bytes ({len(self.reg_data) / (1024*1024):0.2f}mb)"
        )
        output.append(f" -- Unique IP {len(set(self.ips))}")
        output.append(f" -- Raw Size {self.raw_size_mb:0.2f}mb")
        return "".join(output)

    # -------------------------------------------------------------------------
    # Public
    # -------------------------------------------------------------------------

    def from_lines(self, lines):
        """
        Load a trace segment from the given lines.
        """

        # ip storage
        self.ips = [0 for x in range(self.trace.segment_length)]

        # register storage (minus IP)
        MAX_REG_DATA = (
            self.trace.arch.POINTER_SIZE
            * len(self.trace.arch.REGISTERS)
            * self.trace.segment_length
        )
        self.reg_data = bytearray(MAX_REG_DATA)
        self.reg_offsets = array.array("I", [0] * REG_OFFSET_CACHE_SIZE)
        self.reg_masks = [0 for x in range(self.trace.segment_length)]
        self._reg_offset = 0

        # memory defs
        self._mem_read_info = []
        self.read_data = bytearray()
        self._mem_write_info = []
        self.write_data = bytearray()
        self._max_read_size = 0
        self._max_write_size = 0

        self._process_lines(lines)
        # print(f"Snapshot entries: {len(self.mem_delta)}")

    def from_file(self, f):
        """
        Load the trace segment from the given filestream.
        """
        self.load(f)

    def get_ip(self, idx):
        """
        Return the IP for the given timestamp.
        """
        relative_idx = idx - self.base_idx
        return self.trace.ip_addrs[self.ips[relative_idx]]

    def get_reg_delta(self, idx):
        """
        Return the register delta for the given timestamp.
        """
        relative_idx = idx - self.base_idx

        # IP is the only register guaranteed to have changed each step
        ip_address = self.trace.ip_addrs[self.ips[relative_idx]]

        # fetch the mask that tells which registers have changed this delta
        mask = self.trace.masks[self.reg_masks[relative_idx]]

        # if no registers changed, nothing to do but return IP
        if not mask:
            return {self.trace.arch.IP: ip_address}

        #
        # fetch the closest cached register data offset that we can start from
        # for computing precisely where we should be working backwards from
        #

        cache_index = int(relative_idx / REG_OFFSET_CACHE_INTERVAL)
        cache_offset = self.reg_offsets[cache_index]
        cache_idx = cache_index * REG_OFFSET_CACHE_INTERVAL

        # compute the current 'offset' in the reg data that we will work back from
        sizes = self.trace.mask_sizes
        offset_masks = self.reg_masks[cache_idx:relative_idx][::-1]
        offset = cache_offset + sum([sizes[mask_id] for mask_id in offset_masks])

        # compute the location of the packed register delta data
        # offset_slow = sum([sizes[mask_id] for mask_id in self.reg_masks[:relative_idx]])
        # assert offset == offset_slow

        # fetch the register data
        reg_names = self._mask2regs(mask)
        num_regs = len(reg_names)
        reg_data = self.reg_data[offset : offset + (num_regs * self.arch.POINTER_SIZE)]

        # unpack the register data
        pack_fmt = "Q" if self.arch.POINTER_SIZE == 8 else "I"
        reg_values = struct.unpack(pack_fmt * num_regs, reg_data)

        # pack all the registers into a dict that will be returned to the user
        registers = dict(zip(reg_names, reg_values))
        registers[self.trace.arch.IP] = ip_address

        # return the completed register delta
        return registers

    #
    # TODO: ugh some of this stuff is pretty gross too, is it even used still...?
    #

    def get_read_delta(self, idx):
        """
        Return the memory read delta for the given timestamp.
        """
        return self._get_mem_delta(idx, TRACE_MEM_READ)

    def get_write_delta(self, idx):
        """
        Return the memory write delta for the given timestamp.
        """
        return self._get_mem_delta(idx, TRACE_MEM_WRITE)

    def _get_mem_delta(self, idx, mem_type):
        """
        Internal abstraction to search memory delta lists.
        """
        relative_idx = idx - self.base_idx
        found, offset = [], 0

        if mem_type == TRACE_MEM_WRITE:
            idxs, addrs, masks, offsets, data = (
                self.write_idxs,
                self.write_addrs,
                self.write_masks,
                self.write_offsets,
                self.write_data,
            )
        else:
            idxs, addrs, masks, offsets, data = (
                self.read_idxs,
                self.read_addrs,
                self.read_masks,
                self.read_offsets,
                self.read_data,
            )

        try:
            i = idxs.index(relative_idx)
        except ValueError:
            return []

        while i < len(idxs) and idxs[i] == relative_idx:

            #
            # fetch the 'aligned' address for this memory access, and the
            # mask which specifes which bytes were touched starting from
            # the aligned address
            #

            aligned_address = self.trace.mem_addrs[addrs[i]]
            access_mask = masks[i]

            # extract the raw data for this memory access
            offset = offsets[i]
            length = number_of_bits_set(masks[i])
            raw_data = data[offset : offset + length]

            address = aligned_address
            seen_byte = False  # TODO KLUDGE
            while access_mask:
                if access_mask & 1 == 0:
                    address += 1
                    assert not seen_byte, "gap in memory access?"
                else:
                    seen_byte = True
                access_mask >>= 1

            found.append((address, raw_data))
            i += 1

        # return all the hits
        return found

    def get_reg_info(self, idx, reg_names):
        """
        Given a starting timestamp and a list of register names, return

            { reg_name: (value, idx) }

        ... for each discoverable register in this segment.

        """
        relative_idx = idx - self.base_idx
        start_idx = relative_idx + 1
        if not (0 <= relative_idx < self.length):
            return {}

        # compute a 32bit mask of the registers we need to find
        target_mask = self._regs2mask(reg_names)

        #
        # fetch the closest cached register data offset that we can start from
        # for computing precisely where we should be working backwards from
        #

        cache_index = int(start_idx / REG_OFFSET_CACHE_INTERVAL)
        cache_offset = self.reg_offsets[cache_index]
        cache_idx = cache_index * REG_OFFSET_CACHE_INTERVAL

        # alias for faster access / readability
        sizes = self.trace.mask_sizes
        masks = self.trace.masks

        # compute the current 'offset' in the reg data that we will work back from
        offset_masks = self.reg_masks[cache_idx:start_idx][::-1]
        offset = cache_offset + sum([sizes[mask_id] for mask_id in offset_masks])

        # the map of reg_name --> (reg_value, src_idx) to return
        found_registers = {}

        # loop backwards through the segment, starting from the given idx
        search_masks = self.reg_masks[:start_idx][::-1]
        # offset_slow = sum([sizes[mask_id] for mask_id in search_masks])
        # assert offset == offset_slow
        for i, mask_id in enumerate(search_masks):

            # translate the mask id for this step into its register bitfield
            current_mask = masks[mask_id]

            #
            # since we are iterating backwards through the register data, we
            # need to subtract from the offset immediately as it is pointing
            # at the end of the register data for this mask.
            #

            offset -= sizes[mask_id]

            # ignore masks that do not touch the target registers
            if not current_mask & target_mask:
                continue

            # translate the 32bit reg mask into a list of register names
            found_mask = current_mask & target_mask
            found_names = self._mask2regs(found_mask)

            # fetch the registers for this delta / timestamp
            registers = self._unpack_registers(current_mask, offset)

            # add the found register names and the current (global) idx
            for reg_name in found_names:
                found_registers[reg_name] = (registers[reg_name], (self.base_idx + (start_idx - i)))

            # remove the registers we found from the remaining search space
            target_mask ^= found_mask

            # if target_mask is 0, then there are no more registers to look for
            if not target_mask:
                break

        return found_registers

    def get_mem_data(self, mem_id, set_id, data_mask):
        """
        Return the data for a given mem access id, in the given set.
        """

        if set_id == 1:
            addrs, masks, offsets, data = (
                self.write_addrs,
                self.write_masks,
                self.write_offsets,
                self.write_data,
            )
        else:
            addrs, masks, offsets, data = (
                self.read_addrs,
                self.read_masks,
                self.read_offsets,
                self.read_data,
            )

        offset = offsets[mem_id]  # sum([number_of_bits_set(mask) for mask in masks[:mem_id]])
        # offset = sum([number_of_bits_set(mask) for mask in masks[:mem_id]])
        length = number_of_bits_set(masks[mem_id])
        raw_data = data[offset : offset + length]

        address = self.trace.mem_addrs[addrs[mem_id]]
        output = TraceMemory(address, 8)

        byte, i = 0, 0

        while data_mask:
            if data_mask & 1:
                output.data[i] = raw_data[byte]
                output.mask[i] = 0xFF
                byte += 1
            i += 1
            data_mask >>= 1

        # assert byte == length

        return output

    # -------------------------------------------------------------------------
    # Finalization
    # -------------------------------------------------------------------------

    def load(self, f):
        """
        Load the trace segment from the given filestream.
        """
        info = SegmentInfo()
        f.readinto(info)

        self.id = info.id
        self.base_idx = info.base_idx
        self.length = info.length

        if info.ip_num == 0:
            raise ValueError("Empty trace file (ip_num == 0)")

        ip_itemsize = info.ip_length // info.ip_num
        ip_type = type_from_width(ip_itemsize)

        # load the ip trace
        self.ips = array.array(ip_type)
        self.ips.fromfile(f, info.ip_num)

        # load the reg mask data
        reg_mask_type = type_from_width(info.reg_mask_length // info.reg_mask_num)
        self.reg_masks = array.array(reg_mask_type)
        self.reg_masks.fromfile(f, info.reg_mask_num)

        # load the reg data
        self.reg_data = bytearray(info.reg_data_length)
        f.readinto(self.reg_data)

        # load the pre-computed register offsets
        self.reg_offsets = array.array("I")
        self.reg_offsets.fromfile(f, REG_OFFSET_CACHE_SIZE)

        #
        # memory
        #

        idx_type = self.trace.mem_idx_type
        addr_type = self.trace.mem_addr_type

        # load the memory read metadata
        self.read_idxs = array.array(idx_type)
        self.read_idxs.fromfile(f, info.mem_read_num)
        self.read_addrs = array.array(addr_type)
        self.read_addrs.fromfile(f, info.mem_read_num)
        self.read_masks = array.array("B")
        self.read_masks.fromfile(f, info.mem_read_num)

        # load the raw memory read data
        self.read_data = bytearray(info.mem_read_data_length)
        f.readinto(self.read_data)

        # load the memory write metadata
        self.write_idxs = array.array(idx_type)
        self.write_idxs.fromfile(f, info.mem_write_num)
        self.write_addrs = array.array(addr_type)
        self.write_addrs.fromfile(f, info.mem_write_num)
        self.write_masks = array.array("B")
        self.write_masks.fromfile(f, info.mem_write_num)

        # load the raw memory write data
        self.write_data = bytearray(info.mem_write_data_length)
        f.readinto(self.write_data)

        # load the mem delta / 'snapshot' data
        addr_set = sorted(set(self.read_addrs + self.write_addrs))
        delta_entries = (MemValue * len(addr_set))()
        f.readinto(delta_entries)

        self.mem_delta = dict(zip(addr_set, delta_entries))

        self._compute_mem_offsets()

    def dump(self, f):
        """
        Dump the trace segment to the given filestream.
        """
        info = SegmentInfo()

        info.id = self.id
        info.base_idx = self.base_idx
        info.length = self.length

        info.ip_num = self.length
        info.ip_length = info.ip_num * self.ips.itemsize

        info.reg_mask_num = len(self.reg_masks)
        info.reg_mask_length = info.reg_mask_num * self.reg_masks.itemsize
        info.reg_data_length = len(self.reg_data)  # bytearray

        info.mem_read_num = len(self.read_idxs)
        info.mem_read_data_length = len(self.read_data)

        info.mem_write_num = len(self.write_idxs)
        info.mem_write_data_length = len(self.write_data)

        f.write(bytearray(info))
        f.write(bytearray(self.ips))

        f.write(bytearray(self.reg_masks))
        f.write(self.reg_data)
        f.write(bytearray(self.reg_offsets))

        self.read_idxs.tofile(f)
        self.read_addrs.tofile(f)
        self.read_masks.tofile(f)
        f.write(self.read_data)

        self.write_idxs.tofile(f)
        self.write_addrs.tofile(f)
        self.write_masks.tofile(f)
        f.write(self.write_data)

        for mapped_address in sorted(set(self.read_addrs + self.write_addrs)):
            f.write(bytearray(self.mem_delta[mapped_address]))

    # -------------------------------------------------------------------------
    # Finalization
    # -------------------------------------------------------------------------

    def finalize(self, remapped_ip, remapped_mem):
        """
        Bake the trace segment into its final, packed form.
        """
        self._finalize_registers(remapped_ip)
        self._finalize_memory(remapped_mem)

    def _finalize_registers(self, remapped_ip):
        """
        Bake registers into ctype structures.
        """
        assert len(remapped_ip) <= UINT_MAX
        assert len(self.trace.mask2mapped) <= USHRT_MAX

        #
        # pack IP trace
        #

        ip_type = type_from_limit(len(remapped_ip))
        new_ips = array.array(ip_type, [0] * len(self.ips))

        for i, mapped_ip in enumerate(self.ips):
            new_ips[i] = remapped_ip[mapped_ip]

        del self.ips
        self.ips = new_ips

        #
        # pack register masks
        #

        mask_type = type_from_limit(len(self.trace.mask2mapped))
        new_masks = array.array(mask_type, self.reg_masks)

        del self.reg_masks
        self.reg_masks = new_masks

    def _finalize_memory(self, remapped_mem):
        """
        Bake memory into ctype structures.
        """
        idx_type = self.trace.mem_idx_type
        addr_type = self.trace.mem_addr_type

        #
        # pack read data
        #

        # allocate fast, compact python arrays to hold our mem read info
        read_idxs = array.array(idx_type)
        read_addrs = array.array(addr_type)
        read_masks = array.array("B")

        # transfer read metadata into compact / searchable arrays
        for entry in self._mem_read_info:
            idx, old_mapped_address, mask = entry

            # convert the old mapped address to a new mapped address
            mapped_address = remapped_mem[old_mapped_address]

            # pack the data into fast / compact python arrays
            read_idxs.append(idx)
            read_addrs.append(mapped_address)
            read_masks.append(mask)

        del self._mem_read_info
        self.read_idxs = read_idxs
        self.read_addrs = read_addrs
        self.read_masks = read_masks

        #
        # pack write data
        #

        # allocate fast, compact python arrays to hold our mem write info
        write_idxs = array.array(idx_type)
        write_addrs = array.array(addr_type)
        write_masks = array.array("B")

        # transfer write metadata into compact / searchable arrays
        for entry in self._mem_write_info:
            idx, old_mapped_address, mask = entry

            # convert the old mapped address to a new mapped address
            mapped_address = remapped_mem[old_mapped_address]

            # pack the data into fast / compact python arrays
            write_idxs.append(idx)
            write_addrs.append(mapped_address)
            write_masks.append(mask)

        del self._mem_write_info
        self.write_idxs = write_idxs
        self.write_addrs = write_addrs
        self.write_masks = write_masks

        #
        # build trace mask
        #

        new_delta = {}
        mem_masks = self.trace.mem_masks

        for old_mapped_address, mv in self.mem_delta.items():
            mapped_address = remapped_mem[old_mapped_address]
            new_delta[mapped_address] = mv
            mem_masks[mapped_address] |= mv.mask

        del self.mem_delta
        self.mem_delta = new_delta

        self._compute_mem_offsets()

    def _compute_mem_offsets(self):
        """
        Pre-compute the offset of each memory access into the raw memory blobs.
        """
        temp_sizes = {}

        self.read_offsets = array.array("I", [0] * len(self.read_masks))
        self.write_offsets = array.array("I", [0] * len(self.write_masks))

        mem_sets = [(self.read_offsets, self.read_masks), (self.write_offsets, self.write_masks)]

        for offsets, masks in mem_sets:
            offset = 0
            for i, mask in enumerate(masks):
                offsets[i] = offset
                length = temp_sizes.setdefault(mask, number_of_bits_set(mask))
                offset += length

    # -------------------------------------------------------------------------
    # Processing / Logic
    # -------------------------------------------------------------------------

    def _process_lines(self, lines):
        """
        Process text lines from a delta reg/mem trace.
        """
        IP = self.trace.arch.IP
        REGISTERS = self.trace.arch.REGISTERS

        relative_idx = 0

        try:

            for line in lines:
                if not self._process_line(line, relative_idx):
                    continue
                relative_idx += 1

        # TODO: pretty gross, but let's just wrap it to make these issues more apparents
        except Exception as e:
            pmsg(f"LINE PARSE FAILED, line ~{self.base_idx+relative_idx:,}, contents '{line}'")
            pmsg(str(e))

        self.reg_data = bytearray(self.reg_data[: self._reg_offset])
        self.ips = self.ips[:relative_idx]
        self.length = relative_idx

    def _process_line(self, line, relative_idx):
        """
        Process one line of text from a delta reg/mem trace.
        """
        IP = self.trace.arch.IP
        REGISTERS = self.trace.arch.REGISTERS

        delta = line.split(",")
        registers = {}

        # split the state info (registers, memory) into individual items to process
        for item in delta:
            name, value = item.split("=")
            name = name.upper()

            # special compression of IP
            if name == IP:
                ip = int(value, 16)

                try:
                    mapped_ip = self.trace.ip_map[ip]

                except KeyError:
                    mapped_ip = len(self.trace.ip_map)
                    self.trace.ip_map[ip] = mapped_ip

                self.ips[relative_idx] = mapped_ip

            # GPR
            elif name in REGISTERS:
                registers[name] = int(value, 16)

            # handle memory r/w/rw access
            elif name in ["MR", "MW", "MRW"]:

                address, hex_data = value.split(":")
                address = int(address, 16)
                hex_data = bytes(hex_data.strip(), "utf-8")
                data = binascii.unhexlify(hex_data)

                self._process_mem_entry(address, data, name, relative_idx)

            else:
                raise ValueError(
                    f"Invalid line in text trace! '{line}' error on '{name}', (value '{value}')"
                )

        self._pack_registers(registers, relative_idx)

        return True

    def _process_mem_entry(self, address, data, access_type, relative_idx):
        """
        TODO
        """

        byte = 0
        for mapped_address, access_mask, access_data in self._map_mem_access(address, data):

            # read
            if access_type == "MR":

                self._mem_read_info.append((relative_idx, mapped_address, access_mask))
                self.read_data += access_data
                # self._max_read_size = max(self._max_read_size, data_len)

            # write
            elif access_type == "MW":
                self._mem_write_info.append((relative_idx, mapped_address, access_mask))
                self.write_data += access_data
                # print(self._mem_write_info[-1], hexdump(data), "REAL OFFSET", len(self.write_data)-len(data))
                # self._max_write_size = max(self._max_write_size, data_len)

            # read AND write (eg, inc [rax])
            elif access_type == "MRW":

                # read
                self._mem_read_info.append((relative_idx, mapped_address, access_mask))
                self.read_data += access_data
                # self._max_read_size = max(self._max_read_size, data_len)

                # write
                self._mem_write_info.append((relative_idx, mapped_address, access_mask))
                self.write_data += access_data
                # self._max_write_size = max(self._max_write_size, data_len)

            else:
                raise ValueError("Unknown field in trace: '%s=...'" % access_type)

            mv = self.mem_delta[mapped_address]
            mv.mask |= access_mask
            # print(f"ADDRESS: 0x{address:08X} MASK: {access_mask:02X}")

            # snapshot stuff
            bit, byte = 0, 0
            while access_mask:
                if access_mask & 1:
                    # print(bit, byte)
                    mv.value[bit] = access_data[byte]
                    # byte_shift = (bit * 8)
                    # byte_mask = 0xFF << byte_shift
                    # value[0] = (value[0] & ~byte_mask) | (data[byte] << byte_shift)
                    byte += 1
                access_mask >>= 1
                bit += 1

    def _map_mem_access(self, address, data):
        """
        TODO: lol welcome to hell :^)
        """
        output = []
        data_len = len(data)
        access_data = data

        mask_offset = address % 8
        remaining_mask = ((1 << data_len) - 1) << mask_offset
        aligned_address = (address >> 3) << 3
        access_length = min(len(access_data), (8 - mask_offset))

        while remaining_mask:

            aligned_mask = remaining_mask & 0xFF

            mapped_address = self.trace.mem_map.setdefault(aligned_address, len(self.trace.mem_map))

            output.append((mapped_address, aligned_mask, access_data[:access_length]))
            access_data = access_data[access_length:]

            remaining_mask >>= 8
            aligned_address += 8
            access_length = min(len(access_data), 8)

        return output

    def _pack_registers(self, registers, relative_idx):
        """
        Compress a register delta.
        """
        num_regs = len(registers)

        #
        # to help improve the speed of looking up register values in the data
        # blob, we cache pre-computed offsets at finxed intervals throughout
        # the segment.
        #
        # at query time, we can pick the closest cached interval prior to the
        # target idx and only re-compute a fraction of the offsets needed to
        # find the correct offset into the data blob to fetch our reg delta
        #

        if not (relative_idx % REG_OFFSET_CACHE_INTERVAL):
            cache_index = int(relative_idx / REG_OFFSET_CACHE_INTERVAL)
            # print(f"rIDX: {relative_idx:,} CACHE: {cache_index} LEN: {len(self.reg_offsets)}")
            self.reg_offsets[cache_index] = self._reg_offset

        #
        # XXX/TODO: BODGE FOR WHEN PEOPLE DON'T DUMP A FULL REGISTER STATE
        #

        if self.base_idx == 0 and self._reg_offset == 0:
            if num_regs != len(self.arch.REGISTERS):
                for reg_name in self.arch.REGISTERS:
                    if reg_name not in registers:
                        if reg_name == self.arch.IP:
                            continue
                        pmsg(f"MISSING INITIAL REGISTER VALUE FOR {reg_name}")
                        registers[reg_name] = 0
                        num_regs += 1

        mask = self._regs2mask(registers.keys())

        try:
            mapped_mask = self.trace.mask2mapped[mask]
        except KeyError:
            mapped_mask = len(self.trace.mask2mapped)
            self.trace.mask2mapped[mask] = mapped_mask
            self.trace.masks.append(mask)

        self.reg_masks[relative_idx] = mapped_mask

        value_pairs = sorted(
            [(self.arch.REGISTERS.index(name), value) for name, value in registers.items()]
        )
        values = [x[1] for x in value_pairs]
        pack_fmt = "Q" if self.arch.POINTER_SIZE == 8 else "I"
        struct.pack_into(pack_fmt * num_regs, self.reg_data, self._reg_offset, *values)
        self._reg_offset += num_regs * self.arch.POINTER_SIZE

    def _unpack_registers(self, mask, offset):
        """
        Unpack register data from the register buffer.
        """
        reg_names = self._mask2regs(mask)

        # fetch the register data
        num_regs = len(reg_names)
        reg_data = self.reg_data[offset : offset + (num_regs * self.arch.POINTER_SIZE)]

        # unpack the register data
        pack_fmt = "Q" if self.arch.POINTER_SIZE == 8 else "I"
        reg_values = struct.unpack(pack_fmt * num_regs, reg_data)

        # pack all the registers into a dict that will be returned to the user
        registers = dict(zip(reg_names, reg_values))

        # return the completed register delta
        return registers

    # -------------------------------------------------------------------------
    # Util
    # -------------------------------------------------------------------------

    def _regs2mask(self, regs):
        """
        Convert a list of register names to a register mask.
        """
        mask = 0
        for reg in regs:
            reg_bit_index = self.arch.REGISTERS.index(reg)
            mask |= 1 << reg_bit_index
        return mask

    def _mask2regs(self, mask):
        """
        Convert a register mask to a list of register names.
        """
        regs, bit_index = [], 0
        while mask:
            if mask & 1:
                regs.append(self.arch.REGISTERS[bit_index])
            mask >>= 1
            bit_index += 1
        return regs
