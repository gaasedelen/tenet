import bisect
import collections

from tenet.util.log import pmsg

#-----------------------------------------------------------------------------
# analysis.py -- Trace Analysis
#-----------------------------------------------------------------------------
#
#    This file should contain logic to further process, augment, optimize or
#    annotate Tenet traces when a binary analysis framework such as IDA /
#    Binary Ninja is available to a trace reader.
#
#    As of now (v0.2) the only added analysis we do is to try and map
#    ASLR'd trace addresses to executable opened in the database.
#
#    In the future, I imagine this file will be used to indexing events
#    such as function calls, returns, entry and exit to unmapped regions,
#    service pointer annotations, and much more.
#

class TraceAnalysis(object):
    """
    A high level, debugger-like interface for querying Tenet traces.
    """

    def __init__(self, trace, dctx):
        self._dctx = dctx
        self._trace = trace
        self._remapped_regions = []
        self._unmapped_entry_points = []
        self.slide = None
        self._analyze()

    #-------------------------------------------------------------------------
    # Public
    #-------------------------------------------------------------------------

    def rebase_pointer(self, address):
        """
        Return a rebased version of the given address, if one exists.
        """
        for m1, m2 in self._remapped_regions:
            #print(f"m1 start: {m1[0]:08X} address: {address:08X} m1 end: {m1[1]:08X}")
            #print(f"m2 start: {m2[0]:08X} address: {address:08X} m2 end: {m2[1]:08X}")
            if m1[0] <= address <= m1[1]:
               return address + (m2[0] - m1[0])
            if m2[0] <= address <= m2[1]:
               return address - (m2[0] - m1[0])
        return address

    def get_prev_mapped_idx(self, idx):
        """
        Return the previous idx to fall within a mapped code region.
        """
        index = bisect.bisect_right(self._unmapped_entry_points, idx) - 1
        try:
            return self._unmapped_entry_points[index]
        except IndexError:
            return -1

    #-------------------------------------------------------------------------
    # Analysis
    #-------------------------------------------------------------------------

    def _analyze(self):
        """
        Analyze the trace against the binary loaded by the disassembler.
        """
        self._analyze_aslr()
        self._analyze_unmapped()

    def _analyze_aslr(self):
        """
        Analyze trace execution to resolve ASLR mappings against the disassembler.
        """
        dctx, trace = self._dctx, self._trace

        # get *all* of the instruction addresses from disassembler
        instruction_addresses = dctx.get_instruction_addresses()

        #
        # bucket the instruction addresses from the disassembler
        # based on non-aslr'd bits (lower 12 bits, 0xFFF)
        #

        binary_buckets = collections.defaultdict(list)
        for address in instruction_addresses:
            bits = address & 0xFFF
            binary_buckets[bits].append(address)

        # get the set of unique, executed addresses from the trace
        trace_addresses = trace.ip_addrs

        #
        # scan the executed addresses from the trace, and discard
        # any that cannot be bucketed by the non ASLR-d bits that
        # match the open executable
        #

        trace_buckets = collections.defaultdict(list)
        for executed_address in trace_addresses:
            bits = executed_address & 0xFFF
            if bits not in binary_buckets:
                continue
            trace_buckets[bits].append(executed_address)

        #
        # this is where things get a little bit interesting. we compute the
        # distance between addresses in the trace and disassembler buckets
        #
        # the distance that appears most frequently is likely to be the ASLR
        # slide to align the disassembler imagebase and trace addresses
        #

        slide_buckets = collections.defaultdict(list)
        for bits, bin_addresses in binary_buckets.items():
            for executed_address in trace_buckets[bits]:
                for disas_address in bin_addresses:
                    distance = disas_address - executed_address
                    slide_buckets[distance].append(executed_address)

        # basically the executable 'range' of the open binary
        disas_low_address = instruction_addresses[0]
        disas_high_address = instruction_addresses[-1]

        # convert to set for O(1) lookup in following loop
        instruction_addresses = set(instruction_addresses)

        #
        # loop through all the slide buckets, from the most frequent distance
        # (ASLR slide) to least frequent. the goal now is to sanity check the
        # ranges to find one that seems to couple tightly with the disassembler
        #

        for k in sorted(slide_buckets, key=lambda k: len(slide_buckets[k]), reverse=True):
            expected = len(slide_buckets[k])

            #
            # TODO: uh, if it's getting this small, I don't feel comfortable
            # selecting an ASLR slide. the user might be loading a tiny trace
            # with literally 'less than 10' unique instructions (?) that
            # would map to the database
            #

            if expected < 10:
                continue

            hit, seen = 0, 0
            for address in trace_addresses:

                # add the ASLR slide for this bucket to a traced address
                rebased_address = address + k

                # the rebased address seems like it falls within the disassembler ranges
                if disas_low_address <= rebased_address < disas_high_address:
                    seen += 1

                    # but does the address *actually* exist in the disassembler?
                    if rebased_address in instruction_addresses:
                        hit += 1

            #
            # the first *high* hit ratio is almost certainly the correct
            # ASLR, practically speaking this should probably be 1.00, but
            # I lowered it a bit to give a bit of flexibility.
            #
            # NOTE/TODO: a lower 'hit' ratio *could* occur if a lot of
            # undefined instruction addresses in the disassembler get
            # executed in the trace. this could be packed code / malware,
            # in which case we will have to perform more aggressive analysis
            #

            if (hit / seen) > 0.95:
                #print(f"ASLR Slide: {k:08X} Quality: {hit/seen:0.2f} (h {hit} s {seen} e {expected})")
                slide = k
                break

        #
        # if we do not break from the loop, we failed to find an adequate
        # slide, which is very bad.
        #
        # NOTE/TODO: uh what do we do if we fail the ASLR slide?
        #

        else:
            self.slide = None
            return False

        #
        # TODO: err, lol this is all kind of dirty. should probably refactor
        # and clean up this whole 'remapped_regions' stuff.
        #

        m1 = [disas_low_address, disas_high_address]

        if slide < 0:
            m2 = [m1[0] - slide, m1[1] - slide]
        else:
            m2 = [m1[0] + slide, m1[1] + slide]

        self.slide = slide
        self._remapped_regions.append((m1, m2))

        return True

    def _analyze_unmapped(self):
        """
        Analyze trace execution to identify entry/exit to unmapped segments.
        """
        if self.slide is None:
            return

        # alias for readability and speed
        trace, ips = self._trace, self._trace.ip_addrs
        lower_mapped, upper_mapped = self._remapped_regions[0][1]

        #
        # for speed, pull out the 'compressed' ip indexes that matched mapped
        # (known) addresses within the disassembler context
        #

        mapped_ips = set()
        for i, address in enumerate(ips):
            if lower_mapped <= address <= upper_mapped:
                mapped_ips.add(i)

        last_good_idx = 0
        unmapped_entries = []

        # loop through each segment in the trace
        for seg in trace.segments:
            seg_ips = seg.ips
            seg_base = seg.base_idx

            # loop through each executed instruction in this segment
            for relative_idx in range(0, seg.length):
                compressed_ip = seg_ips[relative_idx]

                # the current instruction is in an unmapped region
                if compressed_ip not in mapped_ips:

                    # if we were in a known/mapped region previously, then save it
                    if last_good_idx:
                        unmapped_entries.append(last_good_idx)
                        last_good_idx = 0

                # if we are in a good / mapped region, update our current idx
                else:
                    last_good_idx = seg_base + relative_idx

        #print(f" - Unmapped Entry Points: {len(unmapped_entries)}")
        self._unmapped_entry_points = unmapped_entries
