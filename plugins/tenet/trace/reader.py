import bisect
import struct
import logging

#-----------------------------------------------------------------------------
# reader.py -- Trace Reader
#-----------------------------------------------------------------------------
#
#    NOTE/PREFACE: If you have not already, please read through the overview
#    comment at the start of the TraceFile (file.py) code. This file (the
#    Trace Reader) builds directly ontop of trace files.
#
#    --------------
#
#    This file contains the 'trace reader' implementation for the plugin. It
#    is responsible for the navigating a loaded trace file, providing 'high
#    level' APIs one might expect to 'efficiently' query a program for
#    registers or memory at any timestamp of execution.
#
#    Please be mindful that like the TraceFile implementation, TraceReader
#    should be re-written entirely in a native language. Under the hood, it's
#    not exactly pretty. It was written to make the plugin simple to install
#    and experience as a prototype. It is not equipped to adequately scale to
#    real world targets.
#
#    The most important takeaway from this file should be interface / API
#    that it exposes to the plugin. A performant, native TraceReader that
#    exposes the same API would be enough to scale the plugin's ability to
#    navigate traces that span tens of billions (... maybe even hundreds of
#    billions) of instructions.
#

from tenet.types import BreakpointType
from tenet.util.log import pmsg
from tenet.util.misc import register_callback, notify_callback
from tenet.trace.file import TraceFile
from tenet.trace.types import TraceMemory
from tenet.trace.analysis import TraceAnalysis

logger = logging.getLogger("Tenet.Trace.Reader")

class TraceDelta(object):
    """
    Trace Delta
    """

    def __init__(self, registers, mem_read, mem_write):
        self.registers = registers
        self.mem_reads = mem_read
        self.mem_writes = mem_write

class TraceReader(object):
    """
    A high level, debugger-like interface for querying Tenet traces.
    """

    def __init__(self, filepath, architecture, dctx=None):
        self.idx = 0
        self.dctx = dctx
        self.arch = architecture

        # load the given trace file from disk
        self.trace = TraceFile(filepath, architecture)
        self.analysis = TraceAnalysis(self.trace, dctx)

        self._idx_cached_registers = -1
        self._cached_registers = {}

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._idx_changed_callbacks = []

    #-------------------------------------------------------------------------
    # Trace Properties
    #-------------------------------------------------------------------------

    @property
    def ip(self):
        """
        Return the current instruction pointer.
        """
        return self.get_register(self.arch.IP)

    @property
    def rebased_ip(self):
        """
        Return a rebased version of the current instruction pointer (if available).
        """
        return self.analysis.rebase_pointer(self.ip)

    @property
    def sp(self):
        """
        Return the current stack pointer.
        """
        return self.get_register(self.arch.SP)

    @property
    def registers(self):
        """
        Return the current registers.
        """
        return self.get_registers()

    @property
    def segment(self):
        """
        Return the current trace segment.
        """
        return self.trace.get_segment(self.idx)

    @property
    def delta(self):
        """
        Return the state delta since the previous timestamp.
        """
        read_set, write_set = set(), set()

        for address, data in self.trace.get_read_delta(self.idx):
            read_set |= {address + i for i in range(len(data))}

        for address, data in self.trace.get_write_delta(self.idx):
            write_set |= {address + i for i in range(len(data))}

        regs = self.trace.get_reg_delta(self.idx)

        return TraceDelta(regs, read_set, write_set)

    #-------------------------------------------------------------------------
    # Trace Navigation
    #-------------------------------------------------------------------------

    def seek(self, idx):
        """
        Seek the trace to the given timestamp.
        """

        # clamp the index if it goes past the end of the trace
        if idx >= self.trace.length:
            idx = self.trace.length - 1
        elif idx < 0:
            idx = 0

        # save the new position
        self.idx = idx
        self.get_registers()
        self._notify_idx_changed()

    def seek_percent(self, percent):
        """
        Seek to an approximate percentage into the trace.
        """
        target_idx = int(self.trace.length * (percent / 100))
        self.seek(target_idx)

    def seek_to_first(self, address, access_type, length=1):
        """
        Seek to the first instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        return self.seek_to_next(address, access_type, length, 0)

    def seek_to_final(self, address, access_type, length=1):
        """
        Seek to the final instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        return self.seek_to_prev(address, access_type, length, self.trace.length-1)

    def seek_to_next(self, address, access_type, length=1, start_idx=None):
        """
        Seek to the next instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        if start_idx is None:
            start_idx = self.idx + 1

        if access_type == BreakpointType.EXEC:

            assert length == 1
            idx = self.find_next_execution(address, start_idx)

        elif access_type == BreakpointType.READ:

            if length == 1:
                idx = self.find_next_read(address, start_idx)
            else:
                idx = self.find_next_region_read(address, length, start_idx)

        elif access_type == BreakpointType.WRITE:

            if length == 1:
                idx = self.find_next_write(address, start_idx)
            else:
                idx = self.find_next_region_write(address, length, start_idx)

        elif access_type == BreakpointType.ACCESS:

            if length == 1:
                idx = self.find_next_access(address, start_idx)
            else:
                idx = self.find_next_region_access(address, length, start_idx)

        else:
            raise NotImplementedError

        if idx == -1:
            return False

        self.seek(idx)
        return True

    def seek_to_prev(self, address, access_type, length=1, start_idx=None):
        """
        Seek to the previous instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        if start_idx is None:
            start_idx = self.idx - 1

        if access_type == BreakpointType.EXEC:

            assert length == 1
            idx = self.find_prev_execution(address, start_idx)

        elif access_type == BreakpointType.READ:

            if length == 1:
                idx = self.find_prev_read(address, start_idx)
            else:
                idx = self.find_prev_region_read(address, length, start_idx)

        elif access_type == BreakpointType.WRITE:

            if length == 1:
                idx = self.find_prev_write(address, start_idx)
            else:
                idx = self.find_prev_region_write(address, length, start_idx)

        elif access_type == BreakpointType.ACCESS:

            if length == 1:
                idx = self.find_prev_access(address, start_idx)
            else:
                idx = self.find_prev_region_access(address, length, start_idx)

        else:
            raise NotImplementedError

        if idx == -1:
            return False

        self.seek(idx)
        return True

    def step_forward(self, n=1, step_over=False):
        """
        Step the trace forward by n steps.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """
        if not step_over:
            self.seek(self.idx + n)
        else:
            self._step_over_forward(n)

    def step_backward(self, n=1, step_over=False):
        """
        Step the trace backwards.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """
        if not step_over:
            self.seek(self.idx - n)
        else:
            self._step_over_backward(n)

    def _step_over_forward(self, n):
        """
        Step the trace forward over n instructions / calls.
        """
        address = self.get_ip(self.idx)
        bin_address = self.analysis.rebase_pointer(address)

        #
        # get the address for the linear instruction address after the
        # current instruction
        #

        bin_next_address = self.dctx.get_next_insn(bin_address)
        if bin_next_address == -1:
            self.seek(self.idx + 1)
            return

        trace_next_address = self.analysis.rebase_pointer(bin_next_address)

        #
        # find the next time the instruction after this instruction is
        # executed in the trace
        #

        next_idx = self.find_next_execution(trace_next_address, self.idx)

        #
        # the instruction after the call does not appear in the trace,
        # so just fall-back to 'step into' behavior
        #

        if next_idx == -1:
            self.seek(self.idx + 1)
            return

        self.seek(next_idx)

    def _step_over_backward(self, n):
        """
        Step the trace backward over n instructions / calls.
        """
        address = self.get_ip(self.idx)
        bin_address = self.analysis.rebase_pointer(address)

        bin_prev_address = self.dctx.get_prev_insn(bin_address)

        #
        # could not get the address of the instruction prior to the current
        # one which means we will not be able to decode it / and really are
        # not sure what/where the user would be stepping backwards to...
        #
        # TODO: it's possible to handle this case, but requires a more
        # performant backend than the python prototype that powers this
        #

        if bin_prev_address == -1:
            self.seek(self.idx - 1)
            return

        #
        # special handling for when the prior instruction appears to be a call
        # instruction, this is perhaps the most important 'step over' scenario
        # and also pretty tricky to handle...
        #

        if self.dctx.is_call_insn(bin_prev_address):

            # get the previous stack pointer address
            sp = self.get_register(self.arch.SP, self.idx - 1)

            # attempt to read a pointer off the stack (possibly a ret address)
            try:
                maybe_ret_address = self.read_pointer(sp, self.idx)
            except ValueError:
                print("TODO: stack read failed")
                maybe_ret_address = None

            #
            # if the address off the stack matches the current address,
            # we can assume that we just returned from somewhere.
            #
            # 99% of the time, this will have been from the call insn at
            # prev_address, so let's just assume that is the case and
            # 'reverse step over' onto that.
            #
            # NOTE: technically, we can put in more checks and stuff to
            # try and ensure this is 'correct' but, step over and reverse
            # step over are kind of an imperfect science as is...
            #

            if maybe_ret_address != address:
                self.seek(self.idx - 1)
                return

        trace_prev_address = self.analysis.rebase_pointer(bin_prev_address)

        prev_idx = self.find_prev_execution(trace_prev_address, self.idx)
        if prev_idx == -1:
            self.seek(self.idx - 1)
            return

        self.seek(prev_idx)

    #-------------------------------------------------------------------------
    # Timestamp API
    #-------------------------------------------------------------------------

    #
    # in this section, you will find references to 'resolution'. this is a
    # knob that the trace reader uses to fetch 'approximate' results from
    # the underlying trace.
    #
    # for example, a resolution of 1 is the *most* granular request, where
    # one can ask the reader to inspect each step of the trace to see if it
    # matches a query (eg, 'when was this instruction address executed')
    #
    # in contrast, a resolution of 10_000 means that any single hit within
    # a resolution 'window' is adequate, and the reader should skip to the
    # next window to continue fufilling the query.
    #
    # given a 10 million instruction trace, and a 30px by 1000px image
    # buffer to viualize said trace... there is very little reason to fetch
    # 100_000 unique timestamps that all fall within one vertical pixel of
    # the rendered visualization.
    #
    # instead, we can search the trace in arbitrary resolution 'windows' of
    # roughly 1px (pixel resolution can be calculated based on the length of
    # the trace execution vs the length of the viz in pixels) and fetch results
    # that will suffice for visual summarization of trace execution
    #

    def get_executions(self, address, resolution=1):
        """
        Return a list of timestamps (idx) that executed the given address.
        """
        return self.get_executions_between(address, 0, self.trace.length, resolution)

    def get_executions_between(self, address, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps (idx) that executed the given address, in the given slice.
        """
        assert 0 <= start_idx <= end_idx, f"0 <= {start_idx:,} <= {end_idx:,}"
        assert resolution > 0

        resolution = max(1, resolution)
        logger.debug(f"Fetching executions from {start_idx:,} --> {end_idx:,} (res {resolution:0.2f}, normalized {resolution:0.2f}) for address 0x{address:08X}")

        try:
            mapped_address = self.trace.get_mapped_ip(address)
        except ValueError:
            return []

        output = []
        idx = max(0, start_idx)
        end_idx = min(end_idx, self.trace.length)

        while idx < end_idx:

            # fetch a segment to search forward through
            seg = self.trace.get_segment(idx)
            seg_base = seg.base_idx

            # clamp the segment end if it extends past our segment
            seg_end = min(seg_base + seg.length, end_idx)
            logger.debug(f"Searching seg #{seg.id}, {seg_base:,} --> {seg_end:,}")

            # snip the segment to start from the given global idx
            relative_idx = idx - seg_base
            seg_ips = seg.ips[relative_idx:]

            while idx < seg_end:

                try:
                    idx_offset = seg_ips.index(mapped_address)
                except ValueError:
                    idx = seg_end + 1
                    break

                # we got a hit within the resolution window, save it
                current_idx = idx + idx_offset
                output.append(current_idx)

                # now skip to the next resolution window
                current_resolution_index = current_idx / resolution
                next_resolution_index = current_resolution_index + 1
                next_resolution_target = next_resolution_index * resolution
                idx = round(next_resolution_target)

                #print(f"GOT HIT @ {current_idx:,}, skipping to {idx:,} (y = {current_idx/resolution})")
                #print(f" - Current resolution index {current_resolution_index}")
                #print(f" - Next resolution index {next_resolution_index}")
                #print(f" - Next resolution target {next_resolution_target:,}")

                seg_ips = seg.ips[idx-seg_base:]

        logger.debug(f"Returning hits {output}")
        return output

    def get_memory_accesses(self, address, resolution=1):
        """
        Return a tuple of lists (read, write) containing timestamps that access a given memory address.
        """
        return self.get_memory_accesses_between(address, 0, self.trace.length, resolution)


    def get_memory_reads_between(self, address, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps that read from a given memory address in the given slice.
        """
        reads, _ = self.get_memory_accesses_between(address, start_idx, end_idx, resolution, BreakpointType.READ)
        return reads

    def get_memory_writes_between(self, address, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps that write to a given memory address in the given slice.
        """
        _, writes = self.get_memory_accesses_between(address, start_idx, end_idx, resolution, BreakpointType.WRITE)
        return writes

    def get_memory_accesses_between(self, address, start_idx, end_idx, resolution=1, access_type=BreakpointType.ACCESS):
        """
        Return a tuple of lists (read, write) containing timestamps that access a given memory address in the given slice.
        """
        assert resolution > 0
        resolution = max(1, resolution)

        logger.debug(f"MEMORY ACCESSES @ 0x{address:08X} // {start_idx:,} --> {end_idx:,} (rez {resolution:0.2f})")

        mapped_address = self.trace.get_mapped_address(address)
        if mapped_address == -1:
            return ([], [])

        reads, writes = [], []
        access_mask = self.trace.get_aligned_address_mask(address, 1)

        # clamp the search incase the given params are a bit wonky
        idx = max(0, start_idx)
        end_idx = min(end_idx, self.trace.length)
        assert idx < end_idx

        next_resolution = [idx, idx]

        # search through the trace
        while idx < end_idx:

            # fetch a segment to search forward through
            seg = self.trace.get_segment(idx)
            seg_base = seg.base_idx

            # clamp the segment end if it extends past our segment
            seg_end = min(seg_base + seg.length, end_idx)
            logger.debug(f"seg #{seg.id}, {seg.base_idx:,} --> {seg.base_idx+seg.length:,} -- IDX PTR {idx:,}")

            mem_sets = []

            if access_type & BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks, reads))
            if access_type & BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks, writes))

            for i, mem_type in enumerate(mem_sets):
                idxs, addrs, masks, output = mem_type

                cumulative_index = 0
                current_target = next_resolution[i]

                while current_target < seg_end:

                    try:
                        index = addrs.index(mapped_address)
                    except ValueError:
                        break

                    cumulative_index += index
                    current_idx = seg_base + idxs[index]

                    #
                    # there was a hit to the mapped address, which is aligned
                    # to the arch pointer size... check if the requested addr
                    # matches the access mask for this mem access entry
                    #

                    if not (masks[cumulative_index] & access_mask):
                        addrs = addrs[index+1:]
                        idxs = idxs[index+1:]
                        cumulative_index += 1
                        continue

                    #print(f"FOUND ACCESS TO {self.trace.mem_addrs[mapped_address]:08X} (mask {masks[cumulative_index]:02X}), IDX {current_idx:,}")

                    # we got a hit within the resolution window, save it
                    output.append(current_idx)

                    # now skip to the next resolution window
                    current_resolution_index = current_idx / resolution
                    next_resolution_index = current_resolution_index + 1
                    next_resolution_target = next_resolution_index * resolution
                    current_target = round(next_resolution_target)
                    #print(f"NEXT TARGET: {current_target:,}")

                    # now skip to the next resolution window
                    skip_index = bisect.bisect_left(idxs, current_target - seg_base)
                    if skip_index == len(idxs):
                        break

                    addrs = addrs[skip_index:]
                    idxs = idxs[skip_index:]

                    cumulative_index += (skip_index - index)

                next_resolution[i] = current_target

            idx = seg_end + 1

        return (reads, writes)

    def get_memory_region_reads(self, address, length, resolution=1):
        """
        Return a list of timestamps that read from the given memory region.
        """
        reads, _ = self.get_memory_region_accesses_between(address, length, 0, self.trace.length, resolution, BreakpointType.READ)
        return reads

    def get_memory_region_reads_between(self, address, length, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps that read from the given memory region in the given time slice.
        """
        reads, _ = self.get_memory_region_accesses_between(address, length, start_idx, end_idx, resolution, BreakpointType.READ)
        return reads

    def get_memory_region_writes(self, address, length, resolution=1):
        """
        Return a list of timestamps that write to the given memory region.
        """
        _, writes = self.get_memory_region_accesses_between(address, length, 0, self.trace.length, resolution, BreakpointType.WRITE)
        return writes

    def get_memory_region_writes_between(self, address, length, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps that write to the given memory region in the given time slice.
        """
        _, writes = self.get_memory_region_accesses_between(address, length, start_idx, end_idx, resolution, BreakpointType.WRITE)
        return writes

    def get_memory_region_accesses(self, address, length, resolution=1):
        """
        Return a tuple of (read, write) containing timestamps that access the given memory region.
        """
        return self.get_memory_region_accesses_between(address, length, 0, self.trace.length, resolution)

    def get_memory_region_accesses_between(self, address, length, start_idx, end_idx, resolution=1, access_type=BreakpointType.ACCESS):
        """
        Return a tuple of (read, write) containing timestamps that access the given memory region in the given time slice.
        """
        assert resolution > 0
        resolution = max(1, resolution)

        logger.debug(f"REGION ACCESS BETWEEN @ 0x{address:08X} + {length} //  {start_idx:,} --> {end_idx:,} (rez {resolution:0.2f})")

        reads, writes = [], []
        targets = self._region_to_targets(address, length)

        # clamp the search incase the given params are a bit wonky
        idx = max(0, start_idx)
        end_idx = min(end_idx, self.trace.length)
        assert idx < end_idx

        starting_resolution_index = int(idx / resolution)
        next_resolution = [starting_resolution_index, starting_resolution_index]

        while idx < end_idx:

            # fetch a segment to search forward through
            seg = self.trace.get_segment(idx)
            seg_base = seg.base_idx

            # clamp the segment end if it extends past our segment
            seg_end = min(seg_base + seg.length, end_idx)

            #print("-"*50)
            #print(f"seg #{seg.id}, {seg.base_idx:,} --> {seg.base_idx+seg.length:,} -- IDX PTR {idx:,}")

            mem_sets = []

            if access_type & BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks, reads))
            if access_type & BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks, writes))

            for i, mem_type in enumerate(mem_sets):
                idxs, addrs, masks, output = mem_type
                hits, first_hit = {}, len(addrs)
                resolution_index = next_resolution[i]

                #
                # check each 'aligned address' (actually an id #) within the given region to see
                # if it appears anywhere in the current segment's memory set
                #

                for address_id, address_mask in targets:

                    #
                    # if there is a memory access to the region, we will
                    # break here and begin processing it
                    #

                    try:
                        index = addrs.index(address_id)
                        first_hit = min(index, first_hit)

                    #
                    # no hits for any bytes within this aligned address,
                    # try the next aligned address within the region
                    #

                    except ValueError:
                        continue

                    hits[address_id] = address_mask

                #
                # if we hit this, it means no memory accesses of this
                # type (eg, reads) occured to the region of memory in
                # this segment.
                #
                # there's nothing else to process for this memory set,
                # so just break and move onto the next set (eg, writes)
                #

                if not hits:
                    continue

                for index in range(first_hit, len(addrs)):
                    address_id = addrs[index]
                    target_mask = hits.get(address_id, None)

                    if not target_mask:
                        continue

                    #print("CLOSE! DOES MASK MATCH?")
                    #print(f"  TARGET: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {target_mask:02X}")
                    #print(f" CURRENT: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {masks[index]:02X}")
                    #print(f"  RESULT: {target_mask & masks[index]:02X}")

                    #
                    # got the first hit for this set.. great! save it and
                    # break to search the next memory set
                    #

                    if target_mask & masks[index]:
                        hit_idx = seg_base + idxs[index]
                        hit_resolution_index = int(hit_idx / resolution)
                        if hit_resolution_index < resolution_index:
                            continue
                        output.append(hit_idx)
                        resolution_index += 1

                next_resolution[i] = resolution_index

            idx = seg_end + 1

        return (reads, writes)

    def get_prev_ips(self, n, step_over=False):
        """
        Return the previous n executed instruction addresses.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """

        # single step, return (reverse) canonical trace sequence
        if not step_over:
            start = max(-1, self.idx - 1)
            end = max(-1, start - n)
            return [self.get_ip(idx) for idx in range(start, end, -1)]

        output = []
        dctx, idx = self.dctx, self.idx
        trace_address = self.get_ip(idx)
        bin_address = self.analysis.rebase_pointer(trace_address)

        # (reverse) step over any call instructions
        while len(output) < n and idx > 0:

            bin_prev_address = dctx.get_prev_insn(bin_address)
            did_step_over = False

            # call instruction
            if bin_prev_address != -1 and dctx.is_call_insn(bin_prev_address):

                # get the previous stack pointer address
                sp = self.get_register(self.arch.SP, idx - 1)

                # attempt to read a pointer off the stack (the old ret address)
                try:
                    maybe_ret_address = self.read_pointer(sp, idx)
                except ValueError:
                    print("TODO: stack read failed")
                    maybe_ret_address = None

                #
                # if the address off the stack matches the current address,
                # we can assume that we just returned from somewhere.
                #
                # 99% of the time, this will have been from the call insn at
                # bin_prev_address, so let's just assume that is the case and
                # 'reverse step over' onto that.
                #
                # NOTE: technically, we can put in more checks and stuff to
                # try and ensure this is 'correct' but, step over and reverse
                # step over are kind of an imperfect science as is...
                #

                if maybe_ret_address == trace_address:
                    trace_prev_address = self.analysis.rebase_pointer(bin_prev_address)
                    prev_idx = self.find_prev_execution(trace_prev_address, idx)
                    did_step_over = bool(prev_idx != -1)

            #
            # if it doesn't look like we just returned from a call, we
            # will just fall back to a linear, step-over backwards.
            #
            # this code is intended to cover the case where a conditional
            # happens to jump onto an instruction immediately after a call,
            # which causes the above 'stack inspection' to fail
            #

            if not did_step_over:
                trace_prev_address = self.analysis.rebase_pointer(bin_prev_address)
                prev_idx = self.find_prev_execution(trace_prev_address, idx)

            #
            # uh, wow okay we're pretty lost and have no idea if there is
            # actually something that can be reverse step-over'd. just revert
            # to performing a simple single-step backwards
            #

            if prev_idx == -1:
                prev_idx = idx - 1

            trace_prev_address = self.get_ip(prev_idx)

            # no address was returned, so the end of trace was reached
            if trace_prev_address == -1:
                break

            # save the results and continue looping
            output.append(trace_prev_address)
            trace_address = trace_prev_address
            bin_address = self.analysis.rebase_pointer(trace_address)
            idx = prev_idx

        # return the list of addresses to be 'executed' next
        return output

    def get_next_ips(self, n, step_over=False):
        """
        Return the next N executed instruction addresses.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """

        # single step, return canonical trace sequence
        if not step_over:
            start = min(self.idx + 1, self.trace.length)
            end = min(start + n, self.trace.length)
            return [self.get_ip(idx) for idx in range(start, end)]

        output = []
        dctx, idx = self.dctx, self.idx
        trace_address = self.get_ip(idx)
        bin_address = self.analysis.rebase_pointer(trace_address)

        # step over any call instructions
        while len(output) < n and idx < (self.trace.length - 1):

            #
            # get the address for the instruction address after the
            # current (call) instruction
            #

            bin_next_address = dctx.get_next_insn(bin_address)

            #
            # find the next time the instruction after this instruction is
            # executed in the trace
            #

            if bin_next_address != -1:
                trace_next_address = self.analysis.rebase_pointer(bin_next_address)
                next_idx = self.find_next_execution(trace_next_address, idx)
            else:
                next_idx = -1

            #
            # the instruction after the call does not appear in the trace,
            # so just fall-back to 'step into' behavior
            #

            if next_idx == -1:
                next_idx = idx + 1

            #
            # get the next address to be executed by the trace, according to
            # our stepping behavior
            #

            trace_next_address = self.get_ip(next_idx)

            # no address was returned, so the end of trace was reached
            if trace_next_address == -1:
                break

            # save the results and continue looping
            output.append(trace_next_address)
            bin_address = self.analysis.rebase_pointer(trace_next_address)
            idx = next_idx

        # return the list of addresses to be 'executed' next
        return output

    def find_next_execution(self, address, idx=None):
        """
        Return the next timestamp to execute the given address.
        """
        if idx is None:
            idx = self.idx + 1

        try:
            mapped_ip = self.trace.get_mapped_ip(address)
        except ValueError:
            return -1

        while idx < self.trace.length:
            seg = self.trace.get_segment(idx)

            # slice out and reverse the ips to search through
            relative_idx = idx - seg.base_idx
            ips = seg.ips[relative_idx:]

            # query for the next instance of our target ip
            try:
                next_idx = ips.index(mapped_ip)
                return idx + next_idx

            # no luck, move backwards to the next segment
            except ValueError:
                idx = seg.base_idx + seg.length

        # fail, reached start of trace
        return -1

    def find_prev_execution(self, address, idx=None):
        """
        Return the previous timestamp to execute the given address.
        """
        if idx is None:
            idx = self.idx - 1

        try:
            mapped_ip = self.trace.get_mapped_ip(address)
        except ValueError:
            return -1

        while idx > -1:
            seg = self.trace.get_segment(idx)

            # slice out and reverse the ips to search through
            relative_idx = idx - seg.base_idx
            ips = seg.ips[:relative_idx][::-1]

            # query for the next instance of our target ip
            try:
                prev_idx = ips.index(mapped_ip)
                return idx - prev_idx - 1

            # no luck, move backwards to the next segment
            except ValueError:
                idx = seg.base_idx - 1

        # fail, reached start of trace
        return -1

    def find_next_read(self, address, idx=None):
        """
        Return the next timestamp to read the given memory address.
        """
        return self._find_next_mem_op(address, BreakpointType.READ, idx)

    def find_prev_read(self, address, idx=None):
        """
        Return the previous timestamp to read the given memory address.
        """
        return self._find_prev_mem_op(address, BreakpointType.READ, idx)

    def find_next_write(self, address, idx=None):
        """
        Return the next timestamp to write to the given memory address.
        """
        return self._find_next_mem_op(address, BreakpointType.WRITE, idx)

    def find_prev_write(self, address, idx=None):
        """
        Return the previous timestamp to write to the given memory address.
        """
        return self._find_prev_mem_op(address, BreakpointType.WRITE, idx)

    def find_next_access(self, address, idx=None):
        """
        Return the next timestamp to access the given memory address.
        """
        return self._find_next_mem_op(address, BreakpointType.ACCESS, idx)

    def find_prev_access(self, address, idx=None):
        """
        Return the previous timestamp to access the given memory address.
        """
        return self._find_prev_mem_op(address, BreakpointType.ACCESS, idx)

    def _find_next_mem_op(self, address, bp_type, idx=None):
        """
        Return the next timestamp to read the given memory address.
        """
        if idx is None:
            idx = self.idx + 1

        mapped_address = self.trace.get_mapped_address(address)
        if mapped_address == -1:
            return -1

        access_mask = self.trace.get_aligned_address_mask(address, 1)
        starting_segment = self.trace.get_segment(idx)

        accesses, mem_sets = [], []

        for seg_id in range(starting_segment.id, len(self.trace.segments)):
            seg = self.trace.segments[seg_id]
            seg_base = seg.base_idx

            mem_sets.clear()

            if bp_type == BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))

            if bp_type == BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            if bp_type == BreakpointType.ACCESS:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            # loop through the read / write memory sets for this segment
            for idxs, addrs, masks in mem_sets:
                search_addrs = addrs

                normal_index = 0
                while search_addrs:

                    try:
                        index = search_addrs.index(mapped_address)
                        normal_index += index
                    except ValueError:
                        break

                    if masks[normal_index] & access_mask:

                        assert addrs[normal_index] == mapped_address
                        assert masks[normal_index] & access_mask

                        # ensure that the memory access occurs on or after the starting idx
                        hit_idx = seg_base + idxs[normal_index]
                        if idx <= hit_idx:
                            accesses.append(seg_base + idxs[normal_index])
                            break

                    # the hit was no good.. 'step' past it and keep searching
                    search_addrs = search_addrs[index+1:]
                    normal_index += 1

            #
            # if there has been a read or a write, select the one that is
            # 'closest' to our current idx. there should only be, at most,
            # two elements in this list...
            #

            if accesses:
                return min(accesses, key=lambda x:abs(x-idx))

        # fail, reached end of trace
        return -1

    def _find_prev_mem_op(self, address, bp_type, idx=None):
        """
        Return the previous timestamp to access the given memory address.
        """
        if idx is None:
            idx = self.idx - 1

        mapped_address = self.trace.get_mapped_address(address)
        if mapped_address == -1:
            return -1

        access_mask = self.trace.get_aligned_address_mask(address, 1)
        starting_segment = self.trace.get_segment(idx)

        accesses, mem_sets = [], []

        for seg_id in range(starting_segment.id, -1, -1):
            seg = self.trace.segments[seg_id]
            seg_base = seg.base_idx

            mem_sets.clear()

            if bp_type == BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))

            if bp_type == BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            if bp_type == BreakpointType.ACCESS:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            # loop through the read / write memory sets for this segment
            for idxs, addrs, masks in mem_sets:
                search_addrs = addrs[::-1]

                normal_index = len(search_addrs) - 1
                while search_addrs:

                    try:
                        reverse_index = search_addrs.index(mapped_address)
                        normal_index -= reverse_index
                    except ValueError:
                        break

                    if masks[normal_index] & access_mask:

                        assert addrs[normal_index] == mapped_address
                        assert masks[normal_index] & access_mask

                        # ensure that the memory access occurs on or before the starting idx
                        hit_idx = seg_base + idxs[normal_index]
                        if hit_idx <= idx:
                            accesses.append(seg_base + idxs[normal_index])
                            break

                    # the hit was no good.. 'step' past it and keep searching
                    search_addrs = search_addrs[reverse_index+1:]
                    normal_index -= 1

            if accesses:
                return min(accesses, key=lambda x:abs(x-idx))

        # fail, reached start of trace
        return -1

    def find_next_region_read(self, address, length, idx=None):
        """
        Return the next timestamp to read from given memory region.
        """
        return self._find_next_region_access(address, length, idx, BreakpointType.READ)

    def find_next_region_write(self, address, length, idx=None):
        """
        Return the next timestamp to write to the given memory region.
        """
        return self._find_next_region_access(address, length, idx, BreakpointType.WRITE)

    def find_next_region_access(self, address, length, idx=None):
        """
        Return the next timestamp to access (r/w) the given memory region.
        """
        return self._find_next_region_access(address, length, idx, BreakpointType.ACCESS)

    def _find_next_region_access(self, address, length, idx=None, access_type=BreakpointType.ACCESS):
        """
        Return the next timestamp to access the given memory region.
        """
        if idx is None:
            idx = self.idx + 1

        logger.debug(f"FIND NEXT REGION ACCESS FOR 0x{address:08X} -> 0x{address+length:08X} STARTING AT IDX {idx:,}")

        accesses, mem_sets = [], []
        targets = self._region_to_targets(address, length)
        starting_segment = self.trace.get_segment(idx)

        for seg_id in range(starting_segment.id, len(self.trace.segments)):

            # fetch a segment to search forward through
            seg = self.trace.segments[seg_id]
            seg_base = seg.base_idx

            mem_sets = []

            if access_type & BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))
            if access_type & BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            # loop through the read / write memory sets for this segment
            for idxs, addrs, masks in mem_sets:
                hits, first_hit = {}, len(addrs)

                #
                # check each 'aligned address' (actually an id #) within
                # the given region to see if it appears anywhere in the
                # current segment's memory set
                #

                for address_id, address_mask in targets:

                    #
                    # if there is a memory access to the region, we will
                    # break here and begin processing it
                    #

                    try:
                        index = addrs.index(address_id)
                        first_hit = min(index, first_hit)
                        #print(f"HIT ON 0x{self.trace.mem_addrs[address_id]:08X} @ IDX {seg_base+idxs[index]}")

                    #
                    # no hits for any bytes within this aligned address,
                    # try the next aligned address within the region
                    #

                    except ValueError:
                        continue

                    hits[address_id] = address_mask

                #
                # if we hit this, it means no memory accesses of this
                # type (eg, reads) occured to the region of memory in
                # this segment.
                #
                # there's nothing else to process for this memory set,
                # so just break and move onto the next set (eg, writes)
                #

                if not hits:
                    continue

                for index in range(first_hit, len(addrs)):
                    address_id = addrs[index]
                    target_mask = hits.get(address_id, None)

                    if not target_mask:
                        continue

                    #print("CLOSE! DOES MASK MATCH?")
                    #print(f"  TARGET: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {target_mask:02X}")
                    #print(f" CURRENT: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {masks[index]:02X}")
                    #print(f"  RESULT: {target_mask & masks[index]:02X}")

                    #
                    # got the first hit for this set.. great! save it and
                    # break to search the next memory set
                    #

                    if target_mask & masks[index]:
                        hit_idx = seg_base + idxs[index]
                        if hit_idx < idx:
                            continue
                        accesses.append(hit_idx)
                        #print(f"FOUND HIT AT IDX {hit_idx}")
                        break

            #
            # if there has been a read or a write, select the one that is
            # 'closest' to our current idx. there should only be, at most,
            # two elements in this list...
            #

            if accesses:
                #print("ALL ACCESSES", accesses)
                return min(accesses, key=lambda x:abs(x-idx))

        # fail, reached end of trace
        return -1

    def find_prev_region_read(self, address, length, idx=None):
        """
        Return the previous timestamp to read from the given memory region.
        """
        return self.find_prev_region_access(address, length, idx, BreakpointType.READ)

    def find_prev_region_write(self, address, length, idx=None):
        """
        Return the previous timestamp to write to the given memory region.
        """
        return self.find_prev_region_access(address, length, idx, BreakpointType.WRITE)

    def find_prev_region_access(self, address, length, idx=None, access_type=BreakpointType.ACCESS):
        """
        Return the previous timestamp to access the given memory region.
        """
        if idx is None:
            idx = self.idx - 1

        logger.debug(f"FIND PREV REGION ACCESS FOR 0x{address:08X} -> 0x{address+length:08X} STARTING AT IDX {idx:,}")

        accesses, mem_sets = [], []
        targets = self._region_to_targets(address, length)
        starting_segment = self.trace.get_segment(idx)

        for seg_id in range(starting_segment.id, -1, -1):

            # fetch a segment to search backwards through
            seg = self.trace.segments[seg_id]
            seg_base = seg.base_idx

            mem_sets = []

            if access_type & BreakpointType.READ:
                mem_sets.append((seg.read_idxs, seg.read_addrs, seg.read_masks))
            if access_type & BreakpointType.WRITE:
                mem_sets.append((seg.write_idxs, seg.write_addrs, seg.write_masks))

            # loop through the read / write memory sets for this segment
            for idxs, addrs, masks in mem_sets:
                reverse_addrs = addrs[::-1]
                hits, first_hit = {}, len(reverse_addrs)

                #
                # check each 'aligned address' (actually an id #) within
                # the given region to see if it appears anywhere in the
                # current segment's memory set
                #

                for address_id, address_mask in targets:

                    #
                    # if there is a memory access to the region, we will
                    # break here and begin processing it
                    #

                    try:
                        index = reverse_addrs.index(address_id)
                        first_hit = min(index, first_hit)
                        #print(f"HIT ON 0x{self.trace.mem_addrs[address_id]:08X} @ IDX {seg_base+idxs[index]}")

                    #
                    # no hits for any bytes within this aligned address,
                    # try the next aligned address within the region
                    #

                    except ValueError:
                        continue

                    #
                    # ignore hits that are less than the starting timestamp
                    # because we are searching FORWARD, deeper into time
                    #

                    #if seg_base + idxs[index] <= idx:
                    #    print(f"TOSSING {seg_base+idxs[index]:,}, TOO CLOSE!")
                    #    continue

                    hits[address_id] = address_mask

                #
                # if we hit this, it means no memory accesses of this
                # type (eg, reads) occured to the region of memory in
                # this segment.
                #
                # there's nothing else to process for this memory set,
                # so just break and move onto the next set (eg, writes)
                #

                if not hits:
                    continue

                num_addrs = len(reverse_addrs)
                for reverse_index in range(first_hit, num_addrs):
                    address_id = reverse_addrs[reverse_index]
                    target_mask = hits.get(address_id, None)

                    if not target_mask:
                        continue

                    #print("CLOSE! DOES MASK MATCH?")
                    #print(f"  TARGET: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {target_mask:02X}")
                    #print(f" CURRENT: 0x{self.trace.mem_addrs[address_id]:08X} MASK: {masks[index]:02X}")
                    #print(f"  RESULT: {target_mask & masks[index]:02X}")

                    normal_index = num_addrs - reverse_index - 1

                    #
                    # got the first hit for this set.. great! save it and
                    # break to search the next memory set
                    #

                    if target_mask & masks[normal_index]:
                        hit_idx = seg_base + idxs[normal_index]
                        if hit_idx > idx:
                            continue
                        accesses.append(hit_idx)
                        #print(f"FOUND HIT AT IDX {hit_idx}")
                        break

            #
            # if there has been a read or a write, select the one that is
            # 'closest' to our current idx. there should only be, at most,
            # two elements in this list...
            #

            if accesses:
                return min(accesses, key=lambda x:abs(x-idx))

        # fail, reached end of trace
        return -1

    def find_next_register_change(self, reg_name, idx=None):
        """
        Return the next timestamp to change the given register.
        """
        if idx is None:
            idx = self.idx + 1

        # if the idx is invalid, then there is nothing to do
        if not(0 < idx < self.trace.length):
            return -1

        starting_segment = self.trace.get_segment(idx)
        target_mask_ids = self.trace.get_reg_mask_ids_containing(reg_name)

        # search forward through the remaining segments
        for seg_id in range(starting_segment.id , len(self.trace.segments)):
            seg = self.trace.segments[seg_id]
            seg_base = seg.base_idx

            #
            # we only need to search *part* of the current segment, start
            # from the given/starting idx position
            #

            if seg == starting_segment:
                relative_idx = idx - starting_segment.base_idx

            # for the remaining segments, we need to search them from the start
            else:
                relative_idx = 0

            # search forward through the starting segment
            while relative_idx < seg.length:
                if seg.reg_masks[relative_idx] in target_mask_ids:
                    return seg.base_idx + relative_idx
                relative_idx += 1

        # fail, reached end of trace
        return -1

    def find_prev_register_change(self, reg_name, idx=None):
        """
        Return the prev timestamp to change the given register.
        """

        #
        # search backwards from the current trace position if a starting
        # position is not specified
        #

        if idx is None:
            idx = self.idx - 1

        # if the idx is invalid, then there is nothing to do
        if not(0 < idx < self.trace.length):
            return -1

        starting_segment = self.trace.get_segment(idx)
        target_mask_ids = self.trace.get_reg_mask_ids_containing(reg_name)

        # search backwards through the remaining segments
        for seg_id in range(starting_segment.id, -1, -1):
            seg = self.trace.segments[seg_id]

            #
            # we only need to search *part* of the current segment, start
            # from the given/starting idx position
            #

            if seg == starting_segment:
                relative_idx = idx - starting_segment.base_idx

            #
            # for the remaining segments, we need to search them
            # back to front, as we are iterating backwards in time
            #

            else:
                relative_idx = seg.length - 1

            # search forward through the starting segment
            while relative_idx > -1:
                if seg.reg_masks[relative_idx] in target_mask_ids:
                    return seg.base_idx + relative_idx
                relative_idx -= 1

        # fail, reached end of trace
        return -1

    def _region_to_targets(self, address, length):
        """
        Convert an (address, len) region definition into a list of [(addr_id, access_mask), ...].
        """
        ADDRESS_ALIGMENT = 8 # TODO: this is gross!
        output = []

        #
        # convert the given contiguous region of memory into an array of aligned
        # addresses and memory masks to mirror the 'compressed' trace format
        #

        aligned_address = self.trace.get_aligned_address(address)
        aligned_mask = self.trace.get_aligned_address_mask(address)

        mapped_address = self.trace.get_mapped_address(address)
        if mapped_address != -1:
            output.append((mapped_address, aligned_mask))
            #print(f"aligned: 0x{aligned_address} - mask {aligned_mask}")

        # the bytes consumed so far
        length -= (ADDRESS_ALIGMENT - (address - aligned_address))
        aligned_address += ADDRESS_ALIGMENT

        # process the remaining.. aligned.. addresses
        while length > 0:

            mapped_address = self.trace.get_mapped_address(aligned_address)

            #
            # the current chunk of the region is not seen in the trace, skip
            # to the next chunk
            #

            if mapped_address == -1:
                length -= ADDRESS_ALIGMENT
                aligned_address += ADDRESS_ALIGMENT
                continue

            mask_length = ADDRESS_ALIGMENT if length > ADDRESS_ALIGMENT else length
            access_mask = self.trace.get_aligned_address_mask(aligned_address, mask_length)
            #print(f"aligned: 0x{aligned_address:08X} - mask {access_mask:02X} - mask len {mask_length}")

            output.append((mapped_address, access_mask))

            # continue moving through the region
            length -= ADDRESS_ALIGMENT
            aligned_address += ADDRESS_ALIGMENT

        #for addr, mask in output:
        #    print(f"TARGET {self.trace.mem_addrs[addr]:08X} MASK {mask:02X}")

        return output

    #-------------------------------------------------------------------------
    # State API
    #-------------------------------------------------------------------------

    def get_ip(self, idx=None):
        """
        Return the instruction pointer.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        return self.trace.get_ip(idx)

    def get_register(self, reg_name, idx=None):
        """
        Return a single register value.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        return self.get_registers([reg_name], idx)[reg_name]

    def get_registers(self, reg_names=None, idx=None):
        """
        Return a dict of the requested registers and their values.

        If a list of registers (reg_names) is not provided, all registers will be returned.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        if idx is None:
            idx = self.idx

        # no registers were specified, so we'll return *all* registers
        if reg_names is None:
            reg_names = self.arch.REGISTERS.copy()

        #
        # if the query matches the cached (most recently acces)
        #

        output_registers, target_registers = {}, reg_names.copy()

        # sanity checks
        for reg_name in target_registers:
            if not reg_name in self.arch.REGISTERS:
                raise ValueError(f"Invalid register name: '{reg_name}'")

        #
        # fast path / LRU cache of 1, pickup any registers that we've already
        # queried for this timestamp and remove them from the search
        #

        if idx == self._idx_cached_registers:
            for name in reg_names:
                if name in self._cached_registers:
                    output_registers[name] = self._cached_registers[name]
                    target_registers.remove(name)

        #
        # the trace PC is stored differently, and is tacked on at the end of
        # the query (if it is requested). we remove it here so we don't search
        # for it in the main register query logic
        #

        include_ip = False
        if self.arch.IP in target_registers:
            include_ip = True
            target_registers.remove(self.arch.IP)

        #
        # looks like everything is resolved from the cache already? so we
        # can just return early...
        #

        if not target_registers:
            if include_ip:
                output_registers[self.arch.IP] = self.trace.get_ip(idx)
            return output_registers

        #
        # search for the desired register values
        #

        current_idx = idx
        segment = self.trace.get_segment(idx)

        while segment:

            # fetch the registers of interest
            found_registers = segment.get_reg_info(current_idx, target_registers)
            for reg_name, info in found_registers.items():

                # alias the reg info
                reg_value, reg_idx = info

                # save the found register
                output_registers[reg_name] = reg_value

                # discard the found register from the search set
                target_registers.remove(reg_name)

            #print(f"Finished Seg #{segment.id}, still missing {target_registers}")

            # found all the desired registers!
            if not target_registers:
                break

            # TODO/XXX: uhf, this '-2' is ugly. should probably refactor. but we have to
            # do -2 because get_reg_info() searches from idx + 1.. so -2 into the
            # prev segment.. +1 will put us on the last idx of the segment...

            # move to the next segment if there are still registers to find...
            current_idx = segment.base_idx - 2
            segment = self.trace.get_segment(current_idx)

        # fetch IP, if it was requested
        if include_ip:
            output_registers[self.arch.IP] = self.trace.get_ip(idx)

        # update the set of cached registers
        if self._idx_cached_registers == idx:
            self._cached_registers.update(output_registers)
        else:
            self._cached_registers = output_registers

        # the timestamp for the cached register set
        self._idx_cached_registers = idx

        # return the register set for this trace index
        return output_registers

    def get_memory(self, address, length, idx=None):
        """
        Return the requested memeory.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        if idx is None:
            idx = self.idx

        #print(f"STARTING MEM FETCH AT IDX {idx} (reader @ {self.idx})")
        buffer = TraceMemory(address, length)

        #
        # translate the (address, len) 'region' definition to a set of pointer
        # width (eg, 8 byte) aligned addresses as used internally by the trace
        #

        aligned_addresses = {(((address + i) >> 3) << 3) for i in range(length)}

        get_mapped_address = self.trace.get_mapped_address
        mem_addrs = self.trace.mem_addrs
        mem_masks = self.trace.mem_masks

        missing_mem = {}
        for address in aligned_addresses:

            # translate the aligned addresses to their mapped addresses (a simple id)
            mapped_address = get_mapped_address(address)
            #print(f"SHOULD SEARCH? {address:08X} --> {mapped_address}")

            #
            # if the symbolic address (a mapped id) doesn't appear in the trace
            # at all, there is no need to try and fetch mem for it
            #

            if mapped_address == -1:
                continue

            #
            # save the mask for what bytes at the aligned address should
            # exist in the trace
            #

            missing_mem[mapped_address] = mem_masks[mapped_address]
            #print(f"MISSING 0x{address:08x} - MASK {mem_masks[mapped_address]:02X}")

        missing_mem.pop(-1, None)

        #
        #
        #

        starting_seg = self.trace.get_segment(idx)
        seg = starting_seg

        # NOTE: writes should have priority in this list
        mem_sets = \
        [
            (seg.read_idxs, seg.read_addrs, seg.read_masks),
            (seg.write_idxs, seg.write_addrs, seg.write_masks),
        ]

        segment_hits = {}

        #
        # loop backwards through the read / write memory sets for the segment
        # this get_memory() request started from (eg, the current trace position)
        #

        for set_id, entries in enumerate(mem_sets):
            idxs, addrs, masks = entries

            #
            # slice the memory set down to just the memory accesses that occur
            # before the starting idx/timestamp
            #

            relative_idx = idx - starting_seg.base_idx
            #print(f"ATTEMPTING TO SLICE AT RELATIVE IDX {relative_idx} (idx {idx})")

            index = bisect.bisect_right(idxs, relative_idx)
            idxs = idxs[:index]
            addrs = addrs[:index]
            masks = masks[:index]

            #
            # loop backwards through the memory access list, as we need
            # to find the last-known access to a given address
            #

            for hit_id in range(len(addrs) - 1, -1, -1):
                current_address = addrs[hit_id]
                missing_mask = missing_mem.get(current_address, 0)
                #print(f"MEM ACCESS {self.trace.mem_addrs[current_address]:08X}")
                #print(f" - MISSING MASK? {missing_mask:02X}")

                # the current memory access does not fall into the region
                # we care about... ignore it and keep moving
                if not masks[hit_id] & missing_mask:
                    continue

                # found a hit, save its info to evaluate after hits have
                # been scraped from both sets
                hits = segment_hits.setdefault(current_address, [])
                hits.append((idxs[hit_id], set_id, hit_id))

        #
        # we have collected all the reads/writes to the region of interest
        # for this segment... now we will go through each one until we have
        # enumerated the most recent data from the lists of memory accesses
        #

        for mapped_address, hits in segment_hits.items():
            #print(f"PROCESSING HIT {self.trace.mem_addrs[mapped_address]:08X}")

            #
            # sort the hits to an aligned address by highest idx (most-recent)
            # NOTE: mem set id will be the second sort param (writes take precedence)
            #

            hits = sorted(hits, reverse=True)
            #print(hits)

            #
            # go through each hit for the aligned address, until its value
            # has been fully resolved
            #

            for relative_idx, set_id, hit_id in hits:
                idxs, addrs, masks = mem_sets[set_id]

                missing_mask = missing_mem[mapped_address]
                current_mask = masks[hit_id]

                #assert relative_idx < (idx - seg.base_idx), f"rel {relative_idx} vs {idx} .. {idx - seg.base_idx}"
                #print(f"rel {relative_idx} vs {idx} .. {idx - seg.base_idx}")

                # if this access doesn't contain any new data of interest, ignore it
                if not missing_mask & current_mask:
                    continue

                found_mask = missing_mask & current_mask
                found_mem = seg.get_mem_data(hit_id, set_id, found_mask)
                #print(f"FOUND MEM {found_mem} FOUND MASK {found_mask:02X}")
                #print(f" -  ADDR: 0x{found_mem.address:08X}")
                #print(f" - BADDR: 0x{buffer.address:08X}, LEN {buffer.length}")

                # update the output buffer with the found memory
                buffer.update(found_mem)

                # update the missing mask bits
                missing_mask &= ~found_mask

                # the current address has had all of it bytes resolved
                # back to a concrete values, time to bail
                if not missing_mask:
                    missing_mem.pop(mapped_address)
                    break

                missing_mem[mapped_address] = missing_mask

        #
        # now we will go backwards through the trace segment snapshots and
        # attempt to resolve the remaining missing memory
        #

        for seg_id in range(starting_seg.id-1, -1, -1):

            seg = self.trace.segments[seg_id]
            mem_delta = seg.mem_delta

            to_remove = []

            #
            # loop through all the addresses that we are still missing data
            # for, and check if this segment can resolve it to a concrete value
            #

            for mapped_address, missing_mask in missing_mem.items():

                # skip the current address if it doesn't get touched by this seg
                if not(mapped_address in mem_delta):
                    continue

                #
                # fetch the 'value' (1-8 bytes) that this segment sets at the
                # the current aligned address
                #

                mv = mem_delta[mapped_address]

                #
                # if the bytes set aren't ones that we are still looking for,
                # then there is nothing to fetch for this address, in this seg
                #

                if not (missing_mask & mv.mask):
                    continue

                #
                # create a mask of the missing bytes, that we can resolve with
                # the memory value (mv) provided by this snapshot
                #

                found_mask = missing_mask & mv.mask

                # remove the bits that this memory value will resolve
                missing_mask &= ~found_mask
                if not missing_mask:
                    to_remove.append(mapped_address)

                other_address = mem_addrs[mapped_address]
                if other_address < buffer.address:
                    buffer_index = 0
                    other_index = buffer.address - other_address
                else:
                    buffer_index = other_address - buffer.address
                    other_index = 0

                buffer_remaining = buffer.length - buffer_index
                other_remaining = 8 - other_index
                overlap = min(buffer_remaining, other_remaining)

                #print(f"HIT 0x{other_address:08X} IN SEG {seg_id} (started from {starting_seg.id})", ' '.join(["%02X" % x for x in mv.value]))
                for i in range(overlap):
                    if (found_mask >> (other_index+i)) & 1:
                        #print(f"- GRABBING BYTE @ 0x{other_address+other_index+i:08X}, ({mv.value[other_index+i]:02X})")
                        buffer.data[buffer_index+i] = mv.value[other_index+i]
                        buffer.mask[buffer_index+i] = 0xFF

                missing_mem[mapped_address] = missing_mask

            # remove any addresses that have had their values fully resolved
            for mapped_address in to_remove:
                missing_mem.pop(mapped_address)

        #print("STILL MISSING", ["0x%08X" % self.trace.mem_addrs[x] for x in missing_mem])

        # return the final / found buffer
        return buffer

    def read_pointer(self, address, idx=None):
        """
        Read and return a pointer at the given address from memory.

        If the value cannot be fully resolved and returned, ValueError is raised.
        """
        if idx is None:
            idx = self.idx

        buffer = self.get_memory(address, self.arch.POINTER_SIZE, idx)
        if not len(set(buffer.mask)) == 1 and buffer.mask[0] == 0xFF:
            raise ValueError("Could not fully resolve memory at address")

        pack_fmt = 'Q' if self.arch.POINTER_SIZE == 8 else 'I'
        return struct.unpack(pack_fmt, buffer.data)[0]

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def idx_changed(self, callback):
        """
        Subscribe a callback for a trace navigation event.
        """
        register_callback(self._idx_changed_callbacks, callback)

    def _notify_idx_changed(self):
        """
        Notify listeners of an idx changed event.
        """
        notify_callback(self._idx_changed_callbacks, self.idx)
