import array

class TraceMemory(object):
    """
    A Trace Memory Buffer.

    TODO: this is pretty trash / overraught and should be refactored. also 
    this can probably be moved into tenet.types? 
    """

    def __init__(self, address, length):
        self.address = address
        self.data = array.array('B', [0]) * length
        self.mask = array.array('B', [0]) * length

    def __contains__(self, address):
        if self.address <= address < self.end_address:
            return True
        return False

    @property
    def end_address(self):
        return self.address + self.length

    @property
    def length(self):
        return len(self.data)

    def consume(self, other):
        assert other.address >= self.address

        end_address = max(self.end_address, other.end_address)
        new_length = end_address - self.address

        #
        # if the other buffer is outside the memory region of this object,
        # extend our region to include it
        #

        if new_length > self.length:
            new_data = array.array('B', [0]) * new_length
            new_mask = array.array('B', [0]) * new_length
            new_data[:self.length] = self.data[:self.length]
            new_mask[:self.length] = self.mask[:self.length]
            self.data = new_data
            self.mask = new_mask

        # transfer data from the other memory object, into this one
        base_idx = other.address - self.address
        for i in range(other.length):
            index = base_idx + i
            if other.mask[i]:
                self.data[index] = other.data[i]
                self.mask[index] = 0xFF

    def update(self, other):

        if self.address < other.address:
            this_start = other.address - self.address
            other_start = 0
        else:
            this_start = 0
            other_start = self.address - other.address

        assert this_start >= 0, f"{this_start} must be >= 0"
        assert other_start >= 0, f"{other_start} must be >= 0"

        other_length_left = other.length - other_start
        this_length_left = self.length - this_start
        overlapped_length = min(other_length_left, this_length_left)

        #print('-'*50)
        #print(f" Self Addr 0x{self.address:08X}, Len {self.length}")
        #print(f"Other Addr 0x{other.address:08X}, Len {other.length}")
        #print(f" Overlapping Bytes: {overlapped_length}, self start {this_start}, other start {other_start}")

        for i in range(overlapped_length):
            if other.mask[other_start+i]:
                self.data[this_start+i] = other.data[other_start+i]
                self.mask[this_start+i] = 0xFF

    def __str__(self):
        output = ["%02X" % byte if mask else "??" for byte, mask in zip(self.data, self.mask)]
        return ' '.join(output)