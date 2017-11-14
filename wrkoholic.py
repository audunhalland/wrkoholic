
import argparse
import os
import string
import struct

def strings(buf, min=4):
    result = ""
    for c in buf:
        s = chr(c)
        if s in string.printable:
            result += s
            continue
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:  # catch result at EOF
        yield result

class Stats:
    def __init__(self):
        self.positions = {}

    def reg_value(self, fn, position, value):
        if not position in self.positions:
            self.positions[position] = {}

        values = self.positions[position]

        if value in values:
            values[value].append(fn)
        else:
            values[value] = [fn]

    def analyze(self):
        pos = 8
        out = []
        diff_id = 0
        diffs = {}

        while pos in self.positions:
            values = self.positions[pos]

            if len(values.keys()) == 1:
                out.append(hex(next(x for x in values.keys())))
            else:
                diffs[diff_id] = values
                out.append(chr(ord('A') + diff_id))
                diff_id += 1

            if (pos + 1) % 8 == 0:
                print('%s %s' % (pos - 7, out))
                for i in range(0, diff_id):
                    print('    %s: %s' % (chr(ord('A') + i), { k: len(v) for (k, v) in diffs[i].items() }))
                diff_id = 0
                diffs = {}
                out = []
            pos += 1

class Wrk:
    def __init__(self):
        self.version = None
        self.chunks = []

class Chunk:
    def __init__(self, id, data):
        self.id = id
        self.data = data

def parse_wrk(fn, stats):
    with open(fn, 'rb') as f:
        header = f.read(8)
        if header != b'CAKEWALK':
            return None

        for i in range(0, 256):
            buf = f.read(1)
            data = struct.unpack('B', buf)

            stats.reg_value(fn, i + 8, data[0])

    # Try chunk approach
    print(fn)
    with open(fn, 'rb') as f:
        header = f.read(8)
        if header != b'CAKEWALK':
            return None

        wrk = Wrk()
        f.read(1) # Dummy byte?
        wrk.version = struct.unpack('BB', f.read(2))
        print(wrk.version)
        while True:
            chunk_id = struct.unpack('B', f.read(1))[0]
            if chunk_id == 0xff:
                break

            length = struct.unpack('i', f.read(4))[0]
            data = f.read(length)

            print('chunk[%s] id: %s, length: %s strings: %s'
                  % (len(wrk.chunks), chunk_id, length, [x for x in strings(data)]))

            wrk.chunks.append(Chunk(chunk_id, data))

        rest = f.read()
        if len(rest) > 0:
            raise Exception('Did not expect data after last chunk')

        return wrk


def scan(d):
    stats = Stats()

    for root, dirs, files in os.walk(d):
        for fn in files:
            path = os.path.join(root, fn)
            wrk = parse_wrk(path, stats)

    stats.analyze()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', action='store_true', help='Scan .wrk files and analyze collectively')

    args = parser.parse_args()

    if args.scan:
        scan('.')
