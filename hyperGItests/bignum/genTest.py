# from enum import Enum
# import sys
import queue
import random
import math
from copy import deepcopy
import subprocess
import shlex
import time

"""
 Sample program build call
    ./run.sh L1 L2 input.txt nhigh
 Core Process for test input generation:
    1) generate random input (data) with the size L1 
    2) save data in the input.txt file
    3) generate L2
    4) run the program once for expected output (L1==L2)
    5) run it nhigh times with random L1 and L2 values
"""
#
# max (L1_bits=7)
#   => actual input length range is 2^7 (128 bytes ==> 1024 bits)
#   => input length given is 2^10 (10 bits)
L1_bits = 5  # Actual input length 2^7 bytes
nlow = 40  # number of lows
nhigh = 4  # number of highs for every low
budget = 1  # total budget for every low high pair

L2_bits = L1_bits + 7       # input length given (12 bits random number upto 4096)
search_bytes = 2 ** L1_bits # max actual input length to search (2**7 ==> 128 bytes)
bit_len = search_bytes * 4 + L2_bits  # Search range is 128*8 + 12 ==> 1036 bits
max_range = 2**bit_len - 1  # Initial range for every side-length: 0 .. max_range
print(bit_len)


class TestPair:
    def __init__(self):
        self.leak = 0
        self.input = ""
        self.expected = ""
        self.output = []
        self.cnt = 0

    def __lt__(self, other):
        return self.leak < other.leak


def int_len(val):
    res = 0
    while val != 0:
        val //= 10
        res += 1
    return res


def binary2hex(b_str):
    return hex(int(b_str, 2))[2:].upper()


def add_zeros(st, ll):
    num_0s = ll - len(st)
    return "0" * num_0s + st


def prepare_input(val):
    """
    max 500 byte for random input (4000 bits)
        => actual input range is 2^9 (9 bits)
        => assumed input length is 2^16 (16 bits)
    "L1 bytes Input" "actual input length (L1)" "assumed input length (L2)"
    
    ./buildbntest.sh gcc out.txt 16 32 input.txt nhigh
    1) generate random input (data) with the size L1
    2) save data in the input.txt file
    3) generate L2 (random number not greater than 2^16)
    4) call buildtest with the parameter nhigh      
    """
    b_res = bin(val)[2:]
    l2_start = len(b_res) - L2_bits

    # print(int(b_res[l2_start:], 2))
    l2 = binary2hex(b_res[l2_start:])
    hex_res = binary2hex(b_res[:l2_start])
    if len(hex_res) % 2 == 1:
        hex_res = "0" + hex_res

    while len(l2) < 8:
        l2 += "0"
    # print(int(l2, 16))
    return hex_res+l2


def binary2int(b_str):
    return int(b_str, 2)


def generate_low(rn1, rng_low, rng_high):
    ll = rng_low
    # choose a random starting point with in the range
    if rng_high - rn1 > rng_low:
        ll = random.randrange(rng_low, rng_high - rn1)
    # then choose a random value starting from ll
    res = ll + random.randrange(rn1)

    return res


def insert(temp: TestPair, que):
    que.put(deepcopy(temp))
    if que.qsize() > nlow:
        que.get()


def process_map(mp):
    numel = 0
    for count, elem in enumerate(mp):
        val = mp[elem]
        numel += val

    total = 0
    for count, elem in enumerate(mp):
        val = mp[elem]
        prob = val / numel
        total += (-prob * math.log(prob, 2))

    return total


def decimal2binary(n):
    return bin(n).replace("0b","")


def calculate_entropy(omap, imap):
    res_out = process_map(omap)
    res_in = process_map(imap)

    return res_out - res_in


def exec_cmd(cmd, t_out=1):
    s_process = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    try:
        stdout, stderr = s_process.communicate(timeout=t_out)
        return stdout.decode("ascii")
    except subprocess.TimeoutExpired:
        s_process.send_signal(9)
        return None


def run_4h(low_inp, que):
    test = TestPair()
    omap = dict()
    imap = dict()
    low_hex = prepare_input(low_inp)

    test.input = low_hex
    # Sample call: ./run.sh 5 19 "9E51ABF3AD" 5
    cmd = "./run.sh {} {}".format(test.input, nhigh)
    out_arr = exec_cmd(cmd)
    # print(out_arr)
    out_arr = out_arr.split(";\n")
    if len(out_arr) < nhigh:
        return 0

    imap[test.input] = nhigh
    for h in range(nhigh):
        ostr = test.input + "^" + out_arr[h]
        if ostr in omap:
            omap[ostr] += 1
        else:
            omap[ostr] = 1

    test.leak = calculate_entropy(omap, imap)
    insert(test, que)
    return test.leak


def run(rng1, low, high, que):
    mid = low + (high - low) // 2

    l_sum = 0  # sum of the leaks for the lower half
    for b in range(budget):
        for l in range(nlow):
            low_inp = generate_low(rng1, low, mid)
            l_sum += run_4h(low_inp, que)

    u_sum = 0  # sum of the leaks for the upper half
    for b in range(budget):
        for l in range(nlow):
            low_inp = generate_low(rng1, mid + 1, high)
            u_sum += run_4h(low_inp, que)

    if l_sum > 0 or u_sum > 0:
        print("Left:{:.1f} Right:{:.1f} ".format(l_sum, u_sum), end=' ')
    if l_sum > u_sum:
        return low, mid
    return mid + 1, high


def main(rng):
    que = queue.PriorityQueue()
    range_lower = 0
    range_upper = max_range
    k = 0
    start = time.time()
    while rng > 4:
        k += 1
        rng //= 2
        range_lower, range_upper = run(rng, range_lower, range_upper, que)
        print("{} {}: {:.1f}".format(rng, k, time.time() - start))
        # print(rng)
        # if k % 5 == 0:
        #     print()

    print("{:.1f}".format(time.time() - start))
    print(k)
    total = 0
    while not que.empty():
        top = que.get()
        print("{:.3f} {}".format(top.leak, top.input ))
        total += top.leak
    print(total)


if __name__ == '__main__':
    main(max_range)
    # print(hex(int("010110101001", 2))[2:].upper())


