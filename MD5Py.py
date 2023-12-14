#!/usr/bin/env python3
#
# DISCLAIMER
# ==========
# Made solely for the learning purposes, shared in good faith with everyone.
# For real applications, use: https://docs.python.org/3/library/hashlib.html
#

def MD5(message: str) -> str:
    '''The MD5 Message-Digest Algorithm implemented in Python

    Implementation based on the pseudocode from Wikipedia:
    – https://en.wikipedia.org/wiki/MD5#Pseudocode

    Original specification for reference:
    – https://www.ietf.org/rfc/rfc1321.txt
    '''
    # Convert the message to the sequence of Bytes
    data = message.encode()

    # Helper function used in operations
    def rotate_left_uint32(n: int, d: int) -> int:
        return (n << d) | (n >> (32 - d))

    # The per-round shift amounts
    S = ([7, 12, 17, 22] * 4
         + [5, 9, 14, 20] * 4
         + [4, 11, 16, 23] * 4
         + [6, 10, 15, 21] * 4)

    # Binary integer part of the sines of integers (radians) used as constants
    # K = [math.floor(2**32 * abs(math.sin(i + 1))) for i in range(64)]
    K = [3614090360, 3905402710, 606105819, 3250441966,
         4118548399, 1200080426, 2821735955, 4249261313,
         1770035416, 2336552879, 4294925233, 2304563134,
         1804603682, 4254626195, 2792965006, 1236535329,
         4129170786, 3225465664, 643717713, 3921069994,
         3593408605, 38016083, 3634488961, 3889429448,
         568446438, 3275163606, 4107603335, 1163531501,
         2850285829, 4243563512, 1735328473, 2368359562,
         4294588738, 2272392833, 1839030562, 4259657740,
         2763975236, 1272893353, 4139469664, 3200236656,
         681279174, 3936430074, 3572445317, 76029189,
         3654602809, 3873151461, 530742520, 3299628645,
         4096336452, 1126891415, 2878612391, 4237533241,
         1700485571, 2399980690, 4293915773, 2240044497,
         1873313359, 4264355552, 2734768916, 1309151649,
         4149444226, 3174756917, 718787259, 3951481745]

    # Initialize variables
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    # Pre-processing: adding a single 1 bit and padding data with zeros
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'

    # Append original message length in bits (mod 2**64 == 8 Bytes) to data
    data += ((len(message) * 8) % (2 ** 64)).to_bytes(length=8,
                                                      byteorder='little')

    # Process the data in successive 512-bit chunks
    chunks = [data[i:i + 64] for i in range(0, len(data), 64)]
    for chunk in chunks:

        # Break chunk into sixteen 32-bit words
        M = [int.from_bytes(chunk[i:i + 4], byteorder='little')
             for i in range(0, len(chunk), 4)]

        # Initialize hash value for this chunk
        A = a0
        B = b0
        C = c0
        D = d0

        # Perform 4 rounds of 16 operations each
        for i in range(64):
            # round 1
            if 0 <= i <= 15:
                F = (B & C) | (~B & D)
                g = i

            # round 2
            elif 16 <= i <= 31:
                F = (B & D) | (~D & C)
                g = (5 * i + 1) % 16

            # round 3
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16

            # round 4
            elif 48 <= i <= 63:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            # Save operation result (wrap variables as in 32-bit unsigned int)
            F = (F + A + K[i] + M[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + rotate_left_uint32(F, S[i])) & 0xFFFFFFFF

        # Add current chunk's hash to the result so far (mod 2**32)
        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    # Recover Bytes from integers, note that all values are in little-endian!
    a0 = a0.to_bytes(length=4, byteorder='little')
    b0 = b0.to_bytes(length=4, byteorder='little')
    c0 = c0.to_bytes(length=4, byteorder='little')
    d0 = d0.to_bytes(length=4, byteorder='little')

    digest = a0 + b0 + c0 + d0

    return digest.hex()


#
# MD5 test suite from https://www.ietf.org/rfc/rfc1321.txt
#
if __name__ == '__main__':
    assert MD5('') == 'd41d8cd98f00b204e9800998ecf8427e'
    assert MD5('a') == '0cc175b9c0f1b6a831c399e269772661'
    assert MD5('abc') == '900150983cd24fb0d6963f7d28e17f72'
    assert MD5('message digest') == 'f96b697d7cb7938d525a2f31aaf161d0'
    assert MD5('abcdefghijklm'
               'nopqrstuvwxyz') == 'c3fcd3d76192e4007dfb496cca67e13b'
    assert MD5('ABCDEFGHIJKLM'
               'NOPQRSTUVWXYZ'
               'abcdefghijklm'
               'nopqrstuvwxyz'
               '0123456789') == 'd174ab98d277d9f5a5611c2c9f419d9f'
    assert MD5('12345678901234567890'
               '12345678901234567890'
               '12345678901234567890'
               '12345678901234567890') == '57edf4a22be3c955ac49da2e2107b67a'
