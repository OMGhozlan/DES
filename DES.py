IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

PC1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOX = [

[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
],

[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
],

[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
],

[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
],

[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
],

[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
],

[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
],

[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]


SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def des_bin(val, bitsize):
    bin_val = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(bin_val) > bitsize:
        raise ValueError("Value exceeded the expected size")
    while len(bin_val) < bitsize:
        bin_val = "0" + bin_val
    return bin_val

def str_bit(p_text):
    string = []
    for byte in p_text:
        bin_val = des_bin(byte, 8)
        string.extend([int(bit) for bit in list(bin_val)])
    return string

def bit_str(string):
    return ''.join([chr(int(i,2)) for i in [''.join([str(j) for j in bytes]) for bytes in  slice(string,8)]])

def slice(input, size):
    return [input[i:i+size] for i in range(0, len(input), size)]

DECRYPT=0
ENCRYPT=1

class DES():
    def __init__(self):
        self.s_key = None
        self.p_text = None
        self.keys = []


    def substitute(self, data):
        sub_blocks = slice(data, 6)
        sub = []
        for sub_list in range(len(sub_blocks)):
            block = sub_blocks[sub_list]
            # print("Block: ", block)
            row = int(str(block[0]) + str(block[5]),2)
            column = int(''.join([str(i) for i in block[1:][:-1]]),2)
            # print(sub_list, column, row)
            round_data = S_BOX[sub_list][row][column]
            bin = des_bin(round_data, 4)
            sub += [int(string) for string in bin]
        return sub


    def permute(self, block, table):
        return [block[entry-1] for entry in table]


    def extend(self, block, table):
        return [block[entry-1] for entry in table]


    def xor(self, t1, t2):
        return [l ^ r for l,r in zip(t1,t2)]


    def key_gen(self):
        self.keys = []
        key = str_bit(self.s_key)
        key = self.permute(key, PC1)
        left, right = slice(key, 28)
        for i in range(16):
            left, right = self.shift(left, right, SHIFT[i])
            tmp = left + right
            self.keys.append(self.permute(tmp, PC2))


    def shift(self, left, right, n):
        return left[n:] + left[:n], right[n:] + right[:n]


    def pad(self):
        length = 8 - (len(self.p_text) % 8)
        self.p_text += length * chr(length)


    def unpad(self, data):
        length = ord(data[-1])
        return data[:-length]


    def execute(self, key, p_text, op=ENCRYPT, padding=False):
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            raise ValueError("Key size should be 64 bit (8 bytes) long")
        self.s_key = key
        self.p_text = p_text
        if padding and op==ENCRYPT:
            self.pad()
        elif len(self.p_text) % 8 != 0:
            raise ValueError("Input must be multiple of 8 bytes")
        self.key_gen()
        p_text_blocks = slice(self.p_text, 8)
        round_i = []
        # print(self.p_text)
        for block in p_text_blocks:
            block = str_bit(block)
            block = self.permute(block, IP)
            left, right = slice(block, 32)
            for round in range(16):
                # print('Iteration ', round)
                # print('Data ', block)
                data = self.extend(right, E)
                if op == ENCRYPT:
                    round_d = self.xor(self.keys[round], data)
                else:
                    round_d = self.xor(self.keys[15-round], data)
                # print("Round D: ", round_d)
                round_d = self.substitute(round_d)
                round_d = self.permute(round_d, P)
                round_d = self.xor(left, round_d)
                left = right
                right = round_d
            round_i += self.permute(right + left, FP)
        cipher_t = bit_str(round_i)
        if padding and op==DECRYPT:
            return self.unpad(cipher_t)
        else:
            return cipher_t


    def encrypt(self, key, p_text, padding=False):
        return self.execute(key, p_text, ENCRYPT, padding)


    def decrypt(self, key, p_text, padding=False):
        return self.execute(key, p_text, DECRYPT, padding)


if __name__ == '__main__':
    key = "keykeykey"
    p_text= "Hello wo"
    d = DES()
    filepath = ''
    with open(filepath, 'r') as file:
        data = file.read()
    ciphertext = d.encrypt(key, p_text, True)
    with open(filepath, 'wb') as file:
        file.write(ciphertext)
    plaintext = d.decrypt(key, ciphertext, True)
    with open(filepath, 'wb') as file:
        file.write(plaintext)
    # print ("Ciphered: ", ciphertext.encode('ascii', 'ignore'))
    # print ("Deciphered: ", plaintext)
