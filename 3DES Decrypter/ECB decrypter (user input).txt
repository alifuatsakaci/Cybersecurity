allowed_characters = "0123456789abcdefABCDEF"

flag = False
while not flag:
    flag = True
    ciper_text_O = str(input("Cipher text: "))
    if len(ciper_text_O) % 16 != 0:
        flag = False
        print("< cipher text must have a length of multiple of 16 characters >")
    if flag:
        for i9 in range(len(ciper_text_O)):
            if ciper_text_O[i9] not in allowed_characters:
                flag = False
        if not flag:
            print("< cipher text must consist of only hex digits >")
        else:
            ciper_text_O = ciper_text_O.upper()

flag = False
while not flag:
    flag = True
    key1 = str(input("Key 1: "))
    if len(key1) != 16:
        flag = False
        print("< key must be 16 digits long >")
    if flag:
        for i10 in range(16):
            if key1[i10] not in allowed_characters:
                flag = False
        if not flag:
            print("< key must consist of only hex digits >")
        else:
            key1 = key1.upper()

flag = False
while not flag:
    flag = True
    key2 = str(input("Key 2: "))
    if len(key2) != 16:
        flag = False
        print("< key must be 16 digits long >")
    if flag:
        for i10 in range(16):
            if key2[i10] not in allowed_characters:
                flag = False
        if not flag:
            print("< key must consist of only hex digits >")
        else:
            key2 = key2.upper()

flag = False
while not flag:
    flag = True
    key3 = str(input("Key 3: "))
    if len(key3) != 16:
        flag = False
        print("< key must be 16 digits long >")
    if flag:
        for i10 in range(16):
            if key3[i10] not in allowed_characters:
                flag = False
        if not flag:
            print("< key must consist of only hex digits >")
        else:
            key3 = key3.upper()


def integer_to_binary(integer):
    binary = ""
    power_list = [8, 4, 2, 1]
    for i0 in range(4):
        integer_maybe = integer - power_list[i0]
        if integer_maybe >= 0:
            binary = binary + "1"
            integer = integer_maybe
        else:
            binary = binary + "0"
    return binary


def binary_to_integer(binary):
    integer = 0
    for i1 in range(len(binary)):
        if binary[- i1 - 1] == "1":
            integer = integer + (2 ** i1)
    return integer


IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

IP_inv = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E_box = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_box = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P_permutation = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

PC_1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

PC_2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

htob_list_hex = "0123456789ABCDEF"
htob_list_binary = [
    "0000", "0001", "0010", "0011",
    "0100", "0101", "0110", "0111",
    "1000", "1001", "1010", "1011",
    "1100", "1101", "1110", "1111"
]


def hex_to_binary(text):
    binary = ""
    for i2 in range(len(text)):
        flag_htob = False
        index_htob = 0
        while not flag_htob:
            if htob_list_hex[index_htob] == text[i2]:
                flag_htob = True
                binary = binary + htob_list_binary[index_htob]
            index_htob = index_htob + 1
    return binary


def binary_to_hex(binary):
    hex_btoh = ""
    for i in range(int(len(binary) / 4)):
        group_btoh = binary[i * 4: i * 4 + 4]
        index = 0
        flag = False
        while not flag:
            if htob_list_binary[index] == group_btoh:
                flag = True
                hex_btoh = hex_btoh + htob_list_hex[index]
            index = index + 1
    return hex_btoh


def table_apply(data, table):
    new_data = ""
    for i3 in range(len(table)):
        new_data = new_data + data[table[i3] - 1]
    return new_data


def left_shift(data, amount):
    new_data = data[amount:len(data)] + data[0:amount]
    return new_data


def xor(data_1, data_2):
    result = ""
    for i5 in range(len(data_1)):
        if data_1[i5] == data_2[i5]:
            result = result + "0"
        else:
            result = result + "1"
    return result


one_bit_rounds = [1, 2, 9, 16]


def DES_d(ciper_text_hex, key_hex):
    ciper_text_binary = hex_to_binary(ciper_text_hex)

    key_binary = hex_to_binary(key_hex)

    key_56 = table_apply(key_binary, PC_1)

    Pre_IP_inv_ciper_text = table_apply(ciper_text_binary, IP)

    fake_key_56 = key_56
    round_keys = []
    for key in range(16):
        if (key + 1) in one_bit_rounds:
            key_i = left_shift(fake_key_56[0:28], 1) + left_shift(fake_key_56[28:56], 1)
        else:
            key_i = left_shift(fake_key_56[0:28], 2) + left_shift(fake_key_56[28:56], 2)
        fake_key_56 = key_i
        round_keys.append(table_apply(key_i, PC_2))

    text = Pre_IP_inv_ciper_text[32:64] + Pre_IP_inv_ciper_text[0:32]

    new_text_left = text[0:32]
    new_text_right = text[32:64]

    for round_number in range(16):

        real_round_number = 16 - round_number

        round_key = round_keys[real_round_number - 1]

        old_text_right = new_text_left

        old_text_right_expanded = table_apply(old_text_right, E_box)

        s_box_input = xor(round_key, old_text_right_expanded)

        s_box_output = ""
        for box_index in range(8):
            group = s_box_input[box_index * 6: box_index * 6 + 6]
            row = binary_to_integer(group[0] + group[5])
            column = binary_to_integer(group[1:5])
            s_box_output = s_box_output + integer_to_binary(S_box[box_index][row][column])

        f_function_output = table_apply(s_box_output, P_permutation)

        old_text_left = xor(f_function_output, new_text_right)

        new_text_left = old_text_left
        new_text_right = old_text_right

    plain_text_permutated = new_text_left + new_text_right

    plain_text_binary = table_apply(plain_text_permutated, IP_inv)
    plain_text_hex = binary_to_hex(plain_text_binary)

    return plain_text_hex


def DES_e(ptxt, ky):
    plain_text = hex_to_binary(ptxt)
    key = hex_to_binary(ky)

    plain_text_permutated = table_apply(plain_text, IP)
    key_56 = table_apply(key, PC_1)

    plain_text_left = plain_text_permutated[0:32]
    plain_text_right = plain_text_permutated[32:64]

    key_56_left = key_56[0:28]
    key_56_right = key_56[28:56]

    for round_number in range(16):

        if (round_number + 1) in one_bit_rounds:
            key_56_left_shifted = left_shift(key_56_left, 1)
            key_56_right_shifted = left_shift(key_56_right, 1)
        else:
            key_56_left_shifted = left_shift(key_56_left, 2)
            key_56_right_shifted = left_shift(key_56_right, 2)
        key_56_shifted = key_56_left_shifted + key_56_right_shifted

        new_key_left = key_56_left_shifted
        new_key_right = key_56_right_shifted

        round_key = table_apply(key_56_shifted, PC_2)

        plain_text_right_expanded = table_apply(plain_text_right, E_box)

        s_box_input = xor(plain_text_right_expanded, round_key)

        s_box_output = ""
        for box_index in range(8):
            group = s_box_input[box_index * 6: box_index * 6 + 6]
            row = binary_to_integer(group[0] + group[5])
            column = binary_to_integer(group[1:5])
            s_box_output = s_box_output + integer_to_binary(S_box[box_index][row][column])

        f_function_output = table_apply(s_box_output, P_permutation)

        new_plain_text_right = xor(f_function_output, plain_text_left)
        new_plain_text_left = plain_text_right

        plain_text_left = new_plain_text_left
        plain_text_right = new_plain_text_right

        key_56_left = new_key_left
        key_56_right = new_key_right

    new_plain_text = plain_text_right + plain_text_left

    ciper_text = table_apply(new_plain_text, IP_inv)
    ciper_text_hex = binary_to_hex(ciper_text)

    return ciper_text_hex


plain_text_EEE = ""
plain_text_EDE = ""
for part in range(int(len(ciper_text_O) / 16)):
    partition = ciper_text_O[part * 16: part * 16 + 16]
    plain_text_EEE = plain_text_EEE + DES_d(DES_d(DES_d(partition, key3), key2), key1)
    plain_text_EDE = plain_text_EDE + DES_d(DES_e(DES_d(partition, key3), key2), key1)

plain_text_EEE = hex_to_binary(plain_text_EEE)
plain_text_EDE = hex_to_binary(plain_text_EDE)
index = len(plain_text_EEE) - 1
while index >= 0 and plain_text_EEE[index] == "0":
    index = index - 1
plain_text_EEE = binary_to_hex(plain_text_EEE[0:index])

index = len(plain_text_EDE) - 1
while index >= 0 and plain_text_EDE[index] == "0":
    index = index - 1
plain_text_EDE = binary_to_hex(plain_text_EDE[0:index])

print(f"Ciper text : {ciper_text_O}")
print(f"Key 1      : {key1}")
print(f"Key 2      : {key2}")
print(f"Key 3      : {key3}")
print("< using 3DES (EEE) >")
print(f"Plain text : {plain_text_EEE}")
print("< using 3DES (EDE) >")
print(f"Plain text : {plain_text_EDE}")
