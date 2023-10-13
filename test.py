with open("./exec.cpp", "r") as f:
    list_of_lines = []
    for l in f.readlines():
        list_of_lines.append(l)
    list_of_lines[54] = "        unsigned char AESkey[] = "