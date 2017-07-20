import re

print("pen = {")
with open("enterprise-numbers", "r") as f:

    # skip method is ???
    for i in range(0, 15):
        f.readline()

    while True:
        n = f.readline()
        if not n:
            break

        if re.match(r"\d+", n.strip()):
            num = int(n.strip())
        else:
            continue

        #num = int(f.readline())
        name = f.readline().strip()
        name = name.replace(r'"', "").replace(r'`', "")
        f.readline()
        f.readline()
        print("{0}: \"{1}\",".format(num, name))

print("}")
