import csv

print("element_id = {")

with open('ipfix-information-elements.csv', 'r') as f:
    reader = csv.reader(f)
    header = next(reader)

    for row in reader:
        num = row[0]
        name = row[1]

        if "-" in num:
            begin, end = num.split("-")
            for i in range(int(begin), int(end) + 1):
                print("{0}: \"{1}\",".format(i, name))
        else:
            print("{0}: \"{1}\",".format(num, name))

print("}")
