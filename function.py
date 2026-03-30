st = input("input a string")

def char_info(s):
    counts = {}
    for char in s:
        key = char.lower()
        counts[key] = counts.get(key, 0) + 1

    for index, char in enumerate(s):
        key = char.lower()
        print(f"{char} ({index}) - {counts[key]}")

char_info(st)
