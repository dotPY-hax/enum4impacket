import math
import os

def format_columns(list_of_lists):
    padding = 2
    delimiter = ": "
    columns = list(zip(*list_of_lists))
    widths = [len(max([str(i) for i in column], key=len)) + padding for column in columns]

    lines = []
    for line in list_of_lists:
        new_line = []
        for i, column in enumerate(line):
            new_line.append(str(column) + " " * (widths[i] - len(str(column))))
        lines.append(delimiter.join(new_line))
    return lines


def print_columns(list_of_lists):
    lines = format_columns(list_of_lists)
    for line in lines:
        print(line)

#kek
def print_list(list):
    for line in list:
        print(line)

def print_delimiter(string):
    delimiter = "="
    width = min(os.get_terminal_size()[0], 80)
    filler_width = (width - len(string)) / 2
    print(delimiter * math.floor(filler_width) + string + delimiter * math.ceil(filler_width))


