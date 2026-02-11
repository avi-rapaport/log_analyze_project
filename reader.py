import csv

def csv_list_load(filename):
    with open(filename, "r") as file:
        return list(csv.reader(file))




