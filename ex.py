#! /usr/bin/python3
# coding: UTF-8

file = open('syscalllist.txt')
file_data = file.read()

for line in file_data.split('\n'):
  for tmp in line.split(','):
    if "SEN(" in tmp:
      print('"' + tmp[6:-1] + '"' + ',')
