#! /usr/bin/python3
# coding: UTF-8

file = open('sample.txt')
file_data = file.read()

for line in file_data.split('\n'):
  if '@' in line:
    for tmp in line.split(':'):
      print(tmp)
