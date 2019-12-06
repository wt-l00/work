#! /usr/bin/python3
# coding: UTF-8

file = open('syscalllist.txt')
file_data = file.read()

for line in file_data.split('\n'):
  tmp1 = line.find('\"')
  tmp2 = line.find('\"', tmp1+1)
  
  print('"' + line[tmp1+1:tmp2] + '"' + ',')
