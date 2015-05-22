#!/usr/bin/env python
#-*- coding: utf8 -*-
#########################################################################
# File Name: cal.py
# Author: kejiewei
# mail: jiewei_ke@163.com
# Created Time: 2015年05月19日 星期二 16时17分37秒
#########################################################################

def gen_bl(addr):
    addr = addr / 4
    begin = '0b10010'
    end = '01'
    if addr < 0:
        mid = bin(0x1000000 + addr)
    else:
        mid = bin(addr)
    mid = mid.lstrip('0b')
    return hex(int(begin + (24 - len(mid)) * '0' + mid + end, 2))

def gen_off(target, next_i):
    off = target - next_i
    #print off
    return off



#print gen_bl(0x10334)
off = gen_off(0xffffffc, 0x100007f0)
print gen_bl(off)

