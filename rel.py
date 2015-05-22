#!/usr/bin/env python
#-*- coding: utf8 -*-
#########################################################################
# File Name: rel.py
# Author: kejiewei
# mail: jiewei_ke@163.com
# Created Time: 2015年05月15日 星期五 20时35分29秒
#########################################################################
import sys
import os
import re

import cal

GNU_TOOL_PREFIX = "powerpc-linux-gnu-"
OBJDUMP = GNU_TOOL_PREFIX + "objdump"
READELF = GNU_TOOL_PREFIX + "readelf"
NM = GNU_TOOL_PREFIX + "nm"
CPPFILT = GNU_TOOL_PREFIX + "c++filt"

FUNC_PAT = re.compile("(?P<addr>[0-9a-f]{8}) <(?P<func>.*)>:")
CALL_PAT = re.compile(" *(?P<addr>[0-9a-f]{1,8}).*<(?P<func>.*)>")

def run(cmd):
    #print cmd
    return os.popen(cmd).readlines()

def demangle(func_name):
    return run(CPPFILT + " " + func_name)[0].rstrip()

'''
def gen_rel_sym(elf):
    func_rel_sym = {}
    last_func_index = ()

    asm = run(OBJDUMP + " -S " + elf)
    for line in asm:
        m = re.match(FUNC_PAT, line)
        if m:
            last_func_index = (m.group('func'), m.group('addr'))
            if (last_func_index) not in func_rel_sym:
                func_rel_sym[last_func_index] = []
            continue
        m = re.match(CALL_PAT, line)
        if m:
            func_rel_sym[last_func_index].append((m.group('func'), m.group('addr'), demangle(m.group('func'))))

    for (func, rel_sym) in func_rel_sym.items():
        if len(rel_sym) > 0:
            print '*' * 10
            print func
            for rel in rel_sym:
                #print rel
                print rel[1], rel[0], rel[2]

    return func_rel_sym
'''

'''
Get function offset from relocation file(.o)
'''
def get_func_range(reloc, func):
    func_asm = run("""%s -S %s | awk 'BEGIN{FS="\\n"; RS=""} ($0~/%s/){print}' | sed -n '2p;$p' | awk -F':' '{print $1}'""" % (OBJDUMP, reloc, func))
    (start, end) = func_asm
    return (start.strip(), end.strip())

'''
Get relocation symbol from reloc

rel_sym[0] Offset
rel_sym[1] Sym. Name
rel_sym[2] Type
rel_sym[3] Addend

'''
def get_rel_sym(reloc):
    rel_sym = []
    rel_tab = run("""%s -r %s | awk 'BEGIN{FS="\\n"; RS=""} (NR==1){print $0}' | awk '(NR>2){print}' | awk '{print $1, $3, $5, $7}'""" % (READELF, reloc))
    
    for line in rel_tab:
        #print line
        (off, type, name, addend) = line.rstrip().split(' ')
        rel_sym.append((off, name[0:22], type, addend))
    #print rel_sym
    return rel_sym

'''
Get offset of inject.o.text from target

'''
def get_text_offset(inject, target):
    result = run("%s -S %s | grep %s | tail -1 | awk '{print $4, $5}'" % (READELF, target, inject + '.text'))
    (addr, off) = result[0].strip().split(' ')
    return ('0x' + addr, '0x' + off)

def get_rodata_offset(inject, target):
    result = run("%s -S %s | grep %s | tail -1 | awk '{print $5}'" % (READELF, target, inject + '.rodata'))
    return '0x' + result[0].strip()

'''
Relocate the inject's symbol in range(start, end) with the plt given by target

rel_dict:
key: sym_addr -- the physical addr
value: (sym_off, relocated addr, sym_name, reloc_type)
'''
def rel(inject, target, start, end):
    rel_dict = {}
    target_plt_dict = {}
    
    (text_off, text_addr) = get_text_offset(inject, target)
    print "text_off:" + text_off
    
    # Get Plt symbol from target
    result = run("%s -S %s | egrep '^[0-9a-f]{1,8} <.*@plt>'" % (OBJDUMP, target))
    if len(result) == 0:
        result = run("%s -S -j .plt %s | egrep '^[0-9a-f]{1,8} <.*@plt>'" % (OBJDUMP, target))
    for plt in result:
        (off, name) = plt.rstrip().split(' ')
        target_plt_dict[name.split('<')[1].split('@')[0][0:22]] = '0x' + off
    #print target_plt_dict

    # Get relocation dict
    for rel_sym in get_rel_sym(inject):
        # Only the sym in the func should be relocated
        if int(rel_sym[0], 16) < int(start, 16) or int(rel_sym[0], 16) > int(end, 16):
            continue
        
        print rel_sym
        sym_addr = hex(int(rel_sym[0], 16) + int(text_addr, 16))
        sym_off = hex(int(rel_sym[0], 16) + int(text_off, 16))
        if rel_sym[2] == 'R_PPC_REL24':
            if rel_sym[1] not in target_plt_dict:
                print sym_off, rel_sym[1] + " not in " + target
                continue
            rel_dict[sym_addr] = (sym_off, target_plt_dict[rel_sym[1]], rel_sym[1], rel_sym[2])
        elif rel_sym[1].startswith('.rodata.'):
            print get_rodata_offset(inject, target)
            rodata_off = int(rel_sym[3], 16) + int(get_rodata_offset(inject, target), 16)
            if rel_sym[2] == 'R_PPC_ADDR16_HA':
                rel_dict[sym_addr] = (sym_off, hex((rodata_off >> 16) & 0xffff), rel_sym[1] + rel_sym[3], rel_sym[2])
            elif rel_sym[2] == 'R_PPC_ADDR16_LO':
                rel_dict[sym_addr] = (sym_off, hex(rodata_off & 0xffff), rel_sym[1] + rel_sym[3], rel_sym[2])
            else:
                print off, rel_sym[1] + rel_sym[3] + " not in " + target
    return rel_dict


def write_bin(fp, s):
    tmp = ''.join(map(lambda x: chr(int(x, 16)), [s[i*2:i*2+2] for i in range(len(s)/2)]))
    fp.write(tmp)

def fix_reloc(rel_dict, target):
    with open(target, 'rb+') as fp:
        for (c_addr, rel_info) in rel_dict.items():
            fp.seek(int(c_addr, 16))
            if rel_info[3] == 'R_PPC_REL24':
                instr = cal.gen_bl(cal.gen_off(int(rel_info[1], 16), int(rel_info[0], 16))).lstrip('0x')
                print rel_info[0], "%x" % fp.tell(), instr
                write_bin(fp, instr)
            elif rel_info[3] == 'R_PPC_ADDR16_HA' or rel_info[3] == 'R_PPC_ADDR16_LO':
                instr = "%04x" % int(rel_info[1], 16)
                print rel_info[0], "%x" % fp.tell(), instr
                write_bin(fp, instr)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Usage: %s inject target" % sys.argv[0]
        sys.exit(-1)

    inject = sys.argv[1]
    target = sys.argv[2]
    #gen_rel_sym(elf)
    func = "_Z13my_setOptionsv"
    (start, end) = get_func_range(inject, func)
    print (start, end)
    rel_dict = rel(inject, target, start, end)
    print rel_dict
    fix_reloc(rel_dict, target)
    '''for (c_addr, rel_info) in rel(inject, target, start, end).items():
        print (c_addr, rel_info)
        if rel_info[2] == 'R_PPC_REL24':
            print cal.gen_bl(cal.gen_off(int(rel_info[0], 16), int(c_addr, 16)))'''
