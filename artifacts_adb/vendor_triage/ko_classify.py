#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Classify every vendor .ko by user-facing registration imports + module_init direct calls."""
import json, os, sys, glob
from elftools.elf.elffile import ELFFile

CAT = {
    'chrdev': ['misc_register', 'cdev_add', 'cdev_init', 'register_chrdev', 'alloc_chrdev_region'],
    'devnode': ['device_create', 'device_create_with_groups', 'class_create'],
    'debugfs': ['debugfs_create_dir', 'debugfs_create_file', 'debugfs_create_u32', 'debugfs_create_bool',
                'debugfs_create_u8', 'debugfs_create_x32', 'debugfs_create_regset32'],
    'sysfs': ['sysfs_create_file', 'sysfs_create_group', 'sysfs_create_bin_file', 'sysfs_create_link',
              'device_create_file', 'device_create_bin_file'],
    'netlink': ['netlink_kernel_create', 'netlink_kernel_cfg', 'genl_register_family'],
    'procfs': ['proc_mkdir', 'proc_create', 'proc_create_data', 'proc_create_single'],
    'input': ['input_register_device'],
    'alsa': ['snd_soc_register_codec', 'snd_soc_register_component', 'snd_card_new', 'snd_pcm_new'],
}


def funcs(elf):
    st = elf.get_section_by_name('.symtab')
    if not st:
        return []
    return [(s['st_value'], s['st_value'] + s['st_size'], s.name) for s in st.iter_symbols()
            if s['st_info']['type'] == 'STT_FUNC' and s['st_size'] and s['st_value']]


def main(pattern):
    rows = {}
    for p in sorted(glob.glob(pattern)):
        with open(p, 'rb') as f:
            e = ELFFile(f)
            fs = funcs(e)
            imported = set()
            init_calls = set()
            initfns = set(n for (a, b, n) in fs if n == 'init_module')
            for sec in e.iter_sections():
                if not sec.name.startswith('.rela'):
                    continue
                lnk = e.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    nm = lnk.get_symbol(r['r_info_sym']).name
                    if not nm:
                        continue
                    imported.add(nm)
                    if initfns:
                        for (a, b, fn) in fs:
                            if fn in initfns and a <= r['r_offset'] < b:
                                init_calls.add(nm)
                                break
            cats = {}
            for c, syms in CAT.items():
                hit = sorted(set(imported) & set(syms))
                if hit:
                    cats[c] = hit
            rows[os.path.basename(p)] = {
                'init_fns': sorted(initfns),
                'init_calls_interest': sorted(set([s for s in init_calls if s in sum(CAT.values(), [])])),
                'categories': cats,
            }
    return rows


if __name__ == '__main__':
    r = main(sys.argv[1] if len(sys.argv) > 1 else '_img/lib/modules/*.ko')
    json.dump(r, open('ko_surface_all.json', 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    for k, v in r.items():
        print('%-26s %-28s %s' % (k.replace('.ko', ''), ','.join(sorted(v['categories'].keys())) or '-',
                                   ('init:' + ','.join([s.replace('debugfs_create_', 'dbg:') for s in v['init_calls_interest']])) if v['init_calls_interest'] else ''))
