#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline .ko interface-surface triage (no arbitrary RE).

For each ET_REL module:
  * locate init function symbol(s), list DIRECT calls (via .rela.text / .rela.init.text)
  * list imported kernel symbols of interest (device/dir registration families)
  * dump suspicious strings (device node names, debugfs names)
Output: JSON + human readable text.
"""
import json, sys, os, re
from elftools.elf.elffile import ELFFile

INTEREST = [
    'misc_register', 'cdev_add', 'cdev_init', 'register_chrdev', 'alloc_chrdev_region',
    'device_create', 'device_create_with_groups', 'class_create', 'device_register',
    'debugfs_create_dir', 'debugfs_create_file', 'debugfs_create_u32', 'debugfs_create_bool',
    'debugfs_create_x32', 'debugfs_create_u8', 'debugfs_create_regset32',
    'sysfs_create_file', 'sysfs_create_group', 'sysfs_create_link', 'sysfs_create_bin_file',
    'netlink_kernel_create', 'proc_create', 'proc_create_single', 'proc_mkdir',
    'snd_card_new', 'snd_soc_register_component', 'snd_soc_register_codec',
    'snd_ctl_new1', 'snd_soc_add_component_controls', 'snd_soc_add_codec_controls',
    'input_register_device', 'platform_driver_register', 'i2c_add_driver',
    'remap_pfn_range', 'vm_insert_page', 'copy_from_user', 'copy_to_user',
    'simple_read_from_buffer', 'seq_open', 'single_open', 'kfifo_alloc',
    'request_firmware', 'of_property_read_u32', 'device_create_file',
    'register_netdev', 'regmap_write', 'snd_soc_component_write',
]

STR_PAT = re.compile(rb'[ -~]{3,80}')


def sym_ranges(elf):
    symtab = elf.get_section_by_name('.symtab')
    out = []
    if not symtab:
        return out
    for s in symtab.iter_symbols():
        if s['st_info']['type'] == 'STT_FUNC' and s['st_size'] and s['st_value']:
            out.append((s['st_value'], s['st_value'] + s['st_size'], s.name))
    return out


def rela_calls(elf, secname, ranges):
    """map relocation offset -> symbol name, grouped by enclosing function"""
    res = {}
    for sec in elf.iter_sections():
        if not sec.name.startswith('.rela' + secname):
            continue
        linked = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            off = r['r_offset']
            try:
                nm = linked.get_symbol(r['r_info_sym']).name
            except Exception:
                continue
            if not nm:
                continue
            for (a, b, fn) in ranges:
                if a <= off < b:
                    res.setdefault(fn, []).append((off, nm, r['r_info_type']))
                    break
    return res


def main(paths):
    report = {}
    for p in paths:
        try:
            with open(p, 'rb') as f:
                elf = ELFFile(f)
                ranges = sym_ranges(elf)
                imports = []
                for sec in elf.iter_sections():
                    if sec.name.startswith('.rela'):
                        linked = elf.get_section(sec['sh_link'])
                        for r in sec.iter_relocations():
                            nm = linked.get_symbol(r['r_info_sym']).name
                            if nm:
                                imports.append(nm)
                imports = sorted(set(imports))
                initfns = [n for (a, b, n) in ranges if n in ('init_module',) or n.endswith('_init')]
                calls = {}
                for secn in ('.text', '.init.text'):
                    if elf.get_section_by_name(secn):
                        calls.update(rela_calls(elf, secn, ranges))
                interesting = [s for s in imports if s in INTEREST]
                # strings
                strs = []
                for secn in ('.rodata', '.rodata.str1.1', '.init.rodata'):
                    sec = elf.get_section_by_name(secn)
                    if not sec:
                        continue
                    data = sec.data()
                    for m in STR_PAT.finditer(data):
                        s = m.group().decode('ascii', 'ignore')
                        strs.append(s)
                devnames = sorted(set([s for s in strs if re.search(r'(/dev/|^dbmdx|tfa98|ak4376|apr|wcd|q6|%s)' % '', s)]))
                # pick candidates that look like device or dir names
                cand = []
                for s in strs:
                    if re.match(r'^(dbmdx|tfa98|ak4376|apr|wcd|q6|msm_|llcc|rdbg|msm_q6)', s, re.I) and len(s) < 40:
                        cand.append(s)
                report[os.path.basename(p)] = {
                    'size': os.path.getsize(p),
                    'init_fns': initfns,
                    'init_calls': {k: [c[1] for c in v] for k, v in calls.items() if k in initfns},
                    'imports_interest': interesting,
                    'name_candidates': sorted(set(cand))[:60],
                }
        except Exception as e:
            report[os.path.basename(p)] = {'error': repr(e)}
    return report


if __name__ == '__main__':
    r = main(sys.argv[1:])
    print(json.dumps(r, indent=1, ensure_ascii=False))
