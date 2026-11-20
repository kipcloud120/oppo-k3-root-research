#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build loaded/unloaded delta between /proc/modules (evidence) and modules.load (boot list).

Mapping is an explicit observed table (not a naming rule): lsmod name <- .ko file name.
Evidence source: artifacts_adb/k3_info2.txt §4 (32 rows) ; vendor_ko/modules.load (37 rows).
"""
import re, io, os

MAP = {
    'audio_apr.ko': 'apr_dlkm', 'audio_wglink.ko': 'wglink_dlkm',
    'audio_q6_pdr.ko': 'q6_pdr_dlkm', 'audio_q6_notifier.ko': 'q6_notifier_dlkm',
    'audio_adsp_loader.ko': 'adsp_loader_dlkm', 'audio_q6.ko': 'q6_dlkm',
    'audio_usf.ko': 'usf_dlkm', 'audio_pinctrl_wcd.ko': 'pinctrl_wcd_dlkm',
    'audio_pinctrl_lpi.ko': 'pinctrl_lpi_dlkm', 'audio_swr.ko': 'swr_dlkm',
    'audio_wcd_core.ko': 'wcd_core_dlkm', 'audio_swr_ctrl.ko': 'swr_ctrl_dlkm',
    'audio_wsa881x.ko': 'wsa881x_dlkm', 'audio_platform.ko': 'platform_dlkm',
    'audio_cpe_lsm.ko': 'cpe_lsm_dlkm', 'audio_hdmi.ko': 'hdmi_dlkm',
    'audio_stub.ko': 'stub_dlkm', 'audio_wcd9xxx.ko': 'wcd9xxx_dlkm',
    'audio_mbhc.ko': 'mbhc_dlkm', 'audio_wcd_spi.ko': 'wcd_spi_dlkm',
    'audio_wcd_cpe.ko': 'wcd_cpe_dlkm', 'audio_wcd9335.ko': 'wcd9335_dlkm',
    'audio_wcd934x.ko': 'wcd934x_dlkm', 'audio_digital_cdc.ko': 'digital_cdc_dlkm',
    'audio_analog_cdc.ko': 'analog_cdc_dlkm', 'audio_msm_sdw.ko': 'msm_sdw_dlkm',
    'audio_native.ko': 'native_dlkm', 'audio_machine_sdm710.ko': 'machine_dlkm',
    'llcc_perfmon.ko': 'llcc_perfmon', 'mpq-adapter.ko': 'mpq_adapter',
    'mpq-dmx-hw-plugin.ko': 'mpq_dmx_hw_plugin', 'audio_tfa98xx-v6.ko': 'tfa98xx_v6_dlkm',
    'audio_tfa98xx.ko': 'tfa98xx_dlkm', 'audio_ak4376.ko': 'ak4376_dlkm',
    'audio_dspg_dbmdx.ko': 'dspg_dbmdx_dlkm', 'qca_cld3_wlan.ko': 'wlan',
    'rdbg.ko': 'rdbg',
}


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    load = [l.strip() for l in io.open(os.path.join(root, 'vendor_ko', 'modules.load'), encoding='utf-8') if l.strip()]
    txt = io.open(os.path.join(root, 'artifacts_adb', 'k3_info2.txt'), encoding='utf-8', errors='ignore').read()
    m = re.search(r'===== 4\. 模块 /proc/modules =====(.*?)===== 5\.', txt, re.S)
    rows = [l.strip() for l in m.group(1).strip().splitlines() if l.strip()]
    live = []
    for r in rows:
        live.append(r.split()[0])
    out = []
    out.append('# loaded: %d   modules.load: %d   not loaded: %d' % (len(live), len(load), len(load) - len(live)))
    out.append('# lsmod_name\tko_file\tstate')
    live_set = set(live)
    seen = set()
    for ko in load:
        nm = MAP[ko]
        state = 'LOADED' if nm in live_set else 'NOT_LOADED'
        if nm in live_set:
            seen.add(nm)
        out.append('%s\t%s\t%s' % (nm, ko, state))
    extra = live_set - seen
    if extra:
        out.append('# UNMAPPED live names: ' + ','.join(sorted(extra)))
    print('\n'.join(out))
    io.open(os.path.join(root, 'artifacts_adb', 'vendor_triage', 'loaded_map.tsv'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
