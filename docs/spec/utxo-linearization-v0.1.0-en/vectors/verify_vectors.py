#!/usr/bin/env python3
"""Check v0.1.0 state/caboose vectors. Does not execute Bitcoin Script."""
import hashlib
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).digest()


def parse_state(data):
    require(len(data) >= 9, 'short envelope')
    require(data[:7] == b'UTXOLIN', 'magic')
    require(data[7] == 1, 'version')
    phase = data[8]
    require(phase in (0, 1), 'phase')
    require(len(data) == (41 if phase == 0 else 73), 'length')
    return phase, (data[9:41] if phase else None), data[-32:]


def caboose(state, randomizer):
    require(0 <= randomizer <= 0xffffffff, 'randomizer range')
    wscript = b'\x6a\x24' + sha(state) + randomizer.to_bytes(4, 'little')
    return wscript, b'\x00\x20' + sha(wscript)


def main():
    path = Path(__file__).with_name('encoding-vectors.json')
    obj = json.loads(path.read_text(encoding='utf-8'))
    require(obj['version'] == '0.1.0', 'vector version')
    vectors = {v['name']: v for v in obj['valid']}
    count = 0
    for item in obj['valid']:
        state = bytes.fromhex(item['state_hex'])
        phase, gid, root = parse_state(state)
        require(phase == (0 if item['phase'] == 'GENESIS' else 1), 'phase value')
        require(root == sha(item['application_utf8'].encode('utf-8')), 'example app root')
        require(root.hex() == item['application_root_hex'], 'app root bytes')
        require(len(state) == item['state_length'], 'state length')
        require(sha(state).hex() == item['state_hash_hex'], 'state hash')
        require((gid.hex() if gid is not None else None) == item['genesis_id_wire_hex'], 'wire id')
        require((gid[::-1].hex() if gid is not None else None) == item['genesis_id_display_hex'], 'display id')
        wscript, spk = caboose(state, item['randomizer_uint32'])
        require(len(wscript) == item['witness_script_length'] == 38, 'witnessScript length')
        require(len(spk) == item['script_pubkey_length'] == 34, 'scriptPubKey length')
        require(wscript.hex() == item['witness_script_hex'], 'witnessScript bytes')
        require(spk.hex() == item['script_pubkey_hex'], 'scriptPubKey bytes')
        count += 1
    for item in obj['invalid_state_encodings']:
        try:
            parse_state(bytes.fromhex(item['state_hex']))
        except ValueError:
            pass
        else:
            raise ValueError('invalid state accepted: ' + item['name'])
        count += 1
    for item in obj['invalid_commitment_openings']:
        state = bytes.fromhex(item['provided_state_hex'])
        parse_state(state)
        _, actual = caboose(state, item['provided_randomizer_uint32'])
        expected = bytes.fromhex(vectors[item['vector']]['script_pubkey_hex'])
        require(actual != expected, 'altered opening matched: ' + item['name'])
        count += 1
    for item in obj['identity_comparisons']:
        state = bytes.fromhex(vectors[item['vector']]['state_hex'])
        _, gid, _ = parse_state(state)
        match = gid == bytes.fromhex(item['expected_id_wire_hex'])
        require(match == (item['expected'] == 'match'), 'identity comparison')
        count += 1
    print(f'PASS: {count} encoding, commitment and identity-comparison cases.')
    print('Scope: bytes and hashes only; no Bitcoin Script or lineage verification.')


if __name__ == '__main__':
    main()
