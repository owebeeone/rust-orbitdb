// Deterministic JS OrbitDB fixture generator (oracle) for rust-orbitdb.
// Deep-imports the oplog/identity layer from @orbitdb/core@4.0.0 to avoid the
// IPFS storage tier. Signatures are secp256k1 ECDSA (RFC6979 -> deterministic).
import Entry from '@orbitdb/core/src/oplog/entry.js'
import Identities from '@orbitdb/core/src/identities/identities.js'
import KeyStore from '@orbitdb/core/src/key-store.js'
import MemoryStorage from '@orbitdb/core/src/storage/memory.js'
import { toString as u8ToString } from 'uint8arrays/to-string'
import { privateKeyFromRaw } from '@libp2p/crypto/keys'
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'

const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map(b => parseInt(b, 16)))

// The publickey identity provider uses a two-key scheme:
//   getId('userA')  -> base16(pubkey of key['userA'])  == P1
//   the identity's signing key is then keyed under P1.
// Both must be seeded with fixed scalars for reproducible identities/signatures.
const fixedPrivOuter = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
const fixedPrivInner = hexToBytes('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210')
const id = 'userA'

const keystore = await KeyStore({ storage: await MemoryStorage() })
await keystore.addKey(id, { privateKey: fixedPrivOuter })
const p1 = u8ToString(privateKeyFromRaw(fixedPrivOuter).publicKey.raw, 'base16')
await keystore.addKey(p1, { privateKey: fixedPrivInner })
const identities = await Identities({ keystore })
const identity = await identities.createIdentity({ id })

const entry = await Entry.create(identity, 'log-1', 'hello')
const { bytes, hash } = await Entry.encode(entry)

// The signed message is the entry WITHOUT key/sig/identity (see entry.js create).
// @libp2p/crypto secp256k1 signs sha256(signedBytes), DER-encoded.
const signedValue = { id: 'log-1', payload: 'hello', next: [], refs: [], clock: entry.clock, v: 2 }
const { bytes: signedBytes } = await Block.encode({ value: signedValue, codec: dagCbor, hasher: sha256 })

const fixture = {
  description: 'entry/create: single PUT-less payload "hello" on log-1, fixed key',
  input: {
    logId: 'log-1',
    payload: 'hello',
    identityId: id,
    outerPrivateKeyHex: u8ToString(fixedPrivOuter, 'hex'),
    innerPrivateKeyHex: u8ToString(fixedPrivInner, 'hex'),
  },
  expected: {
    v: entry.v,
    payload: entry.payload,
    clock: entry.clock,
    next: entry.next,
    refs: entry.refs,
    key: entry.key,
    identity: entry.identity,
    sig: entry.sig,
    cid: hash,
    bytesHex: u8ToString(bytes, 'hex'),
    signedBytesHex: u8ToString(signedBytes, 'hex'),
  },
}
console.log(JSON.stringify(fixture, null, 2))
