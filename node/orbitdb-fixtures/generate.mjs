// Deterministic JS OrbitDB fixture generator (oracle) for rust-orbitdb.
// Deep-imports the oplog/identity layer from @orbitdb/core@4.0.0 to avoid the
// IPFS storage tier. Signatures are secp256k1 ECDSA (RFC6979 -> deterministic).
// Emits an array of conformance cases to stdout.
import Entry from '@orbitdb/core/src/oplog/entry.js'
import Clock from '@orbitdb/core/src/oplog/clock.js'
import Identities from '@orbitdb/core/src/identities/identities.js'
import KeyStore from '@orbitdb/core/src/key-store.js'
import MemoryStorage from '@orbitdb/core/src/storage/memory.js'
import { toString as u8ToString } from 'uint8arrays/to-string'
import { privateKeyFromRaw } from '@libp2p/crypto/keys'
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'

const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map(b => parseInt(b, 16)))
const hex = (u8) => u8ToString(u8, 'hex')

// The publickey identity provider uses a two-key scheme:
//   getId('userA') -> base16(pubkey of key['userA']) == P1
//   the identity's signing key is then keyed under P1.
// Both must be seeded with fixed scalars for reproducible identities/signatures.
const fixedPrivOuter = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
const fixedPrivInner = hexToBytes('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210')
const id = 'userA'
const logId = 'log-1'

const keystore = await KeyStore({ storage: await MemoryStorage() })
await keystore.addKey(id, { privateKey: fixedPrivOuter })
const p1 = u8ToString(privateKeyFromRaw(fixedPrivOuter).publicKey.raw, 'base16')
await keystore.addKey(p1, { privateKey: fixedPrivInner })
const identities = await Identities({ keystore })
const identity = await identities.createIdentity({ id })

// Build one fixture case from an entry's inputs.
async function makeCase(description, payload, { time = 0, next = [], refs = [] } = {}) {
  const clock = Clock(identity.publicKey, time)
  const entry = await Entry.create(identity, logId, payload, null, clock, next, refs)
  const { bytes, hash } = await Entry.encode(entry)

  // The signed message is the entry WITHOUT key/sig/identity (see entry.js create).
  const signedValue = { id: logId, payload, next, refs, clock: entry.clock, v: 2 }
  const { bytes: signedBytes } = await Block.encode({ value: signedValue, codec: dagCbor, hasher: sha256 })

  return {
    description,
    input: { logId, payload, identityId: id, time, next, refs },
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
      bytesHex: hex(bytes),
      signedBytesHex: hex(signedBytes),
    },
  }
}

// A real prior CID to use in next/refs.
const parent = await makeCase('entry/parent: plain payload for use as a next/ref target', 'parent')
const parentCid = parent.expected.cid

const cases = [
  await makeCase('entry/create-hello: string payload, empty next/refs, time 0', 'hello'),
  // Object payload whose key orders differ between lexicographic and dag-cbor
  // canonical (length-first): top-level op(2),key(3),value(5); nested z(1),aa(2).
  await makeCase(
    'entry/object-payload: map payload, canonical key ordering at two levels',
    { op: 'PUT', key: 'k1', value: { z: 1, aa: 2 } }
  ),
  await makeCase('entry/with-next-refs: non-empty next and refs, time 1', 'child', {
    time: 1,
    next: [parentCid],
    refs: [parentCid],
  }),
  await makeCase('entry/clock-time: multi-byte clock time (>23)', 'tick', { time: 42 }),
]

console.log(JSON.stringify(cases, null, 2))
