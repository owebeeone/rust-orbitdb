// Deterministic JS OrbitDB fixture generator (oracle) for rust-orbitdb.
// Deep-imports the oplog/identity layer from @orbitdb/core@4.0.0 to avoid the
// IPFS storage tier. Signatures are secp256k1 ECDSA (RFC6979 -> deterministic).
import Entry from '@orbitdb/core/src/oplog/entry.js'
import Identities from '@orbitdb/core/src/identities/identities.js'
import KeyStore from '@orbitdb/core/src/key-store.js'
import MemoryStorage from '@orbitdb/core/src/storage/memory.js'
import { toString as u8ToString } from 'uint8arrays/to-string'

// Fixed 32-byte secp256k1 private scalar -> reproducible identity + signatures.
const fixedPriv = Uint8Array.from(
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'.match(/../g).map(h => parseInt(h, 16))
)
const id = 'userA'

const keystore = await KeyStore({ storage: await MemoryStorage() })
await keystore.addKey(id, { privateKey: fixedPriv })
const identities = await Identities({ keystore })
const identity = await identities.createIdentity({ id })

const entry = await Entry.create(identity, 'log-1', 'hello')
const { bytes, hash } = await Entry.encode(entry)

const fixture = {
  description: 'entry/create: single PUT-less payload "hello" on log-1, fixed key',
  input: { logId: 'log-1', payload: 'hello', identityId: id, privateKeyHex: u8ToString(fixedPriv, 'hex') },
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
  },
}
console.log(JSON.stringify(fixture, null, 2))
