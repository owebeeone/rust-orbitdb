// Deterministic JS OrbitDB fixture generator (oracle) for rust-orbitdb.
// Deep-imports the oplog/identity layer from @orbitdb/core@4.0.0 to avoid the
// IPFS storage tier. Signatures are secp256k1 ECDSA (RFC6979 -> deterministic).
// Emits an array of conformance cases to stdout.
import { writeFileSync } from 'node:fs'
import Entry from '@orbitdb/core/src/oplog/entry.js'
import Log from '@orbitdb/core/src/oplog/log.js'
import Clock, { compareClocks } from '@orbitdb/core/src/oplog/clock.js'
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
const logId = 'log-1'

const keystore = await KeyStore({ storage: await MemoryStorage() })
const identities = await Identities({ keystore })

async function makeIdentity(idName, outerHex, innerHex) {
  await keystore.addKey(idName, { privateKey: hexToBytes(outerHex) })
  const p1 = u8ToString(privateKeyFromRaw(hexToBytes(outerHex)).publicKey.raw, 'base16')
  await keystore.addKey(p1, { privateKey: hexToBytes(innerHex) })
  const identity = await identities.createIdentity({ id: idName })
  return { identity, innerHex }
}

const A = await makeIdentity(
  'userA',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
)
const B = await makeIdentity(
  'userB',
  '1111111111111111111111111111111111111111111111111111111111111111',
  '2222222222222222222222222222222222222222222222222222222222222222'
)
// Backwards-compatible bindings used by the single-writer cases/logs below.
const identity = A.identity
const fixedPrivInner = hexToBytes(A.innerHex)
const id = 'userA'

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
    input: {
      logId,
      payload,
      identityId: id,
      time,
      next,
      refs,
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

// Clock comparison oracle: cmp is sign(compareClocks(a, b)) in {-1, 0, 1}.
const clockPair = (a, b, description) => ({
  description,
  a,
  b,
  cmp: Math.sign(compareClocks(a, b)),
})
const clocks = [
  clockPair({ id: 'aaa', time: 5 }, { id: 'aaa', time: 5 }, 'identical clock -> 0'),
  clockPair({ id: 'aaa', time: 5 }, { id: 'bbb', time: 5 }, 'same time, a.id < b.id -> -1'),
  clockPair({ id: 'bbb', time: 5 }, { id: 'aaa', time: 5 }, 'same time, a.id > b.id -> 1'),
  clockPair({ id: 'aaa', time: 5 }, { id: 'aaa', time: 7 }, 'a.time < b.time -> -1'),
  clockPair({ id: 'aaa', time: 9 }, { id: 'zzz', time: 2 }, 'time dominates id -> 1'),
  clockPair({ id: 'm', time: 0 }, { id: 'm', time: 1 }, 'time 0 vs 1 -> -1'),
]

// Log append oracle: append a sequence and record each entry's structure and
// the heads after each step. referencesCount defaults to 0, so refs stay empty
// (linear chain). Rust must reproduce next/refs/clock/cid and heads.
async function makeLog(description, payloads) {
  const log = await Log(identity, { logId: 'log-seq' })
  const steps = []
  for (const payload of payloads) {
    const e = await log.append(payload)
    const heads = await log.heads()
    steps.push({
      payload,
      cid: e.hash,
      next: e.next,
      refs: e.refs,
      clock: e.clock,
      headsAfter: heads.map((h) => h.hash),
    })
  }
  return {
    description,
    logId: 'log-seq',
    identityId: id,
    key: identity.publicKey,
    identityHash: identity.hash,
    innerPrivateKeyHex: u8ToString(fixedPrivInner, 'hex'),
    steps,
  }
}

const logs = [await makeLog('log/linear-append: a,b,c,d', ['a', 'b', 'c', 'd'])]

// Multi-writer join oracle: two writers append concurrently to the same logId
// (both at time 1, next []), A joins B (concurrent heads), then A appends a
// converging entry whose next covers both heads.
function entryRec(e) {
  return { payload: e.payload, cid: e.hash, next: e.next, refs: e.refs, clock: e.clock }
}
async function makeJoin(description) {
  const logA = await Log(A.identity, { logId: 'log-mw' })
  const logB = await Log(B.identity, { logId: 'log-mw' })
  const ea = await logA.append('from-A')
  const eb = await logB.append('from-B')
  await logA.join(logB)
  const headsAfterJoin = (await logA.heads()).map((h) => h.hash)
  const ec = await logA.append('converge')
  const headsAfterConverge = (await logA.heads()).map((h) => h.hash)
  return {
    description,
    logId: 'log-mw',
    writerA: { key: A.identity.publicKey, identityHash: A.identity.hash, innerPrivateKeyHex: A.innerHex },
    writerB: { key: B.identity.publicKey, identityHash: B.identity.hash, innerPrivateKeyHex: B.innerHex },
    ea: entryRec(ea),
    eb: entryRec(eb),
    headsAfterJoin,
    ec: entryRec(ec),
    headsAfterConverge,
  }
}

const joins = [await makeJoin('join/concurrent: A and B diverge, A joins B, then converge')]

// Refs / traverse oracle: a chain appended with referencesCount, recording each
// entry's skip-refs, plus the full traverse order (descending) and values
// order (ascending).
async function makeRefsLog(description, payloads, referencesCount) {
  const log = await Log(A.identity, { logId: 'log-refs' })
  const steps = []
  for (const payload of payloads) {
    const e = await log.append(payload, { referencesCount })
    steps.push({ payload, cid: e.hash, next: e.next, refs: e.refs, clock: e.clock })
  }
  const values = (await log.values()).map((e) => e.hash)
  const traverseOrder = []
  for await (const e of log.traverse()) {
    traverseOrder.push(e.hash)
  }
  return {
    description,
    logId: 'log-refs',
    key: A.identity.publicKey,
    identityHash: A.identity.hash,
    innerPrivateKeyHex: A.innerHex,
    referencesCount,
    steps,
    values,
    traverseOrder,
  }
}

const refsLogs = [
  await makeRefsLog('log/refs: 6 appends, referencesCount 2', ['a', 'b', 'c', 'd', 'e', 'f'], 2),
  await makeRefsLog('log/refs: 7 appends, referencesCount 3', ['a', 'b', 'c', 'd', 'e', 'f', 'g'], 3),
]

const outDir = new URL('./corpus/', import.meta.url)
writeFileSync(new URL('entries.json', outDir), JSON.stringify(cases, null, 2) + '\n')
writeFileSync(new URL('clocks.json', outDir), JSON.stringify(clocks, null, 2) + '\n')
writeFileSync(new URL('logs.json', outDir), JSON.stringify(logs, null, 2) + '\n')
writeFileSync(new URL('joins.json', outDir), JSON.stringify(joins, null, 2) + '\n')
writeFileSync(new URL('refs.json', outDir), JSON.stringify(refsLogs, null, 2) + '\n')
console.error(
  `wrote ${cases.length} entries, ${clocks.length} clocks, ${logs.length} logs, ${joins.length} joins, ${refsLogs.length} refs`
)
