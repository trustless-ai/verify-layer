// ─────────────────────────────────────────────────────────────────────────────
// trustless-ai wallet · verify-don't-trust layer (sketch, v0)
//
// A normal wallet TRUSTS the RPC's answer for a balance. This PROVES it: we take
// the RPC's eth_getProof (an EIP-1186 Merkle-Patricia proof of the account) and
// verify it against the block's stateRoot — so a lying RPC cannot forge a balance
// without breaking keccak.
//
// The trust boundary, stated honestly:
//   • The block HEADER (hence stateRoot) here still comes from the RPC. A full
//     trustless client gets the header from a consensus light client (sync
//     committee), removing that last trust. Swapping the header source is the
//     ONLY remaining step to full trustlessness — the state proof below is done.
//   • Given a stateRoot, the ACCOUNT STATE is proven, not trusted.
//
// Two independent defenses, both demonstrated below with prove-it-can-fail:
//   (A) BINDING   — keccak(proof[0]) must equal the block's stateRoot. Stops an
//                   RPC handing a self-consistent proof rooted at a fake state.
//   (B) MPT PROOF — the Merkle-Patricia path for keccak(address) must verify.
//                   Stops any tampered node / forged balance.
// ─────────────────────────────────────────────────────────────────────────────
import { keccak_256 } from '@noble/hashes/sha3.js';
import { RLP } from '@ethereumjs/rlp';
import { hexToBytes, bytesToHex, bytesToBigInt, equalsBytes, setLengthLeft, bigIntToBytes } from '@ethereumjs/util';
import { verifyMerkleProof } from '@ethereumjs/mpt';
import fs from 'node:fs';

const keccak = (b) => keccak_256(b);
const KEY = fs.readFileSync(process.env.HOME + '/.claude/alchemy_key', 'utf8').trim();
const RPC = `https://eth-mainnet.g.alchemy.com/v2/${KEY}`;

async function rpc(method, params) {
  const r = await fetch(RPC, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

// Core: verify an account against a KNOWN stateRoot. Returns the proven account,
// or throws (invalid MPT proof), or {boundToHeader:false} (proof roots elsewhere).
async function checkAccountProof(expectedStateRoot, address, accountProofBytes) {
  // (A) BINDING — the proof's top node must hash to the header's stateRoot.
  const boundToHeader = equalsBytes(keccak(accountProofBytes[0]), expectedStateRoot);

  // (B) MPT PROOF — verify the Merkle-Patricia path for keccak(address).
  const key = keccak(hexToBytes(address));
  const value = await verifyMerkleProof(key, accountProofBytes); // throws if tampered; null = non-existence

  let proven = null;
  if (value !== null) {
    const [nonce, balance, storageRoot, codeHash] = RLP.decode(value);
    proven = {
      nonce: bytesToBigInt(nonce),
      balance: bytesToBigInt(balance),
      storageRoot: bytesToHex(storageRoot),
      codeHash: bytesToHex(codeHash),
    };
  }
  return { boundToHeader, proven };
}

async function verifyAccount(address, blockTag = 'finalized') {
  const block = await rpc('eth_getBlockByNumber', [blockTag, false]);
  const res = await rpc('eth_getProof', [address, [], block.number]);
  const stateRoot = hexToBytes(block.stateRoot);
  const accountProof = res.accountProof.map(hexToBytes);
  const { boundToHeader, proven } = await checkAccountProof(stateRoot, address, accountProof);

  // Cross-check: does the RPC's own claimed balance match what the PROOF proves?
  const claimedBalance = BigInt(res.balance);
  const provenBalance = proven ? proven.balance : 0n;
  const claimMatchesProof = claimedBalance === provenBalance;

  return {
    verified: boundToHeader && claimMatchesProof,
    address, block: BigInt(block.number), stateRoot: block.stateRoot,
    boundToHeader, claimMatchesProof,
    provenBalanceWei: provenBalance, provenBalanceEth: Number(provenBalance) / 1e18,
    proven, raw: { block, res, accountProof, stateRoot },
  };
}

// Verify a STORAGE slot — chains proof-of-custody: state root → account.storageRoot → slot value.
// (Token balances are just a storage slot: keccak(pad32(holder) ++ pad32(mappingSlot)).)
async function verifyStorage(address, slot, blockTag = 'finalized') {
  const block = await rpc('eth_getBlockByNumber', [blockTag, false]);
  const slotHex = bytesToHex(setLengthLeft(bigIntToBytes(BigInt(slot)), 32));
  const res = await rpc('eth_getProof', [address, [slotHex], block.number]);
  const stateRoot = hexToBytes(block.stateRoot);
  const accountProof = res.accountProof.map(hexToBytes);
  const { boundToHeader, proven } = await checkAccountProof(stateRoot, address, accountProof); // → storageRoot
  const storageRoot = hexToBytes(proven.storageRoot);

  const sp = res.storageProof[0];
  const sProof = sp.proof.map(hexToBytes);
  const storageKey = keccak(setLengthLeft(bigIntToBytes(BigInt(slot)), 32));
  const boundToAccount = equalsBytes(keccak(sProof[0]), storageRoot); // storage proof roots at account.storageRoot
  const leaf = await verifyMerkleProof(storageKey, sProof);           // throws if tampered
  const provenValue = leaf === null ? 0n : bytesToBigInt(RLP.decode(leaf));

  return {
    verified: boundToHeader && boundToAccount && provenValue === BigInt(sp.value),
    slot: BigInt(slot), provenValue, claimed: BigInt(sp.value),
    boundToHeader, boundToAccount, block: BigInt(block.number),
  };
}

const fmt = (b) => `${b} wei  (${(Number(b) / 1e18).toFixed(4)} ETH)`;

async function main() {
  const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'; // holds all wrapped ETH — visible balance
  console.log('trustless-ai · verify-don\'t-trust layer (v0)\n');

  // ── 1) HONEST PATH — prove the balance ───────────────────────────────────────
  const r = await verifyAccount(WETH);
  console.log(`account   ${r.address}`);
  console.log(`block     #${r.block}   stateRoot ${r.stateRoot}`);
  console.log(`PROVEN    balance = ${fmt(r.provenBalanceWei)}   nonce=${r.proven.nonce}`);
  console.log(`bound to header stateRoot?  ${r.boundToHeader ? 'YES' : 'NO'}`);
  console.log(`RPC-claimed balance matches PROVEN?  ${r.claimMatchesProof ? 'YES' : 'NO'}`);
  console.log(`==> ${r.verified ? '✅ VERIFIED (proven, not trusted)' : '❌ REJECTED'}\n`);

  // ── 2) prove-it-can-fail A: forged state root (RPC roots the proof elsewhere) ─
  const wrongRoot = hexToBytes(r.stateRoot); wrongRoot[0] ^= 0x01; // flip one bit of the expected root
  const a = await checkAccountProof(wrongRoot, r.address, r.raw.accountProof);
  console.log(`[tamper A] verify against a WRONG stateRoot (1 bit flipped):`);
  console.log(`  bound to header?  ${a.boundToHeader ? 'YES' : 'NO'}  ==> ${a.boundToHeader ? '❌ (should reject!)' : '✅ REJECTED (binding caught it)'}\n`);

  // ── 3) prove-it-can-fail B: tampered proof node (forge the balance) ───────────
  const tampered = r.raw.accountProof.map((n) => Uint8Array.from(n));
  tampered[tampered.length - 1][5] ^= 0x01; // corrupt a byte inside the account LEAF node
  let rejectedB = false, note = '';
  try {
    const b = await checkAccountProof(r.raw.stateRoot, r.address, tampered);
    // if it didn't throw, the tampered leaf no longer hashes into its parent → verify returns null/other
    rejectedB = !(b.boundToHeader && b.proven && b.proven.balance === r.provenBalanceWei);
    note = b.proven ? `proven balance now ${fmt(b.proven.balance)}` : 'proof no longer resolves the account';
  } catch (e) {
    rejectedB = true; note = 'MPT verification threw: ' + e.message.split('\n')[0].slice(0, 80);
  }
  console.log(`[tamper B] corrupt one byte inside the account leaf node:`);
  console.log(`  ${note}`);
  console.log(`  ==> ${rejectedB ? '✅ REJECTED (MPT proof caught it)' : '❌ (should reject!)'}\n`);

  // ── 4) STORAGE proof — verify a contract variable, chained state→account→slot ──
  const s = await verifyStorage(WETH, 2); // WETH9 slot 2 = decimals (18)
  console.log(`[storage] WETH slot 2 (decimals):  proven=${s.provenValue}  RPC-claimed=${s.claimed}`);
  console.log(`  chain of custody: header→account.storageRoot→slot  = ${s.boundToHeader && s.boundToAccount ? 'intact' : 'BROKEN'}`);
  console.log(`  ==> ${s.verified ? '✅ VERIFIED (storage proven, not trusted)' : '❌ REJECTED'}\n`);

  console.log(`trust tier: PROOF-VERIFIED state @ stateRoot#${r.block}`);
  console.log(`  (header from RPC in this v0 — swap header source for a consensus light client = full trustless)`);
}
main().catch((e) => { console.error('ERROR', e); process.exit(1); });
