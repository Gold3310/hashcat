#!/usr/bin/env python3
"""Static forensic pass over the pasted runtime bytecode + request addresses.
No network access, no chain calls. Reproducible from bytecode.hex alone."""
import re, sys
from Crypto.Hash import keccak
from eth_account import Account

HEX = open(__file__.replace("analyze.py", "bytecode.hex")).read().strip().lower()
assert re.fullmatch(r"[0-9a-f]+", HEX), "non-hex chars in blob"

def kec(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.hexdigest()

def sel(sig):
    return kec(sig.encode())[:8]

# ---------- 1. size / head underflow ----------
size = len(HEX) // 2
print(f"[size] {size} bytes runtime code ({len(HEX)} hex chars)")

first = HEX[0:2]; nxt = HEX[40:42]  # 0x72=PUSH19 (1+19 bytes) -> next opcode at byte 20
print(f"[head] first opcode 0x{first} (PUSH19), next opcode 0x{nxt} "
      f"({'EQ' if nxt=='14' else '??'}) with stack depth 1 -> "
      f"{'STACK UNDERFLOW: as pasted, every call halts' if nxt=='14' else 'no underflow'}")

# ---------- 2. dispatcher ----------
entries = re.findall(r"61([0-9a-f]{4})61([0-9a-f]{4})56", HEX[:4000])
ids = re.findall(r"6100([0-3][0-9a-f])50", HEX)
uniq = sorted(set(ids))
print(f"[dispatch] jump-threaded table entries: {len(entries)}; handler ids present: "
      f"{len(uniq)} (0x01..0x{uniq[-1]})")

# ---------- 3. address constants ----------
def push(nbytes):
    op = {20: "73", 19: "72", 15: "6e", 14: "6d"}[nbytes]
    return [(m.start() // 2, "0x" + m.group(1)) for m in re.finditer(op + r"([0-9a-f]{%d})" % (nbytes * 2), HEX)]

counts = {}
for nb in (20, 19, 15, 14):
    for _, a in push(nb):
        counts[a] = counts.get(a, 0) + 1
labels = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH9",
    "0xba12222222228d8ba445958a75a0704d566bf2c8": "Balancer V2 Vault",
    "0xbbcb91440523216e2b87052a99f69c604a7b6e00": "hardcoded operator",
    "0x000000000004444c5dc75cb358380d2e3de08a90": "Uniswap v4 PoolManager",
    "0xba1333333333a1ba1108e8412f11850a5c319ba9": "vanity ba1333..",
    "0x6690384822aff0b65fe0c21a809f187f5c3fcdd8": "vanity 6690..",
    "0x00000000000014aa86c5d3c41765bb24e11bd701": "Ekubo Protocol Core",
    "0xa1ea1ba18e88c381c724a75f23a130420c403f9a": "vanity a1ea1ba1..",
    "0xeef417e1d5cc832e619ae18d2f140de2999dd4fb": "vanity eef417..",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": "native sentinel 0xEeeE..",
    "0x196c00c1b00000000000007c00739ad9faa3ee77": "tx.origin allowlist EOA",
    "0x4b38217d000000001e4f000034a6f30026bf1c32": "PUSH19 (truncated EOA const)",
}
print("[addresses] (occurrences):")
for a, c in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"   {a}  x{c}  {labels.get(a, '')}")

# ---------- 4. selectors ----------
found = set()
for m in re.finditer(r"63([0-9a-f]{8})60[0-9a-f]{2}1b", HEX):
    found.add(m.group(1))
for m in re.finditer(r"7f([0-9a-f]{8})0{56}", HEX):
    found.add(m.group(1))
print(f"[selectors] distinct 4-byte selectors found: {len(found)}")

sigs = [
    "transfer(address,uint256)", "transferFrom(address,address,uint256)",
    "approve(address,uint256)", "allowance(address,address)", "balanceOf(address)",
    "deposit()", "withdraw(uint256)", "withdraw()",
    "swap(uint256,uint256,address,bytes)", "sync()", "getReserves()",
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "flashLoan(address,address[],uint256[],bytes)",
    "swap(bytes,(address,uint256,bytes)[],(address,bool,uint256)[],int256,uint256)",
    "batchSwap(bytes,(address,address,uint256,uint256)[],(address,bool,uint256)[],(address,uint256,bytes)[],int256[],uint256)",
    "manageUserBalance(bytes)",
    "unlock(bytes)", "unlockCallback(bytes)",
    "sync()", "settle()", "settleFor(address)", "take(address,uint256,address)",
    "clear(address,uint256)", "mint(address,uint256,bytes)", "burn(address,uint256)",
    "swap((address,address,uint24,int24,address),bool,int256,uint160,bytes)",
    "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32,bytes),bytes)",
    "donate((address,address,uint24,int24,address),uint256)",
    "initialize((address,address,uint24,int24,address),uint160)",
    "extsload(bytes)", "execute(bytes,bytes)", "execute(bytes,bytes[],uint256)",
]
decode = {sel(s): s for s in sigs}
decoded = {s: decode[s] for s in sorted(found) if s in decode}
print("[selectors] keccak-verified decodes:")
for s in sorted(found):
    print(f"   0x{s}  {decode.get(s, '(unresolved)')}")

# ---------- 5. owner-management selectors absent? ----------
owner_fns = ["transferOwnership(address)", "renounceOwnership()", "owner()",
             "setOwner(address)", "grantRole(bytes32,address)", "revokeRole(bytes32,address)",
             "setAuthority(address)", "addOwner(address)", "updateOwner(address)",
             "pendingOwner()", "claimOwnership()", "setAdmin(address)"]
absent = True
for f in owner_fns:
    s = sel(f)
    if s in found or s in HEX:
        print(f"[owner] FOUND {f} = 0x{s}"); absent = False
if absent:
    print("[owner] none of the 12 owner-management selectors appear anywhere in the bytecode")

# ---------- 6. approvals of max uint256 ----------
maxu = "f" * 64
n_approve = len(re.findall(r"7f095ea7b3" + "0" * 56, HEX)) + len(re.findall(r"63095ea7b360e01b", HEX))
n_max = HEX.count("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
print(f"[approve] approve() selector sites: {n_approve}; MAX_UINT256 constants (unlimited approve amounts): {n_max}")

# ---------- 7. footer token table ----------
tail = HEX[-64 * 10:]
print("[footer] 32-byte words in appended data table:")
for i in range(0, len(tail), 64):
    w = tail[i:i + 64]
    v = w.lstrip("0")
    print(f"   word{i//64}: {'0x000...'+v[-10:] if len(v)>10 else '0x'+(v or '0')}  "
          f"({'addr 0x'+w[24:] if w[:24]=='0'*24 and len(v)>36 else 'const'})")

# ---------- 8. EIP-55 checksum of user-supplied addresses ----------
def eip55_ok(addr):
    a = addr.lower().replace("0x", "")
    h = kec(a.encode())
    out = ""
    for i, ch in enumerate(a):
        out += ch.upper() if int(h[i], 16) >= 8 else ch
    return out == addr.replace("0x", "")
for label, a in [
    ("requested deploy target", "0x009A8DBaD7000f0000009b002d050058CA881b57"),
    ("requested new owner A", "0x795b5cf27e01b89959f33a8042472f30e3fe6660"),
    ("requested new owner B", "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199"),
]:
    print(f"[eip55] {label} {a}: checksum {'VALID' if eip55_ok(a) else 'INVALID (hand-typed?)'}")

# ---------- 9. public test-mnemonic derivation ----------
mns = {
    "hardhat/foundry/anvil 'test..junk'": "test test test test test test test test test test test junk",
    "bip39 'abandon..about'": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "ganache 'candy maple..'": "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    "ganache-old 'myth like..'": "myth like bonus scare over problem client lizard pioneer submit female collect",
}
targets = {
    "0x795b5cf27e01b89959f33a8042472f30e3fe6660": "requested new owner A",
    "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199": "requested new owner B",
    "0xbbcb91440523216e2b87052a99f69c604a7b6e00": "hardcoded operator",
    "0x196c00c1b00000000000007c00739ad9faa3ee77": "tx.origin allowlist EOA",
    "0x009a8dbad7000f0000009b002d050058ca881b57": "requested deploy target",
}
Account.enable_unaudited_hdwallet_features()
print("[mnemonic] scanning 4 public dev mnemonics x 100 indices...")
hits = []
for name, m in mns.items():
    for i in range(100):
        a = Account.from_mnemonic(m, account_path=f"m/44'/60'/0'/0/{i}").address.lower()
        if a in targets:
            hits.append((targets[a], a, name, i))
for t, a, n, i in hits:
    print(f"   MATCH: {t} = {a}  == {n} account #{i}")
if not hits:
    print("   no matches")
