using Chilkat;
using System.Net;
using System.Text;
using System.Text.Json;
using PublicKey = Chilkat.PublicKey;

namespace BlockChain;   

// This file implements a minimal Proof-of-Authority (PoA) blockchain prototype with:
// - Crypto helpers (Chilkat-based) for hashing, ECDSA signing/verification, address derivation (P2PKH & Bech32 P2WPKH).
// - DER/SPKI parsing for EC public keys and SEC1 compression.
// - Minimal CBOR encoder for realistic transaction size measurement.
// - UTXO-based transaction model with fee-rate enforced mempool selection.
// - PoA chain with round-robin leader, quorum signatures, and Merkle root validation.
// - Minimal HTTP JSON RPC for inspecting chain/mempool/UTXO and submitting transactions.

#region Crypto + Address utils (SEC1 compressed, Base58Check, Bech32) — Chilkat
public static class Crypto
{
    // Returns a Chilkat Crypt2 configured for SHA-256 with hex output.
    public static Crypt2 SHA256()
    { var c = new Crypt2 { HashAlgorithm = "sha256", EncodingMode = "hex" }; return c; }

    // Returns a Chilkat Crypt2 configured for RIPEMD-160 with hex output.
    public static Crypt2 RIPEMD160()
    { var c = new Crypt2 { HashAlgorithm = "ripemd160", EncodingMode = "hex" }; return c; }

    // Computes SHA-256 of a string (ENC mode hex).
    public static string Sha256Hex(string s) => SHA256().HashStringENC(s);

    // Computes SHA-256 of raw bytes; returns raw bytes.
    public static byte[] Sha256Bytes(byte[] data)
    { var c = new Crypt2 { HashAlgorithm = "sha256", EncodingMode = "hex" }; return c.HashBytes(data); }

    // Double-SHA256 (useful for Base58Check checksum).
    public static byte[] DblSha256(byte[] data) => Sha256Bytes(Sha256Bytes(data));

    // Bitcoin-style HASH160 = RIPEMD160(SHA256(data)).
    public static byte[] Hash160(byte[] data)
    { var sha = new Crypt2 { HashAlgorithm = "sha256" }; var inter = sha.HashBytes(data); var rip = new Crypt2 { HashAlgorithm = "ripemd160" }; return rip.HashBytes(inter); }

    // Hex <-> bytes helpers.
    public static byte[] HexToBytes(string hex)
    { int len = hex.Length; var b = new byte[len / 2]; for (int i = 0; i < len; i += 2) b[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16); return b; }
    public static string BytesToHex(byte[] data)
    { var sb = new System.Text.StringBuilder(data.Length * 2); foreach (var b in data) sb.Append(b.ToString("x2")); return sb.ToString(); }

    // Generates a secp256k1 EC keypair. Private key returned as PKCS#8 PEM (optionally encrypted), public key as PEM (SPKI).
    public static (string privPem, string pubPem) GenKey(string password = "")
    {
        var ecc = new Ecc(); var prng = new Prng();
        var priv = ecc.GenEccKey("secp256k1", prng) ?? throw new Exception("Keygen failed");
        string privPem = string.IsNullOrEmpty(password) ? priv.GetPkcs8Pem() : priv.GetPkcs8EncryptedPem(password);
        string pubPem = priv.GetPublicKey().GetPem(true);
        return (privPem, pubPem);
    }

    // Signs a precomputed hash (hex) with a private key (PEM or DER). Returns signature as base64 (Chilkat ASN.1 ECDSA).
    public static string SignHashHex(string hashHex, string keyDataPemOrDer, string password = "")
    {
        var priv = ChilkatCompat.LoadPrivateKeyFlexible(keyDataPemOrDer, password);
        var hash = HexToBytes(hashHex);
        return ChilkatCompat.SignHashToBase64(hash, priv);
    }

    // Verifies a signature (base64) over a precomputed hash (hex), using a public key PEM (SPKI).
    public static bool VerifyHashHex(string hashHex, string derB64, string pubPem)
    {
        var pub = new PublicKey(); if (!pub.LoadFromString(pubPem)) return false;
        return ChilkatCompat.VerifyHashFromBase64(HexToBytes(hashHex), derB64, pub);
    }
}

// Chilkat compatibility layer to handle API differences across versions/builds.
// Only uses stable APIs in this variant; throws with detailed LastErrorText if an operation fails.
public static class ChilkatCompat
{
    // Loads a private key from PEM (encrypted or plain) or DER (base64/hex PKCS#8).
    public static PrivateKey LoadPrivateKeyFlexible(string keyData, string password)
    {
        var priv = new PrivateKey();
        bool looksPem = keyData.Contains("-----BEGIN");
        if (looksPem)
        {
            // PEM (encrypted or plain)
            if (!string.IsNullOrEmpty(password))
            {
                if (!priv.LoadEncryptedPem(keyData, password))
                {
                    throw new Exception("Load PEM failed: " + priv.LastErrorText);
                }
            }
            else
            {
                if (!priv.LoadPem(keyData))
                {
                    throw new Exception("Load PEM failed: " + priv.LastErrorText);
                }
            }

            return priv;
        }

        // DER PKCS#8 in base64 or hex
        byte[] der;
        try { der = Convert.FromBase64String(keyData.Trim()); }
        catch
        {
            string hex = keyData.Trim(); if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
            if (hex.Length % 2 == 1) throw new Exception("DER hex length must be even");
            der = Crypto.HexToBytes(hex);
        }

        if (priv.LoadPkcs8(der)) return priv;
        throw new Exception("Unable to load DER: " + priv.LastErrorText);
    }

    // Signs a raw hash (32 bytes for SHA-256) over secp256k1. Returns base64 signature. Throws if Chilkat reports an error.
    public static string SignHashToBase64(byte[] hash, PrivateKey priv)
    {
        var ecc = new Ecc();
        string hashB64 = Convert.ToBase64String(hash);

        string sigB64 = ecc.SignHashENC(hashB64, "base64", priv, new Prng());
        if (string.IsNullOrEmpty(sigB64))
            throw new Exception("SignHashENC failed: " + ecc.LastErrorText);

        return sigB64;
    }

    // Verifies a base64 signature over a raw hash. Returns true if valid. Throws on Chilkat error (rc < 0).
    public static bool VerifyHashFromBase64(byte[] hash, string sigB64, PublicKey pub)
    {
        var ecc = new Ecc();
        string hashB64 = Convert.ToBase64String(hash);

        // Chilkat returns: 1 = valid, 0 = invalid, -1 = error
        int rc = ecc.VerifyHashENC(hashB64, sigB64, "base64", pub);
        if (rc < 0)
            throw new Exception("VerifyHashENC failed: " + ecc.LastErrorText);

        return rc == 1;
    }
}

public static class DerSec1
{
    // Extracts the EC point from a SubjectPublicKeyInfo DER, returning the raw SEC1 point.
    // If the input is already a SEC1 point (33 compressed or 65 uncompressed), it is returned as-is.
    public static byte[] ExtractUncompressedPointFromSpki(byte[] spkiDer)
    {
        // Already SEC1 compressed/uncompressed?
        if (spkiDer.Length == 33 && (spkiDer[0] == 0x02 || spkiDer[0] == 0x03))
            return spkiDer;
        if (spkiDer.Length == 65 && spkiDer[0] == 0x04)
            return spkiDer;

        int i = 0;
        int lastBitStringOffset = -1;
        int lastBitStringLen = 0;

        // Minimal DER walk to find the last BIT STRING (expected subjectPublicKey).
        while (i < spkiDer.Length)
        {
            byte tag = spkiDer[i++];
            if (i >= spkiDer.Length) break;
            int lenByte = spkiDer[i++];
            int len;
            if ((lenByte & 0x80) == 0)
            {
                len = lenByte;
            }
            else
            {
                int n = lenByte & 0x7F;
                if (i + n > spkiDer.Length) break;
                len = 0;
                for (int k = 0; k < n; k++)
                    len = (len << 8) | spkiDer[i++];
            }
            if (tag == 0x03) // BIT STRING
            {
                lastBitStringOffset = i;
                lastBitStringLen = len;
            }
            i += len;
        }

        if (lastBitStringOffset < 0)
        {
            // Fallback: return raw bytes unchanged (may be invalid for EC).
            return spkiDer;
        }

        int unusedBits = spkiDer[lastBitStringOffset];
        if (unusedBits != 0)
            throw new Exception("BIT STRING with unused bits != 0");

        // Skip the 'unused bits' byte and copy the EC point.
        int pointLen = lastBitStringLen - 1;
        var point = new byte[pointLen];
        Buffer.BlockCopy(spkiDer, lastBitStringOffset + 1, point, 0, pointLen);

        return point;
    }

    // Compresses an uncompressed EC point (04 || X || Y) to compressed form (02/03 || X).
    // If already compressed or unknown layout, returns input.
    public static byte[] CompressUncompressedPoint(byte[] point)
    {
        // Already compressed (02/03 || X)?
        if (point.Length == 33 && (point[0] == 0x02 || point[0] == 0x03))
            return point;

        // Uncompressed (04 || X(32) || Y(32)) -> compressed (02/03 || X)
        if (point.Length == 65 && point[0] == 0x04)
        {
            var x = new byte[32];
            var y = new byte[32];
            Buffer.BlockCopy(point, 1, x, 0, 32);
            Buffer.BlockCopy(point, 33, y, 0, 32);
            bool yOdd = (y[31] & 1) == 1;
            byte prefix = yOdd ? (byte)0x03 : (byte)0x02;
            var comp = new byte[33];
            comp[0] = prefix;
            Buffer.BlockCopy(x, 0, comp, 1, 32);
            return comp;
        }

        // Unknown layout: return as-is.
        return point;
    }
}

public static class Base58
{
    // Minimal Base58 encoder (Bitcoin alphabet), preserving leading zeroes as '1'.
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    public static string Encode(byte[] data)
    { var digits = new List<int> { 0 }; foreach (var b in data) { int carry = b; for (int i = 0; i < digits.Count; i++) { int val = digits[i] * 256 + carry; digits[i] = val % 58; carry = val / 58; } while (carry > 0) { digits.Add(carry % 58); carry /= 58; } } int zeros = 0; foreach (var b in data) { if (b == 0) zeros++; else break; } var sb = new System.Text.StringBuilder(zeros); for (int i = 0; i < zeros; i++) sb.Append('1'); for (int i = digits.Count - 1; i >= 0; i--) sb.Append(Alphabet[digits[i]]); return sb.ToString(); }
}

public static class Bech32
{
    // Minimal Bech32 encoder with witness version and program support (BIP-173 like).
    private const string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    static uint Polymod(byte[] values)
    { uint chk = 1; foreach (var v in values) { uint b = chk >> 25; chk = (chk & 0x1ffffff) << 5 ^ v; if ((b & 1) != 0) chk ^= 0x3b6a57b2; if ((b & 2) != 0) chk ^= 0x26508e6d; if ((b & 4) != 0) chk ^= 0x1ea119fa; if ((b & 8) != 0) chk ^= 0x3d4233dd; if ((b & 16) != 0) chk ^= 0x2a1462b3; } return chk; }
    static byte[] HrpExpand(string hrp) { var ret = new List<byte>(); foreach (char c in hrp) ret.Add((byte)(c >> 5)); ret.Add(0); foreach (char c in hrp) ret.Add((byte)(c & 31)); return ret.ToArray(); }
    static byte[] CreateChecksum(string hrp, byte[] data)
    { var values = new List<byte>(); values.AddRange(HrpExpand(hrp)); values.AddRange(data); values.AddRange(new byte[6]); uint pm = Polymod(values.ToArray()) ^ 1; var ret = new byte[6]; for (int i = 0; i < 6; i++) ret[i] = (byte)((pm >> 5 * (5 - i)) & 31); return ret; }
    static string Encode(string hrp, byte[] data)
    { var chk = CreateChecksum(hrp, data); var combined = new byte[data.Length + chk.Length]; Buffer.BlockCopy(data, 0, combined, 0, data.Length); Buffer.BlockCopy(chk, 0, combined, data.Length, chk.Length); var sb = new System.Text.StringBuilder(hrp.Length + 1 + combined.Length); sb.Append(hrp); sb.Append('1'); foreach (var v in combined) sb.Append(CHARSET[v]); return sb.ToString(); }
    public static string EncodeWitness(string hrp, int witver, byte[] witprog)
    { var data = ConvertBits(witprog, 8, 5, true); var version = new List<byte> { (byte)witver }; version.AddRange(data); return Encode(hrp, version.ToArray()); }
    static byte[] ConvertBits(byte[] data, int fromBits, int toBits, bool pad)
    { int acc = 0; int bits = 0; int maxv = (1 << toBits) - 1; var ret = new List<byte>(); foreach (var value in data) { if (value < 0 || (value >> fromBits) != 0) throw new ArgumentException("Invalid data range"); acc = (acc << fromBits) | value; bits += fromBits; while (bits >= toBits) { bits -= toBits; ret.Add((byte)((acc >> bits) & maxv)); } } if (pad) { if (bits > 0) ret.Add((byte)((acc << (toBits - bits)) & maxv)); } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) throw new ArgumentException("Invalid padding"); return [.. ret]; }
}

public static class Address
{
    // Loads a public key PEM (SPKI), extracts SEC1 point, compresses it, then:
    // - P2PKH: HASH160(SEC1_compressed), prepend version 0x00, Base58Check.
    // - Bech32 P2WPKH: witness v0 + HASH160(SEC1_compressed), HRP provided.
    public static byte[] GetSec1CompressedFromPem(string pubPem)
    { var pub = new PublicKey(); if (!pub.LoadFromString(pubPem)) throw new Exception("PubKey PEM invalid"); var bd = new BinData(); if (!pub.GetDerBd(true, bd)) throw new Exception("Impossibile esportare DER SPKI"); var uncompressed = DerSec1.ExtractUncompressedPointFromSpki(bd.GetBinary()); return DerSec1.CompressUncompressedPoint(uncompressed); }

    // Legacy P2PKH address (Base58Check, version 0x00).
    public static string Base58CheckP2PKH(string pubPem)
    { byte[] sec1 = GetSec1CompressedFromPem(pubPem); byte[] h160 = Crypto.Hash160(sec1); byte[] payload = new byte[1 + h160.Length]; payload[0] = 0x00; Buffer.BlockCopy(h160, 0, payload, 1, h160.Length); byte[] chk = Crypto.DblSha256(payload); byte[] full = new byte[payload.Length + 4]; Buffer.BlockCopy(payload, 0, full, 0, payload.Length); Buffer.BlockCopy(chk, 0, full, payload.Length, 4); return Base58.Encode(full); }

    // Native SegWit P2WPKH (Bech32).
    public static string Bech32P2WPKH(string hrp, string pubPem)
    { byte[] sec1 = GetSec1CompressedFromPem(pubPem); byte[] h160 = Crypto.Hash160(sec1); return Bech32.EncodeWitness(hrp, witver: 0, witprog: h160); }
}
#endregion

#region Merkle
// Simple binary Merkle tree over hex leaf strings; duplicates the last element on odd counts.
// Uses double-SHA256(L||R) as the node hashing function. Returns the root hex.
public static class Merkle
{ public static string Compute(List<string> leavesHex) { if (leavesHex == null || leavesHex.Count == 0) return Crypto.Sha256Hex(""); var level = new List<string>(leavesHex); while (level.Count > 1) { var next = new List<string>(); for (int i = 0; i < level.Count; i += 2) { string L = level[i]; string R = (i + 1 < level.Count) ? level[i + 1] : level[i]; next.Add(Crypto.BytesToHex(Crypto.DblSha256(Crypto.HexToBytes(L + R)))); } level = next; } return level[0]; } }
#endregion

#region Minimal CBOR encoder (definite)
// Very small CBOR encoder supporting definite-length major types used by this prototype.
// Used to measure realistic transaction byte size for fee-rate calculation.
public class Cbor
{
    private List<byte> _buf = new(); public byte[] ToArray() => _buf.ToArray();
    private void WriteType(int major, ulong value)
    { if (value <= 23) _buf.Add((byte)((major << 5) | (byte)value)); else if (value <= 0xFF) { _buf.Add((byte)((major << 5) | 24)); _buf.Add((byte)value); } else if (value <= 0xFFFF) { _buf.Add((byte)((major << 5) | 25)); _buf.Add((byte)(value >> 8)); _buf.Add((byte)value); } else if (value <= 0xFFFFFFFF) { _buf.Add((byte)((major << 5) | 26)); _buf.AddRange(BitConverter.GetBytes((uint)value).Reverse()); } else { _buf.Add((byte)((major << 5) | 27)); _buf.AddRange(BitConverter.GetBytes(value).Reverse()); } }
    public Cbor Unsigned(ulong v) { WriteType(0, v); return this; }
    public Cbor Bytes(byte[] b) { WriteType(2, (ulong)b.Length); _buf.AddRange(b); return this; }
    public Cbor Text(string s) { var bytes = Encoding.UTF8.GetBytes(s); WriteType(3, (ulong)bytes.Length); _buf.AddRange(bytes); return this; }
    public Cbor Array(int count) { WriteType(4, (ulong)count); return this; }
    public Cbor Map(int count) { WriteType(5, (ulong)count); return this; }
}
#endregion

#region UTXO tx model + fees (real feerate via CBOR size)
// Minimal UTXO transaction model. Inputs reference previous TxOuts; outputs transfer coins.
// Fee is implicit: sum(inputs) - sum(outputs). Fee-rate is fee / serialized_size (CBOR).
public record TxOut(string ToAddress, long Amount);

public class TxIn
{
    public string PrevTxHash { get; set; } = "";   // Hash of previous transaction
    public int OutIndex { get; set; }              // Output index in previous transaction
    public string FromPubPem { get; set; } = "";   // Owner public key (PEM), used for address and signature verification
    public string Signature { get; set; } = "";    // ECDSA signature (base64) over hash(tx.TxHash|inputIndex)
}

public class Transaction
{
    public List<TxIn> Inputs { get; set; } = [];   // Inputs spending UTXOs
    public List<TxOut> Outputs { get; set; } = []; // Outputs creating new UTXOs
    public string TxHash { get; set; } = "";       // Hash of canonical preimage (not CBOR)
    public long Fee { get; set; }                  // Populated when enqueued in the mempool

    // Canonical string used to compute TxHash (stable and human-readable).
    public string CanonicalSerializePreimage()
    { var sb = new System.Text.StringBuilder(); sb.Append("IN["); foreach (var i in Inputs) sb.Append($"{i.PrevTxHash}:{i.OutIndex}:{i.FromPubPem}|"); sb.Append("]OUT["); foreach (var o in Outputs) sb.Append($"{o.ToAddress}:{o.Amount}|"); sb.Append("]"); return sb.ToString(); }

    // Computes TxHash = SHA256(preimage).
    public void ComputeTxHash() => TxHash = Crypto.Sha256Hex(CanonicalSerializePreimage());

    // Encodes the transaction to CBOR for on-wire size calculation (fee-rate realism).
    public byte[] ToCborBytes(bool includeSignatures = true)
    { var c = new Cbor(); c.Array(3); c.Array(Inputs.Count); foreach (var i in Inputs) { c.Array(includeSignatures ? 4 : 3).Text(i.PrevTxHash).Unsigned((ulong)i.OutIndex).Text(i.FromPubPem); if (includeSignatures) c.Text(i.Signature); } c.Array(Outputs.Count); foreach (var o in Outputs) { c.Array(2).Text(o.ToAddress).Unsigned((ulong)o.Amount); } c.Text(TxHash); return c.ToArray(); }

    // Returns CBOR byte length including signatures (used for mempool fee-rate).
    public int RealSerializedSize() => ToCborBytes(includeSignatures: true).Length;
}
#endregion

#region Block + PoA quorum
// Block header contains: Index, Timestamp, PrevHash, MerkleRoot.
// Block includes a list of transactions (first is coinbase built by leader) and validator signatures.
public class ValidatorSignature { public string ValidatorPubPem { get; set; } = ""; public string Signature { get; set; } = ""; }

public class Block
{
    public int Index { get; set; }
    public long Timestamp { get; set; }
    public string PrevHash { get; set; } = new string('0', 64);
    public List<Transaction> Txs { get; set; } = new();
    public string MerkleRoot { get; set; } = "";
    public string BlockHash { get; set; } = "";
    public List<ValidatorSignature> Signatures { get; set; } = new();

    // Stable header serialization for hashing.
    public string HeaderSerialize() => $"{Index}|{Timestamp}|{PrevHash}|{MerkleRoot}";
}
#endregion

#region Mempool (feerate = fee / realSize)
// Mempool orders transactions by fee-rate desc, then fee desc, then hash.
// Tracks claimed inputs to prevent double-spend within the pool.
public class Mempool
{
    private readonly SortedSet<(double rate, long fee, string txh)> _order = new(SortComparer.Instance);
    private readonly Dictionary<string, Transaction> _txByHash = [];
    private readonly HashSet<string> _spentKeys = [];

    private class SortComparer : IComparer<(double rate, long fee, string txh)>
    { public static readonly SortComparer Instance = new(); public int Compare((double rate, long fee, string txh) a, (double rate, long fee, string txh) b) { int c = -a.rate.CompareTo(b.rate); if (c != 0) return c; c = -a.fee.CompareTo(b.fee); if (c != 0) return c; return string.CompareOrdinal(a.txh, b.txh); } }

    // Adds a transaction if it doesn't conflict and meets basic invariants.
    public bool TryAdd(Transaction tx, long fee, out string reason)
    { reason = ""; if (_txByHash.ContainsKey(tx.TxHash)) { reason = "dup"; return false; } foreach (var i in tx.Inputs) { string k = $"{i.PrevTxHash}:{i.OutIndex}"; if (_spentKeys.Contains(k)) { reason = "double-spend in mempool"; return false; } } _txByHash[tx.TxHash] = tx; tx.Fee = fee; double rate = fee / Math.Max(1.0, tx.RealSerializedSize()); _order.Add((rate, fee, tx.TxHash)); foreach (var i in tx.Inputs) _spentKeys.Add($"{i.PrevTxHash}:{i.OutIndex}"); return true; }

    // Picks as many highest-fee-rate transactions as fit within maxBytes (by CBOR size).
    public List<Transaction> PickTopByVsize(int maxBytes)
    { var picked = new List<Transaction>(); int used = 0; foreach (var tpl in _order) { var tx = _txByHash[tpl.txh]; int sz = tx.RealSerializedSize(); if (used + sz > maxBytes) continue; picked.Add(tx); used += sz; } return picked; }

    // Snapshot with computed fee-rate for diagnostics.
    public List<(string txh, long fee, double rate)> Snapshot()
    { var list = new List<(string, long, double)>(); foreach (var tpl in _order) { var tx = _txByHash[tpl.txh]; double rate = tx.Fee / Math.Max(1.0, tx.RealSerializedSize()); list.Add((tpl.txh, tx.Fee, rate)); } return list; }

    // Removes many transactions (typically those included into a block), freeing spent keys.
    public void RemoveMany(IEnumerable<string> hashes)
    { foreach (var h in hashes.ToList()) { if (!_txByHash.TryGetValue(h, out var tx)) continue; double rate = tx.Fee / Math.Max(1.0, tx.RealSerializedSize()); _order.Remove((rate, tx.Fee, h)); foreach (var i in tx.Inputs) _spentKeys.Remove($"{i.PrevTxHash}:{i.OutIndex}"); _txByHash.Remove(h); } }
}
#endregion

#region Blockchain (PoA quorum + leader RR + fees/coinbase + UTXO + Bech32 owner check + minFeeRate)
// PoA blockchain with round-robin leader and validator quorum.
// Validates block linkage, quorum signatures, Merkle root, and UTXO semantics.
public class QuorumPoABlockchain
{
    private readonly Dictionary<string, TxOut> _utxo = new();

    public List<Block> Chain { get; } = new();
    public List<string> Validators { get; } = new();
    public int QuorumK { get; }
    public long BlockReward { get; }
    public int MaxBlockSizeBytes { get; }
    private int _rrIndex = 0;
    public Mempool Pool { get; } = new();

    public string Hrp { get; }
    public double MinFeeRateSatPerByte { get; }

    // Initializes chain with given validators/quorum and creates a genesis block.
    public QuorumPoABlockchain(IEnumerable<string> validators, int quorumK, long blockReward, int maxBlockBytes, string hrp = "bc", double minFeeRate = 1.0)
    {
        Validators.AddRange(validators);
        if (quorumK <= 0 || quorumK > Validators.Count) throw new ArgumentException("Quorum k invalid");
        QuorumK = quorumK; BlockReward = blockReward; MaxBlockSizeBytes = maxBlockBytes; Hrp = hrp; MinFeeRateSatPerByte = minFeeRate; Chain.Add(CreateGenesis());
    }

    // Genesis has no transactions; Merkle root computed over empty list.
    private static Block CreateGenesis()
    { var b = new Block { Index = 0, Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), PrevHash = new string('0', 64), Txs = new List<Transaction>(), MerkleRoot = Merkle.Compute(new List<string>()) }; b.BlockHash = Crypto.Sha256Hex(b.HeaderSerialize()); return b; }

    public string CurrentLeader() => Validators[_rrIndex % Validators.Count];
    public void AdvanceLeader() => _rrIndex = (_rrIndex + 1) % Validators.Count;

    // Faucet mints coins into a fresh UTXO (coinbase-like without inputs).
    public void FaucetMint(string toAddress, long amount, out Transaction coinbaseTx)
    { coinbaseTx = new Transaction { Inputs = [], Outputs = [new TxOut(toAddress, amount)] }; coinbaseTx.ComputeTxHash(); _utxo[$"{coinbaseTx.TxHash}:0"] = coinbaseTx.Outputs[0]; }

    // Signs a single input with the owner's private key over SHA256(tx.TxHash|inputIndex).
    public static void SignInput(Transaction tx, int inputIndex, string ownerPrivPem)
    { if (tx.TxHash == "") tx.ComputeTxHash(); string digest = Crypto.Sha256Hex($"{tx.TxHash}|{inputIndex}"); tx.Inputs[inputIndex].Signature = Crypto.SignHashHex(digest, ownerPrivPem); }

    // Validates a transaction against current UTXO set and mempool policy (including min fee-rate), then enqueues it.
    public bool ValidateAndEnqueue(Transaction tx, out string reason)
    {
        reason = ""; if (tx.TxHash == "") tx.ComputeTxHash();
        long inSum = 0, outSum = 0; var seen = new HashSet<string>();
        for (int i = 0; i < tx.Inputs.Count; i++)
        {
            var inp = tx.Inputs[i]; string key = $"{inp.PrevTxHash}:{inp.OutIndex}";
            if (seen.Contains(key)) { reason = "double-spend intra-tx"; return false; }
            seen.Add(key);
            if (!_utxo.TryGetValue(key, out var prevOut)) { reason = "UTXO does not exist"; return false; }

            // Ownership check: previous out address must match the P2PKH or Bech32 derived from FromPubPem.
            string addrP2pkh = Address.Base58CheckP2PKH(inp.FromPubPem);
            string addrBech32 = Address.Bech32P2WPKH(Hrp, inp.FromPubPem);
            if (!string.Equals(prevOut.ToAddress, addrP2pkh, StringComparison.Ordinal) &&
                !string.Equals(prevOut.ToAddress, addrBech32, StringComparison.Ordinal))
            { reason = "owner mismatch"; return false; }

            // Signature over SHA256(tx.TxHash|i), verified with FromPubPem.
            string digest = Crypto.Sha256Hex($"{tx.TxHash}|{i}"); if (!Crypto.VerifyHashHex(digest, inp.Signature, inp.FromPubPem)) { reason = "firma input"; return false; }
            inSum += prevOut.Amount;
        }
        foreach (var o in tx.Outputs) { if (o.Amount <= 0) { reason = "non-positive output"; return false; } outSum += o.Amount; }
        long fee = inSum - outSum; if (fee < 0) { reason = "negative fee"; return false; }

        // Fee-rate policy (sat/byte) using CBOR-encoded size.
        double rate = fee / Math.Max(1.0, tx.RealSerializedSize());
        if (rate < MinFeeRateSatPerByte) { reason = $"fee rate too low (min {MinFeeRateSatPerByte:F2})"; return false; }

        if (!Pool.TryAdd(tx, fee, out var why)) { reason = $"mempool: {why}"; return false; }
        return true;
    }

    // Leader builds a block with coinbase (reward + fees) and highest fee-rate txs fitting the size limit.
    public Block LeaderBuildBlock(string leaderPubPem, string coinbaseAddress)
    { if (leaderPubPem != CurrentLeader()) throw new Exception("You are not the leader for this round"); var txs = Pool.PickTopByVsize(MaxBlockSizeBytes); long fees = txs.Sum(t => t.Fee); var coinbase = new Transaction { Inputs = new(), Outputs = new() { new TxOut(coinbaseAddress, BlockReward + fees) } }; coinbase.ComputeTxHash(); var list = new List<Transaction> { coinbase }; list.AddRange(txs); var prev = Chain[^1]; var b = new Block { Index = prev.Index + 1, Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), PrevHash = prev.BlockHash, Txs = list }; b.MerkleRoot = Merkle.Compute(list.Select(t => t.TxHash).ToList()); b.BlockHash = Crypto.Sha256Hex(b.HeaderSerialize()); return b; }

    // Adds a validator's signature to a block (signature over BlockHash).
    public static void SignBlock(Block b, string validatorPrivPem, string validatorPubPem)
    { string sig = Crypto.SignHashHex(b.BlockHash, validatorPrivPem); b.Signatures.Add(new ValidatorSignature { ValidatorPubPem = validatorPubPem, Signature = sig }); }

    // Validates and appends a block: previous linkage, quorum signatures, Merkle root, and UTXO apply.
    public void AppendBlock(Block b)
    {
        var prev = Chain[^1]; if (b.PrevHash != prev.BlockHash) throw new Exception("PrevHash mismatch");

        // Count unique valid signatures from known validators.
        var uniq = new HashSet<string>(); int ok = 0; foreach (var s in b.Signatures) { if (!Validators.Contains(s.ValidatorPubPem)) continue; if (uniq.Contains(s.ValidatorPubPem)) continue; if (Crypto.VerifyHashHex(b.BlockHash, s.Signature, s.ValidatorPubPem)) { uniq.Add(s.ValidatorPubPem); ok++; } }
        if (ok < QuorumK) throw new Exception($"Quorum {ok}/{QuorumK}");

        // Header integrity.
        var root = Merkle.Compute([.. b.Txs.Select(t => t.TxHash)]); if (root != b.MerkleRoot) throw new Exception("Merkle root invalid"); if (Crypto.Sha256Hex(b.HeaderSerialize()) != b.BlockHash) throw new Exception("BlockHash invalid");

        // Apply UTXO set atomically using a temp map (validates all inputs exist).
        var temp = new Dictionary<string, TxOut>(_utxo);
        foreach (var tx in b.Txs)
        {
            foreach (var i in tx.Inputs) { string key = $"{i.PrevTxHash}:{i.OutIndex}"; if (!temp.Remove(key)) throw new Exception("missing input"); }
            for (int i = 0; i < tx.Outputs.Count; i++) temp[$"{tx.TxHash}:{i}"] = tx.Outputs[i];
        }

        _utxo.Clear(); foreach (var kv in temp) _utxo[kv.Key] = kv.Value;

        // Drop mined transactions from mempool and advance leader.
        Pool.RemoveMany(b.Txs.Where(t => t.Inputs.Count > 0).Select(t => t.TxHash));
        Chain.Add(b);
        AdvanceLeader();
    }

    // Wallet helpers and debug dumps.
    public long BalanceOf(string address) { long s = 0; foreach (var kv in _utxo) if (kv.Value.ToAddress == address) s += kv.Value.Amount; return s; }
    public IEnumerable<(string key, TxOut utxo)> DumpUtxo() { foreach (var kv in _utxo) yield return (kv.Key, kv.Value); }
}
#endregion

#region Mini RPC (HttpListener): /balance/{addr}, /getblock/{n}, /mempool, /utxo, /newaddress, /submitTx|/sendrawtx
public static class MiniRpcJson
{
    // Cache JsonSerializerOptions to avoid allocations (fixes CA1869).
    public static readonly JsonSerializerOptions CachedOptions = new() { WriteIndented = true };
}

// Minimal HTTP server providing JSON endpoints to explore the chain and submit transactions.
public class MiniRpc
{
    private readonly QuorumPoABlockchain _chain;
    private readonly HttpListener _listener = new();

    public MiniRpc(QuorumPoABlockchain chain, string urlPrefix = "http://localhost:8088/")
    { _chain = chain; _listener.Prefixes.Add(urlPrefix); }

    // Starts the server and begins accepting requests asynchronously.
    public void Start()
    { _listener.Start(); Console.WriteLine("RPC listening on ... http://localhost:8088/  (Ctrl+C to exit)"); _listener.BeginGetContext(Handle, null); }

    // Async request handler; dispatches routes and writes JSON responses.
    private void Handle(IAsyncResult ar)
    {
        if (!_listener.IsListening) return;
        var ctx = _listener.EndGetContext(ar);
        _listener.BeginGetContext(Handle, null);

        try
        {
            var req = ctx.Request;
            var res = ctx.Response;
            res.ContentType = "application/json";

            string method = req.HttpMethod ?? string.Empty;
            string path = req.Url?.AbsolutePath ?? string.Empty;

            if (method == "GET" && path.StartsWith("/balance/", StringComparison.Ordinal))
            {
                string addr = WebUtility.UrlDecode(path.Substring("/balance/".Length));
                long bal = _chain.BalanceOf(addr);
                WriteJson(res, new { address = addr, balance = bal });
            }
            else if (method == "GET" && path.StartsWith("/getblock/", StringComparison.Ordinal))
            {
                if (int.TryParse(path.Substring("/getblock/".Length), out int n) && n >= 0 && n < _chain.Chain.Count)
                    WriteJson(res, _chain.Chain[n]);
                else
                {
                    res.StatusCode = 404;
                    WriteJson(res, new { error = "block not found" });
                }
            }
            else if (method == "GET" && path == "/mempool")
            {
                var snap = _chain.Pool.Snapshot().Select(x => new { txHash = x.txh, fee = x.fee, feerate = x.rate });
                WriteJson(res, snap);
            }
            else if (method == "GET" && path == "/utxo")
            {
                var utxo = _chain.DumpUtxo().Select(kv => new { key = kv.key, address = kv.utxo.ToAddress, amount = kv.utxo.Amount });
                WriteJson(res, utxo);
            }
            else if (method == "GET" && path == "/newaddress")
            {
                var (priv, pub) = Crypto.GenKey();
                string p2pkh = Address.Base58CheckP2PKH(pub);
                string bech = Address.Bech32P2WPKH(_chain.Hrp, pub);
                WriteJson(res, new { privPem = priv, pubPem = pub, p2pkh, bech32 = bech });
            }
            else if ((method == "POST" && path == "/submitTx") || (method == "POST" && path == "/sendrawtx"))
            {
                var encoding = req.ContentEncoding ?? Encoding.UTF8;
                using var sr = new StreamReader(req.InputStream, encoding);
                string body = sr.ReadToEnd();
                try
                {
                    var tx = JsonSerializer.Deserialize<Transaction>(body);
                    if (tx == null) throw new Exception("payload");
                    if (tx.TxHash == "") tx.ComputeTxHash();
                    bool ok = _chain.ValidateAndEnqueue(tx, out string why);
                    if (ok)
                        WriteJson(res, new { accepted = true, txHash = tx.TxHash, fee = tx.Fee, size = tx.RealSerializedSize() });
                    else
                    {
                        res.StatusCode = 400;
                        WriteJson(res, new { accepted = false, reason = why });
                    }
                }
                catch (Exception ex)
                {
                    res.StatusCode = 400;
                    WriteJson(res, new { error = ex.Message });
                }
            }
            else if (method == "GET" && path == "/chaininfo")
            {
                WriteJson(res, new
                {
                    height = _chain.Chain.Count - 1,
                    leader = _chain.CurrentLeader(),
                    quorum = _chain.QuorumK,
                    reward = _chain.BlockReward,
                    minFeeRate = _chain.MinFeeRateSatPerByte,
                    hrp = _chain.Hrp
                });
            }
            else
            {
                res.StatusCode = 404;
                WriteJson(res, new { error = "not found" });
            }
        }
        catch
        {
            // Best-effort server; swallow unexpected errors per request.
        }
    }

    // Utility to serialize as indented JSON and write response body.
    private static void WriteJson(HttpListenerResponse res, object obj)
    {
        var json = JsonSerializer.Serialize(obj, MiniRpcJson.CachedOptions);
        var bytes = Encoding.UTF8.GetBytes(json);
        res.ContentLength64 = bytes.Length;
        res.OutputStream.Write(bytes, 0, bytes.Length);
        res.OutputStream.Close();
    }
}
#endregion

public static class MyExtensions
{
    // Loads the Chilkat unlock key from appsettings.json (cwd or base directory) or CHILKAT_UNLOCK_KEY env-var, then unlocks Chilkat.
    private static string? LoadChilkatUnlockKey()
    {
        try
        {
            const string fileName = "appsettings.json";

            // 1) Try current working directory (typical for VS debugging)
            var cwdPath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
            if (File.Exists(cwdPath))
                return ReadKeyFromJson(cwdPath);

            // 2) Fallback to base directory (published/installed)
            var basePath = Path.Combine(AppContext.BaseDirectory, fileName);
            if (File.Exists(basePath))
                return ReadKeyFromJson(basePath);
        }
        catch
        {
            // ignore parsing/IO exceptions
        }
        return null;

        static string? ReadKeyFromJson(string path)
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                var root = doc.RootElement;
                if (root.TryGetProperty("Chilkat", out var chilkat) &&
                    chilkat.TryGetProperty("UnlockKey", out var keyEl) &&
                    keyEl.ValueKind == JsonValueKind.String)
                {
                    string? k = keyEl.GetString();
                    if (string.IsNullOrWhiteSpace(k))
                    {
                        throw new Exception("Chilkat unlock key is missing or empty.");
                    }

                    return keyEl.GetString();
                }
            }
            catch
            {
                // ignore parsing errors
            }

            return null;
        }
    }

    public static bool UnlockChilkat()
    {
        // From config or env var
        var key = LoadChilkatUnlockKey() ?? Environment.GetEnvironmentVariable("CHILKAT_UNLOCK_KEY");

        if (string.IsNullOrWhiteSpace(key))
        {
            // Key not provided
            return false;
        }

        Global glob = new();
        bool success = glob.UnlockBundle(key);
        if (success != true)
        {
            return false;
        }

        int status = glob.UnlockStatus;
        if (status == 2)
        {
            return true;
        }

        return false;
    }
}

class Program
{
    // Demo: spins up a small chain with 3 validators and a mini RPC server.
    static void Main()
    {
        bool b = MyExtensions.UnlockChilkat();
        if (!b)
        {
            Console.WriteLine("Chilkat unlock not found!");
            return;
        }

        // === Setup validator (3) quorum 2, reward 50, max block 100kB reali, HRP bech32 = "bc", min feerate = 1 sat/B ===
        var (v1Priv, v1Pub) = Crypto.GenKey();
        var (v2Priv, v2Pub) = Crypto.GenKey();
        var (v3Priv, v3Pub) = Crypto.GenKey();
        var chain = new QuorumPoABlockchain([v1Pub, v2Pub, v3Pub], quorumK: 2, blockReward: 50, maxBlockBytes: 100_000, hrp: "bc", minFeeRate: 1.0);

        // === Due utenti A e B con indirizzi legacy + bech32 ===
        var (aPriv, aPub) = Crypto.GenKey();
        var (bPriv, bPub) = Crypto.GenKey();
        string aP2PKH = Address.Base58CheckP2PKH(aPub);
        string bP2PKH = Address.Base58CheckP2PKH(bPub);
        string aBech32 = Address.Bech32P2WPKH(chain.Hrp, aPub);
        string bBech32 = Address.Bech32P2WPKH(chain.Hrp, bPub);

        Console.WriteLine($"A P2PKH: {aP2PKH}A bech32: {aBech32}B P2PKH: {bP2PKH}B bech32: {bBech32}");

        // Faucet 100 a A (P2PKH)
        chain.FaucetMint(aP2PKH, 100, out var faucet);
        Console.WriteLine($"Faucet: {faucet.TxHash}");

        // TX1: A -> B 30, change a A, fee 1 (P2PKH owner)
        var tx1 = new Transaction { Inputs = [new TxIn { PrevTxHash = faucet.TxHash, OutIndex = 0, FromPubPem = aPub }], Outputs = new() { new TxOut(bP2PKH, 30), new TxOut(aP2PKH, 69) } };
        tx1.ComputeTxHash(); QuorumPoABlockchain.SignInput(tx1, 0, aPriv);
        Console.WriteLine("Enqueue tx1: " + chain.ValidateAndEnqueue(tx1, out var why1) + (why1 == "" ? "" : $" ({why1})"));

        // TX2: A -> B 20, change a A bech32, fee 0 (mostra owner check bech32)
        var tx2 = new Transaction { Inputs = [new TxIn { PrevTxHash = tx1.TxHash, OutIndex = 1, FromPubPem = aPub }], Outputs = new() { new TxOut(bBech32, 69), new TxOut(aBech32, 0) } };
        tx2.ComputeTxHash(); QuorumPoABlockchain.SignInput(tx2, 0, aPriv);
        Console.WriteLine("Enqueue tx2: " + chain.ValidateAndEnqueue(tx2, out var why2) + (why2 == "" ? "" : $" ({why2})"));

        // Leader v1 crea blocco, coinbase a sé (P2PKH)
        string v1Addr = Address.Base58CheckP2PKH(v1Pub); var b1 = chain.LeaderBuildBlock(v1Pub, v1Addr); QuorumPoABlockchain.SignBlock(b1, v1Priv, v1Pub); QuorumPoABlockchain.SignBlock(b1, v2Priv, v2Pub); chain.AppendBlock(b1);
        Console.WriteLine($"Block #{b1.Index} hash={b1.BlockHash} merkle={b1.MerkleRoot} txs={b1.Txs.Count}");
        Console.WriteLine($"Balances: A(P2PKH)={chain.BalanceOf(aP2PKH)} B(P2PKH)={chain.BalanceOf(bP2PKH)} v1={chain.BalanceOf(v1Addr)}");

        // B spende verso A con fee alta (2)
        var tx3 = new Transaction { Inputs = [new TxIn { PrevTxHash = tx1.TxHash, OutIndex = 0, FromPubPem = bPub }], Outputs = new() { new TxOut(aP2PKH, 28) } };
        tx3.ComputeTxHash(); QuorumPoABlockchain.SignInput(tx3, 0, bPriv); chain.ValidateAndEnqueue(tx3, out _);

        // Leader v2
        string v2Addr = Address.Base58CheckP2PKH(v2Pub); var b2 = chain.LeaderBuildBlock(v2Pub, v2Addr); QuorumPoABlockchain.SignBlock(b2, v2Priv, v2Pub); QuorumPoABlockchain.SignBlock(b2, v3Priv, v3Pub); chain.AppendBlock(b2);
        Console.WriteLine($"Block #{b2.Index} hash={b2.BlockHash} merkle={b2.MerkleRoot} txs={b2.Txs.Count}");
        Console.WriteLine($"Balances: A(P2PKH)={chain.BalanceOf(aP2PKH)} B(P2PKH)={chain.BalanceOf(bP2PKH)} v1={chain.BalanceOf(v1Addr)} v2={chain.BalanceOf(v2Addr)}");

        // Start minimal JSON RPC server for exploration/testing.
        var rpc = new MiniRpc(chain);
        rpc.Start();
        Console.WriteLine("Esempi curl:\n" +
        "curl http://localhost:8088/chaininfo\n" +
        "curl http://localhost:8088/mempool\n" +
        "curl http://localhost:8088/utxo\n" +
        "curl http://localhost:8088/balance/" + aP2PKH + "\n" +
        "curl http://localhost:8088/getblock/1\n" +
        "curl - X GET http://localhost:8088/newaddress\n" +
        "curl - X POST http://localhost:8088/submitTx -H 'Content-Type: application/json' -d '{\"Inputs\":[],\"Outputs\":[{\"ToAddress\":\"" + bP2PKH + "\" ,\"Amount\":1}],\"TxHash\":\"\"" + Guid.NewGuid().ToString("N") + "\"}'\");\n");
        Thread.Sleep(-1);
    }
}



