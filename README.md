# BlockChain (PoA demo in C#/.NET 8)

A minimal Proof-of-Authority (PoA) blockchain prototype demonstrating:
- UTXO-based transactions with fee and fee-rate policy.
- Address derivation: legacy P2PKH (Base58Check) and native SegWit P2WPKH (Bech32).
- ECDSA signing/verification on secp256k1 using the Chilkat library.
- Merkle root computation and block header hashing.
- Round-robin leader selection and validator quorum for PoA.
- A tiny HTTP JSON RPC for inspecting the chain and submitting transactions.

This project is educational and not intended for production use.

## Features

- Crypto helpers for SHA-256, RIPEMD-160, HASH160, double-SHA256
- SEC1 compressed EC point extraction from public key PEM (SPKI)
- Base58Check and Bech32 encoders
- Minimal CBOR encoder used to measure realistic transaction size for fee-rate
- Mempool ordered by fee-rate (sat/byte), then fee, then tx hash
- PoA blockchain with:
  - Genesis block
  - Round-robin leader
  - Quorum K of N validator signatures over block hash
  - Merkle root verification
  - UTXO application with atomic state update
- HTTP JSON RPC endpoints

## Requirements

- .NET 8 SDK
- Chilkat .NET library available at runtime
- Chilkat unlock key provided via configuration or environment variable

## Configuration

Provide a Chilkat unlock key either via `appsettings.json` or an environment variable.

Example `appsettings.json` in the application directory:

```
{
  "Chilkat": {
    "UnlockKey": "Your-Chilkat-Unlock-Key"
  }
}
```

## Commento al codice

La sezione seguente riprende `Program.cs` commentandone i componenti principali punto per punto:

1. **Utilità crittografiche e di formattazione indirizzi**
   - `Crypto` centralizza funzioni di hashing (SHA-256, RIPEMD-160), conversioni esadecimali e firma/verifica secp256k1 tramite Chilkat.
   - `ChilkatCompat` incapsula l'interoperabilità con Chilkat per caricare chiavi private in vari formati e gestire firme ECDSA con messaggi d'errore dettagliati.
   - `DerSec1`, `Base58`, `Bech32` e `Address` forniscono gli strumenti per derivare indirizzi stile Bitcoin (P2PKH legacy e P2WPKH SegWit).

2. **Altre primitive di supporto**
   - `Merkle` calcola radici di alberi Merkle duplicando l'ultima foglia quando necessario e applicando double-SHA256 sulle coppie concatenate.
   - `Cbor` implementa un encoder minimale usato per stimare la dimensione effettiva di una transazione e quindi il suo fee-rate.

3. **Modello UTXO e transazioni**
   - `TxOut`, `TxIn` e `Transaction` definiscono il modello UTXO: gli input citano output precedenti, gli output specificano destinatario/importo e `CanonicalSerializePreimage` genera il preimage da cui deriva l'hash di transazione.
   - Le transazioni si serializzano in CBOR per calcolare la dimensione reale, memorizzano la fee e devono rispettare la soglia di fee-rate prima di entrare in mempool.

4. **Blocchi e firme dei validatori**
   - `Block` incapsula intestazione (indice, timestamp, hash precedente, Merkle root), lista di transazioni e firme, esponendo `HeaderSerialize` come preimage stabile per l'hash del blocco.

5. **Mempool ordinato per fee-rate**
   - `Mempool` mantiene le transazioni ordinate per fee-rate decrescente (poi fee e hash), impedisce doppie spese interne e offre snapshot diagnostici.

6. **Blockchain PoA con quorum**
   - `QuorumPoABlockchain` gestisce validatori, quorum, ricompensa per blocco, limite dimensione e politica di fee mentre aggiorna il set UTXO.
   - `ValidateAndEnqueue` verifica esistenza nel set UTXO, ownership tramite indirizzo, firma ECDSA, fee non negativa e fee-rate sopra soglia prima di inserire in mempool.
   - `LeaderBuildBlock`, `SignBlock` e `AppendBlock` costruiscono blocchi, raccolgono firme dei validatori, validano Merkle root e applicano le modifiche allo stato.

7. **Server JSON-RPC minimale**
   - `MiniRpcJson` prepara le opzioni `JsonSerializer`; `MiniRpc` espone endpoint asincroni per saldi, blocchi, mempool, UTXO e invio transazioni.

8. **Integrazione con Chilkat ed entrypoint**
   - `MyExtensions.UnlockChilkat` carica la chiave di sblocco da configurazione o variabile d'ambiente e interrompe l'avvio se assente.
   - `Main` orchestra tutto: genera validatori e utenti di esempio, effettua un faucet, costruisce blocchi consecutivi e avvia il server JSON-RPC.
