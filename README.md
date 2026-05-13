
![logo](https://i.postimg.cc/Zn43rfQR/logo.png)

Offline Bitcoin Brain Wallets CPU Cracker leveraging the [Loyce Club](http://addresses.loyce.club/) legacy address database. Generates compressed **[C]** and uncompressed **[U]** P2PKH addresses from wordlists or credential dumps and checks balances against a local indexed dataset.

> **Note:** This is a purely offline tool. No external APIs are contacted; all lookups are performed against a local copy of the blockchain address database.

## Requirements

- Python 3.10+
- `pip install colorama ecdsa pycryptodome base58 zstandard tqdm pyfiglet`
- `blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz` placed in `./funded/`

## Usage

```bash
python3 BTC-BrainCracker.py -i <input> -o <output> --mode <mode> [--lowcase]
```

<img width="640" height="365" alt="output" src="https://github.com/user-attachments/assets/6b864602-5654-4baa-a0f1-05dd6c7dc443" />

### Modes

| Mode | Description | Input Format Example |
|------|-------------|---------------------|
| `wordlist` | One word per line; each line is hashed to generate keys | `monkey123` |
| `cuser` | Extract **usernames** from combo lists (email truncated) | `alice@domain.com:fO0b@r!` → `alice` |
| `cpass` | Extract **passwords** from combo lists | `admin:P@ssw0rd` → `P@ssw0rd` |
| `wallet` | Validate existing wallet credentials | `5Hue...;1A1zP1eP5...` or `priv;addr;label` |

### Examples

```bash
# Wordlist mode
python3 BTC-BrainCracker.py -i wordlists/rockyou.txt -o hits.txt --mode wordlist

# Combo list (password mode)
python3 BTC-BrainCracker.py -i combos.txt.gz -o hits.txt --mode cpass --lowcase

# Wallet verification
python3 BTC-BrainCracker.py -i wallets.csv -o verified.txt --mode wallet
```

---

## File Structure

```
├── funded/                      # Local database directory
│   └── blockchair_bitcoin_...   # Loyce Club TSV (required)
├── resume/                      # Auto-generated checkpoint files
├── wordlists/                   # Input wordlists (user-created)
│   ├── english.dic
│   └── *.txt / *.zst / *.gz
├── BTC-BrainCracker.py          # Main script
```

- **Checkpointing:** Progress is automatically saved to `resume/` after every 100 lines. Interrupted scans resume seamlessly.
- **Supported formats:** Plain text (`.txt`, `.dic`), GZip (`.gz`), ZStandard (`.zst`).

---

## Ethical Disclaimer

This tool is provided for **educational purposes, security research, and the recovery of your own lost credentials only**. 

- **Unauthorized access** to cryptocurrency wallets you do not own is **illegal** under computer fraud statutes in most jurisdictions.
- The author assumes **no liability** for misuse, damages, or legal consequences arising from the use of this software.
- Always ensure you have explicit permission to test any wallet or key material.
