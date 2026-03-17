# Contract Security Scanner — MCP Server

[![contract-scanner-mcp MCP server](https://glama.ai/mcp/servers/fino-oss/contract-scanner-mcp/badges/score.svg)](https://glama.ai/mcp/servers/fino-oss/contract-scanner-mcp)


Scan any Base L2 smart contract for security risks directly from your AI assistant.

**3 tools exposed:**
- `scan_contract` — Full security scan (source verification, risky selectors, age, activity)
- `batch_scan` — Compare up to 5 contracts side by side
- `interpret_risk` — Get an actionable recommendation (SAFE / CAUTION / HIGH_RISK / DO_NOT_USE)

**Risk score: 0-100.** Analyzes: mint/blacklist/backdoor functions, proxy patterns, source verification, contract age, transaction activity.

---

## Installation

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "contract-scanner": {
      "command": "node",
      "args": ["/Users/sam/Desktop/samDev/p8/mcp/server.js"]
    }
  }
}
```

Restart Claude Desktop. The tools appear automatically.

---

### Cursor

Add to `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "contract-scanner": {
      "command": "node",
      "args": ["/Users/sam/Desktop/samDev/p8/mcp/server.js"]
    }
  }
}
```

---

### Cline (VS Code extension)

1. Open Cline settings → MCP Servers → Add server
2. Set type: `stdio`
3. Command: `node /Users/sam/Desktop/samDev/p8/mcp/server.js`

---

### Any MCP client (generic)

The server uses **stdio transport** — just pipe JSON-RPC messages:

```bash
node /Users/sam/Desktop/samDev/p8/mcp/server.js
```

---

## Usage examples

Once connected, just ask your AI assistant naturally:

```
"Scan this contract before I approve: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

"Compare the risk of these 3 Aave clones: 0x... 0x... 0x..."

"Is this token safe to buy? 0x4ed4e862860bed51a9570b96d89af5e1b0efefed"
```

---

## What gets analyzed

| Check | Source |
|-------|--------|
| Source code verified? | BaseScan API |
| Mint / burn functions | Bytecode selector scan |
| Pause / freeze | Bytecode selector scan |
| Blacklist / whitelist | Bytecode selector scan |
| Backdoors (rescueTokens, withdrawAll) | Bytecode selector scan |
| Upgradeable proxy | BaseScan + delegatecall detection |
| Contract age | BaseScan transaction history |
| Activity level | BaseScan recent txs |

---

## Risk scoring

| Score | Label | Meaning |
|-------|-------|---------|
| 0-9 | SAFE | No red flags |
| 10-29 | LOW | Minor concerns |
| 30-49 | MEDIUM | Elevated risk — review before interacting |
| 50-69 | HIGH | Significant risk — small amounts only |
| 70+ | CRITICAL | Avoid — potential rug or backdoor |

---

## Technical notes

- **Chain**: Base L2 only (`https://mainnet.base.org`)
- **API**: BaseScan free tier (no key needed for basic checks; set `BASESCAN_API_KEY` env var for full source analysis)
- **No wallet needed**: read-only RPC calls only
- **Latency**: ~2-5s per contract (network dependent)

---

*Built on Base. Agent wallet: `0x804dd2cE4aA3296831c880139040e4326df13c6e`*
