/**
 * MCP Server — Contract Security Scanner
 *
 * Exposes the p8 contract scanner as an MCP tool.
 * Compatible with: Claude Desktop, Cursor, Cline, any MCP client.
 *
 * Usage (stdio):
 *   node /path/to/p8/mcp/server.js
 *
 * Tools exposed:
 *   scan_contract(address)     — Full security scan of a Base contract
 *   scan_contract_quick(address) — Bytecode-only scan (no Etherscan API needed)
 */

import { McpServer }    from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z }            from 'zod';
import { scanContract } from './scanner.js';

// ─── Server ───────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'contract-scanner',
  version: '1.0.0',
});

// ─── Tool: scan_contract ──────────────────────────────────────────────────────

server.tool(
  'scan_contract',
  `Scans an EVM smart contract on Base L2 for security risks.

Analyzes:
- Source code verification status
- Risky function selectors (mint, blacklist, pause, backdoors, etc.)
- Proxy / upgradeability patterns
- Contract age (new contracts = higher risk)
- Transaction activity

Returns a risk score (0-100) and categorized findings (critical/high/medium/good).

Use this before:
- Interacting with an unknown contract
- Approving a token spend
- Investing in a DeFi protocol
- Auditing a smart contract`,
  {
    address: z
      .string()
      .regex(/^0x[0-9a-fA-F]{40}$/, 'Must be a valid EVM address (0x + 40 hex chars)')
      .describe('Contract address on Base L2 to scan'),
    include_raw: z
      .boolean()
      .optional()
      .default(false)
      .describe('Include raw findings array in response (default: false)'),
  },
  async ({ address, include_raw }) => {
    try {
      const result = await scanContract(address);

      if (result.error) {
        return {
          content: [{
            type: 'text',
            text: `❌ **Scan failed**: ${result.error}\n\nAddress \`${address}\` is not a deployed contract on Base.`,
          }],
          isError: true,
        };
      }

      // Risk emoji
      const emoji = result.riskScore >= 70 ? '🔴' :
                    result.riskScore >= 50 ? '🟠' :
                    result.riskScore >= 30 ? '🟡' :
                    result.riskScore >= 10 ? '🟢' : '✅';

      // Build markdown response
      const lines = [
        `## ${emoji} Risk Score: ${result.riskScore}/100 — ${result.riskLabel}`,
        ``,
        `**Contract**: \`${result.address}\``,
        `**Name**: ${result.meta.contractName || 'Unknown'}`,
        `**Age**: ${result.meta.agedays ?? '?'} days`,
        `**Source verified**: ${result.meta.sourceVerified ? '✅ Yes' : '❌ No'}`,
        `**Bytecode**: ${result.meta.bytecodeSize} bytes`,
        `**Recent txs**: ${result.meta.recentTxCount ?? '?'}`,
        ``,
      ];

      // Group findings by severity
      const bySeverity = { critical: [], high: [], medium: [], info: [], good: [] };
      for (const f of result.findings) {
        (bySeverity[f.severity] || bySeverity.info).push(f);
      }

      const icons = { critical: '🔴', high: '🟠', medium: '🟡', info: 'ℹ️', good: '✅' };

      for (const [sev, items] of Object.entries(bySeverity)) {
        if (items.length === 0) continue;
        lines.push(`### ${icons[sev]} ${sev.toUpperCase()} (${items.length})`);
        for (const f of items) {
          lines.push(`- **${f.name}**${f.detail ? `: ${f.detail}` : ''}`);
        }
        lines.push('');
      }

      // Summary
      lines.push(`---`);
      lines.push(`**On-chain summary**: \`${result.summary}\``);
      lines.push(`**Result hash**: \`${result.resultHash}\``);
      lines.push(`**Scanned at**: ${result.timestamp}`);

      const text = lines.join('\n');

      const content = [{ type: 'text', text }];

      if (include_raw) {
        content.push({
          type: 'text',
          text: `\n\n<details>\n<summary>Raw JSON</summary>\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\`\n</details>`,
        });
      }

      return { content };

    } catch (err) {
      return {
        content: [{
          type: 'text',
          text: `❌ **Scanner error**: ${err.message}\n\nPlease check the address and try again.`,
        }],
        isError: true,
      };
    }
  }
);

// ─── Tool: batch_scan ────────────────────────────────────────────────────────

server.tool(
  'batch_scan',
  `Scans multiple contracts at once and returns a risk comparison table.
  
Useful for:
- Comparing multiple DeFi protocols before choosing one
- Auditing all contracts in a project
- Quick portfolio risk assessment

Scans up to 5 contracts in parallel.`,
  {
    addresses: z
      .array(z.string().regex(/^0x[0-9a-fA-F]{40}$/))
      .min(2)
      .max(5)
      .describe('List of 2-5 contract addresses on Base L2'),
  },
  async ({ addresses }) => {
    try {
      // Scan all in parallel
      const results = await Promise.allSettled(
        addresses.map(addr => scanContract(addr))
      );

      const lines = [
        `## 📊 Batch Scan — ${addresses.length} contracts`,
        ``,
        `| Contract | Name | Risk | Score | Verified | Age |`,
        `|----------|------|------|-------|----------|-----|`,
      ];

      for (let i = 0; i < results.length; i++) {
        const r = results[i];
        if (r.status === 'rejected' || r.value?.error) {
          lines.push(`| \`${addresses[i].slice(0, 10)}...\` | ERROR | ❓ | N/A | N/A | N/A |`);
          continue;
        }
        const v = r.value;
        const emoji = v.riskScore >= 70 ? '🔴' :
                      v.riskScore >= 50 ? '🟠' :
                      v.riskScore >= 30 ? '🟡' :
                      v.riskScore >= 10 ? '🟢' : '✅';

        lines.push(
          `| \`${v.address.slice(0, 10)}...\` | ${v.meta.contractName || '?'} | ${emoji} ${v.riskLabel} | ${v.riskScore}/100 | ${v.meta.sourceVerified ? '✅' : '❌'} | ${v.meta.agedays ?? '?'}d |`
        );
      }

      lines.push('');
      lines.push(`_Scanned at ${new Date().toISOString()}_`);

      return {
        content: [{ type: 'text', text: lines.join('\n') }],
      };

    } catch (err) {
      return {
        content: [{ type: 'text', text: `❌ Batch scan error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Tool: interpret_risk ────────────────────────────────────────────────────

server.tool(
  'interpret_risk',
  `Given a risk score and findings from a scan, provides an actionable recommendation.

Returns: SAFE_TO_USE / PROCEED_WITH_CAUTION / HIGH_RISK / DO_NOT_USE`,
  {
    risk_score: z.number().min(0).max(100).describe('Risk score from scan_contract'),
    risk_label: z.enum(['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).describe('Risk label from scan_contract'),
    has_unverified_source: z.boolean().describe('Whether source code is unverified'),
    has_backdoor: z.boolean().optional().default(false).describe('Whether rescueTokens/withdrawAll detected'),
    context: z.enum(['token', 'defi', 'nft', 'unknown']).optional().default('unknown').describe('Type of contract being evaluated'),
  },
  async ({ risk_score, risk_label, has_unverified_source, has_backdoor, context }) => {
    let verdict = '';
    let explanation = '';
    let actions = [];

    if (has_backdoor) {
      verdict = '🔴 DO_NOT_USE';
      explanation = 'Backdoor functions detected (rescueTokens/withdrawAll). This contract can drain funds.';
      actions = ['Do not approve any token spend', 'Do not deposit funds', 'Warn your community'];
    } else if (risk_score >= 70 || (has_unverified_source && risk_score >= 40)) {
      verdict = '🟠 HIGH_RISK';
      explanation = `Score ${risk_score}/100 indicates significant risk. ${has_unverified_source ? 'Unverified source makes it impossible to audit fully.' : ''}`;
      actions = ['Only interact with small amounts to test', 'Check if audited by a firm', 'Look for team doxxing'];
    } else if (risk_score >= 30) {
      verdict = '🟡 PROCEED_WITH_CAUTION';
      explanation = `Score ${risk_score}/100. Some elevated-risk patterns found but no critical issues.`;
      actions = [
        'Check if mint/pause are behind a timelock',
        context === 'defi' ? 'Verify TVL history before depositing' : null,
        'Read the contract documentation',
      ].filter(Boolean);
    } else {
      verdict = '✅ SAFE_TO_USE';
      explanation = `Score ${risk_score}/100. No critical issues detected. Standard risk for a ${context} contract.`;
      actions = ['Standard due diligence still recommended', 'Monitor for contract upgrades if proxy'];
    }

    const text = [
      `## ${verdict}`,
      ``,
      explanation,
      ``,
      `**Recommended actions:**`,
      ...actions.map(a => `- ${a}`),
    ].join('\n');

    return { content: [{ type: 'text', text }] };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // MCP servers communicate via stdio — no console.log here
}

main().catch(err => {
  process.stderr.write(`MCP server error: ${err.message}\n`);
  process.exit(1);
});
