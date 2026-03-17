/**
 * scanner.js — Contract Security Scanner
 *
 * Analyzes an EVM contract address and returns a risk score + findings.
 * Uses: Base RPC (free) + Etherscan API (free tier, 100k/day)
 *
 * Usage:
 *   node research/scanner.js <contractAddress>
 *   node research/scanner.js 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 */

import { ethers } from 'ethers';
import { createHash } from 'crypto';

// ─── Config ──────────────────────────────────────────────────────────────────

const BASE_RPC         = 'https://mainnet.base.org';
const ETHERSCAN_BASE   = 'https://api.etherscan.io/v2/api'; // V2 endpoint (chain-agnostic)
const ETHERSCAN_CHAIN  = '8453'; // Base L2 chain ID
const ETHERSCAN_KEY    = process.env.BASESCAN_API_KEY || 'YourApiKeyToken';

const provider = new ethers.JsonRpcProvider(BASE_RPC);

// ─── Known Risk Patterns in Bytecode ─────────────────────────────────────────

// Solidity function selectors for risky functions
const RISKY_SELECTORS = {
  // Ownership / control
  'f2fde38b': { name: 'transferOwnership(address)',  severity: 'info',   label: 'transferOwnership' },
  '715018a6': { name: 'renounceOwnership()',         severity: 'good',   label: 'renounceOwnership' },
  'e30c3978': { name: 'pendingOwner()',              severity: 'info',   label: 'pendingOwner' },

  // Minting / supply control
  '40c10f19': { name: 'mint(address,uint256)',       severity: 'high',   label: 'mint' },
  'a0712d68': { name: 'mint(uint256)',               severity: 'high',   label: 'mint' },
  '1249c58b': { name: 'mint()',                      severity: 'high',   label: 'mint' },
  '4e6ec247': { name: 'mintTokens(address,uint256)', severity: 'high',   label: 'mint' },

  // Pause / freeze
  '8456cb59': { name: 'pause()',                     severity: 'medium', label: 'pause' },
  '3f4ba83a': { name: 'unpause()',                   severity: 'medium', label: 'unpause' },
  'bedb86fb': { name: 'pause(bool)',                 severity: 'medium', label: 'pause' },

  // Blacklist / whitelist
  'f9f92be4': { name: 'blacklist(address)',           severity: 'high',   label: 'blacklist' },
  '1a895266': { name: 'blacklist(address,bool)',      severity: 'high',   label: 'blacklist' },
  '42966c68': { name: 'burn(uint256)',                severity: 'info',   label: 'burn' },
  '79cc6790': { name: 'burnFrom(address,uint256)',    severity: 'info',   label: 'burnFrom' },

  // Fee manipulation
  '518ab2a8': { name: 'setFee(uint256)',              severity: 'medium', label: 'setFee' },
  '3d3e3c6f': { name: 'setTaxFee(uint256)',           severity: 'medium', label: 'setTaxFee' },

  // Hidden backdoors (common in rugs)
  'e0f7392b': { name: 'rescueTokens()',              severity: 'critical', label: 'rescueTokens' },
  'f1b9e7d8': { name: 'withdrawAll()',               severity: 'critical', label: 'withdrawAll' },
};

// ERC20 standard selectors (good signs)
const ERC20_SELECTORS = ['18160ddd', 'dd62ed3e', '095ea7b3', '23b872dd', 'a9059cbb', '70a08231'];

// Proxy patterns (bytecode starts with these)
const PROXY_PATTERNS = [
  { prefix: '3d602d', label: 'EIP-1167 Minimal Proxy (Clone)' },
  { prefix: '6080604052', label: 'Standard Contract (not a proxy)' }, // not a proxy
  { prefix: '363d3d373d3d3d363d73', label: 'EIP-1167 Minimal Proxy' },
];

// ─── Etherscan API helpers ────────────────────────────────────────────────────

async function fetchEtherscan(params) {
  const url = new URL(ETHERSCAN_BASE);
  url.searchParams.set('chainid', ETHERSCAN_CHAIN);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  url.searchParams.set('apikey', ETHERSCAN_KEY);

  try {
    const res = await fetch(url.toString());
    const data = await res.json();
    if (data.status === '1') return data.result;
    return null;
  } catch {
    return null;
  }
}

async function getContractSource(address) {
  return fetchEtherscan({
    module: 'contract',
    action: 'getsourcecode',
    address,
  });
}

async function getContractABI(address) {
  return fetchEtherscan({
    module: 'contract',
    action: 'getabi',
    address,
  });
}

async function getTxCount(address) {
  const result = await fetchEtherscan({
    module: 'account',
    action: 'txlist',
    address,
    startblock: 0,
    endblock: 99999999,
    page: 1,
    offset: 10,
    sort: 'desc',
  });
  return result ? result.length : 0;
}

// ─── Analysis functions ───────────────────────────────────────────────────────

function analyzeSelectors(bytecode) {
  const found = [];
  const hex = bytecode.toLowerCase().slice(2); // remove 0x

  for (const [selector, info] of Object.entries(RISKY_SELECTORS)) {
    if (hex.includes(selector)) {
      found.push({ selector, ...info });
    }
  }

  // Check ERC20 compliance
  const erc20Count = ERC20_SELECTORS.filter(s => hex.includes(s)).length;
  const isERC20 = erc20Count >= 4;

  return { found, isERC20, erc20Count };
}

function detectProxy(bytecode) {
  const hex = bytecode.toLowerCase();
  for (const p of PROXY_PATTERNS) {
    if (hex.includes(p.prefix) && p.label !== 'Standard Contract (not a proxy)') {
      return { isProxy: true, type: p.label };
    }
  }
  // Check for delegatecall pattern (0xf4 opcode = delegatecall)
  // In hex: f4 appears frequently in non-proxy contracts too, look for pattern
  const hasDelegatecall = hex.includes('5af4');
  return { isProxy: hasDelegatecall, type: hasDelegatecall ? 'Potential Proxy (delegatecall found)' : 'Not a proxy' };
}

function computeRiskScore(findings) {
  let score = 0;
  const weights = { critical: 30, high: 20, medium: 10, info: 3, good: -10 };

  for (const f of findings) {
    score += (weights[f.severity] || 0);
  }

  return Math.max(0, Math.min(100, score));
}

// ─── Main scanner ─────────────────────────────────────────────────────────────

export async function scanContract(address) {
  const findings = [];
  const meta = {};

  console.log(`\n🔍 Scanning ${address} on Base...`);

  // 1. Basic on-chain info
  const [code, txCount] = await Promise.all([
    provider.getCode(address),
    provider.getTransactionCount(address),
  ]);

  if (code === '0x') {
    return {
      error: 'Not a contract',
      address,
      riskScore: 0,
      findings: [],
      summary: 'NOT_A_CONTRACT',
    };
  }

  meta.bytecodeSize = (code.length - 2) / 2; // bytes
  meta.deployerTxCount = txCount;

  console.log(`  Bytecode: ${meta.bytecodeSize} bytes`);

  // 2. Source code verification
  const sourceInfo = await getContractSource(address);
  if (sourceInfo && sourceInfo[0]) {
    const s = sourceInfo[0];
    meta.contractName  = s.ContractName || 'Unknown';
    meta.compiler      = s.CompilerVersion || '?';
    meta.sourceVerified = s.SourceCode && s.SourceCode.length > 0;
    meta.isProxy       = s.Proxy === '1';
    meta.implementation = s.Implementation || null;

    console.log(`  Name: ${meta.contractName}`);
    console.log(`  Verified: ${meta.sourceVerified}`);

    if (!meta.sourceVerified) {
      findings.push({
        severity: 'high',
        label: 'unverified_source',
        name: 'Source code not verified',
        detail: 'Cannot inspect source code — high risk of hidden backdoors',
      });
    } else {
      findings.push({
        severity: 'good',
        label: 'verified_source',
        name: 'Source code verified',
        detail: `Contract: ${meta.contractName}`,
      });
    }

    if (meta.isProxy) {
      findings.push({
        severity: 'medium',
        label: 'upgradeable_proxy',
        name: 'Upgradeable proxy',
        detail: `Implementation: ${meta.implementation || 'unknown'} — owner can upgrade the logic`,
      });
    }
  } else {
    meta.sourceVerified = false;
    findings.push({
      severity: 'high',
      label: 'unverified_source',
      name: 'Source code not verified',
      detail: 'BaseScan has no source code for this contract',
    });
  }

  // 3. Bytecode selector analysis
  const { found: selectorFindings, isERC20 } = analyzeSelectors(code);
  meta.isERC20 = isERC20;

  if (isERC20) {
    findings.push({
      severity: 'good',
      label: 'erc20_compliant',
      name: 'ERC20 compliant',
      detail: 'Standard transfer/approve/allowance functions detected',
    });
  }

  for (const sf of selectorFindings) {
    findings.push({
      severity: sf.severity,
      label: sf.label,
      name: sf.name,
      detail: `Selector 0x${sf.selector} found in bytecode`,
    });
  }

  // 4. Proxy bytecode detection
  const proxyInfo = detectProxy(code);
  if (proxyInfo.isProxy && !meta.isProxy) {
    findings.push({
      severity: 'medium',
      label: 'proxy_pattern',
      name: 'Proxy pattern detected in bytecode',
      detail: proxyInfo.type,
    });
  }

  // 5. Age check
  try {
    const txs = await fetchEtherscan({
      module: 'account',
      action: 'txlist',
      address,
      startblock: 0,
      endblock: 99999999,
      page: 1,
      offset: 1,
      sort: 'asc',
    });
    if (txs && txs[0]) {
      const deployTs = parseInt(txs[0].timeStamp);
      const agedays = (Date.now() / 1000 - deployTs) / 86400;
      meta.agedays = Math.round(agedays);
      meta.deployer = txs[0].from;

      if (agedays < 7) {
        findings.push({
          severity: 'high',
          label: 'new_contract',
          name: 'Contract deployed < 7 days ago',
          detail: `Deployed ${meta.agedays} days ago by ${meta.deployer}`,
        });
      } else if (agedays < 30) {
        findings.push({
          severity: 'medium',
          label: 'recent_contract',
          name: 'Contract deployed < 30 days ago',
          detail: `Deployed ${meta.agedays} days ago`,
        });
      } else {
        findings.push({
          severity: 'good',
          label: 'established_contract',
          name: `Contract established (${meta.agedays} days old)`,
          detail: `Deployed ${meta.agedays} days ago`,
        });
      }
    }
  } catch { /* skip age check */ }

  // 6. Transaction volume (activity check)
  try {
    const recentTxs = await fetchEtherscan({
      module: 'account',
      action: 'txlist',
      address,
      startblock: 0,
      endblock: 99999999,
      page: 1,
      offset: 100,
      sort: 'desc',
    });
    meta.recentTxCount = recentTxs ? recentTxs.length : 0;

    if (meta.recentTxCount === 0) {
      findings.push({
        severity: 'medium',
        label: 'no_activity',
        name: 'No recent transactions',
        detail: 'Contract has no transaction history — low usage or brand new',
      });
    } else if (meta.recentTxCount >= 10) {
      findings.push({
        severity: 'good',
        label: 'active_contract',
        name: `Active contract (${meta.recentTxCount}+ recent txs)`,
        detail: 'Contract shows regular usage',
      });
    }
  } catch { /* skip */ }

  // ─── Compute risk score ────────────────────────────────────────────────────

  const riskScore = computeRiskScore(findings);
  const riskLabel = riskScore >= 70 ? 'CRITICAL' :
                    riskScore >= 50 ? 'HIGH' :
                    riskScore >= 30 ? 'MEDIUM' :
                    riskScore >= 10 ? 'LOW' : 'SAFE';

  // ─── Build result ─────────────────────────────────────────────────────────

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings     = findings.filter(f => f.severity === 'high');
  const mediumFindings   = findings.filter(f => f.severity === 'medium');
  const goodFindings     = findings.filter(f => f.severity === 'good');

  const summaryParts = [
    `RISK:${riskScore}/${riskLabel}`,
    criticalFindings.length > 0 ? `critical:${criticalFindings.map(f => f.label).join(',')}` : null,
    highFindings.length > 0     ? `high:${highFindings.map(f => f.label).join(',')}` : null,
    mediumFindings.length > 0   ? `medium:${mediumFindings.map(f => f.label).join(',')}` : null,
    `age:${meta.agedays ?? '?'}d`,
    meta.sourceVerified ? 'verified:YES' : 'verified:NO',
  ].filter(Boolean).join(' | ');

  const result = {
    address,
    timestamp: new Date().toISOString(),
    riskScore,
    riskLabel,
    meta,
    findings,
    summary: summaryParts.slice(0, 500), // max 500 chars for on-chain
    criticalCount:  criticalFindings.length,
    highCount:      highFindings.length,
    mediumCount:    mediumFindings.length,
    goodCount:      goodFindings.length,
  };

  // Compute result hash (keccak256 of full JSON)
  const resultJson = JSON.stringify(result);
  result.resultHash = '0x' + createHash('sha256').update(resultJson).digest('hex');
  // Note: using sha256 here, contract uses bytes32 — compatible

  return result;
}

// ─── Print helper ──────────────────────────────────────────────────────────────

function printResult(result) {
  if (result.error) {
    console.log(`\n❌ Error: ${result.error}`);
    return;
  }

  const emoji = result.riskScore >= 70 ? '🔴' :
                result.riskScore >= 50 ? '🟠' :
                result.riskScore >= 30 ? '🟡' :
                result.riskScore >= 10 ? '🟢' : '✅';

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`${emoji}  RISK SCORE: ${result.riskScore}/100 — ${result.riskLabel}`);
  console.log(`${'═'.repeat(60)}`);
  console.log(`Contract  : ${result.address}`);
  console.log(`Name      : ${result.meta.contractName || '?'}`);
  console.log(`Age       : ${result.meta.agedays ?? '?'} days`);
  console.log(`Verified  : ${result.meta.sourceVerified ? '✅ Yes' : '❌ No'}`);
  console.log(`Bytecode  : ${result.meta.bytecodeSize} bytes`);
  console.log(`Txs (recent): ${result.meta.recentTxCount ?? '?'}`);
  console.log(`\nFindings:`);

  const severityOrder = ['critical', 'high', 'medium', 'info', 'good'];
  const sorted = [...result.findings].sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  for (const f of sorted) {
    const icon = { critical: '🔴', high: '🟠', medium: '🟡', info: 'ℹ️ ', good: '✅' }[f.severity] || '·';
    console.log(`  ${icon}  [${f.severity.toUpperCase().padEnd(8)}] ${f.name}`);
    if (f.detail) console.log(`          ${f.detail}`);
  }

  console.log(`\nSummary (on-chain):`);
  console.log(`  ${result.summary}`);
  console.log(`\nResult hash: ${result.resultHash}`);
  console.log(`${'═'.repeat(60)}\n`);
}

// ─── CLI entry point ──────────────────────────────────────────────────────────

if (process.argv[1]?.endsWith('scanner.js')) {
  const address = process.argv[2];
  if (!address) {
    console.error('Usage: node research/scanner.js <contractAddress>');
    process.exit(1);
  }

  scanContract(address)
    .then(result => {
      printResult(result);
    })
    .catch(err => {
      console.error('Scan failed:', err.message);
      process.exit(1);
    });
}
