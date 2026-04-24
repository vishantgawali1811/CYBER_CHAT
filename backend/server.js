import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'csv-parse/sync';

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

const datasetPath = path.resolve('..', 'ml', 'dataset_fixed.csv');

app.get('/', (_req, res) => {
  res.type('html').send(`
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Cyber ML Backend</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: #02050a;
            color: #dffcff;
            font-family: monospace;
          }
          .card {
            max-width: 760px;
            margin: 24px;
            padding: 24px;
            border: 1px solid rgba(43, 246, 255, 0.35);
            border-radius: 16px;
            background: rgba(7, 18, 34, 0.9);
          }
          a { color: #2bf6ff; }
          p { line-height: 1.5; }
        </style>
      </head>
      <body>
        <main class="card">
          <h1>Cyber ML Backend Online</h1>
          <p>The API server is running. Use the endpoints below:</p>
          <ul>
            <li><a href="/api/health">/api/health</a></li>
            <li><a href="/api/ml/stats">/api/ml/stats</a></li>
          </ul>
          <p>Chat endpoint: POST /api/chat</p>
          <p>Prediction endpoint: POST /api/ml/predict</p>
        </main>
      </body>
    </html>
  `);
});

function loadDataset() {
  const csvText = fs.readFileSync(datasetPath, 'utf-8');
  const records = parse(csvText, {
    columns: true,
    skip_empty_lines: true,
    trim: true
  });

  const byCve = new Map();
  for (const record of records) {
    if (!byCve.has(record.cve_id)) {
      byCve.set(record.cve_id, []);
    }
    byCve.get(record.cve_id).push(record);
  }

  return {
    records,
    byCve
  };
}

let data;
try {
  data = loadDataset();
} catch (error) {
  console.error('Failed to load dataset_fixed.csv:', error.message);
  data = {
    records: [],
    byCve: new Map()
  };
}

function predictRisk({ cvss, attack_vector, privileges, exploit }) {
  let score = Number(cvss) || 0;

  if ((attack_vector || '').toUpperCase() === 'NETWORK') {
    score += 1.0;
  }

  if ((privileges || '').toUpperCase() === 'NONE') {
    score += 0.7;
  }

  if (String(exploit).toLowerCase() === 'true') {
    score += 1.2;
  }

  if (score >= 9) {
    return 'CRITICAL';
  }
  if (score >= 7) {
    return 'HIGH';
  }
  if (score >= 4) {
    return 'MEDIUM';
  }
  return 'LOW';
}

function labelDistribution(records) {
  const counts = {};
  for (const item of records) {
    const key = item.label || 'UNKNOWN';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function normalizeText(value) {
  return String(value || '').trim().toLowerCase();
}

function compareVersion(recordVersion, inputVersion) {
  const left = normalizeText(recordVersion);
  const right = normalizeText(inputVersion);

  if (!left || !right) {
    return false;
  }

  return left === right || left.includes(right) || right.includes(left);
}

function summarizeMatches(matches) {
  const distribution = labelDistribution(matches);
  const topLabel = Object.entries(distribution).sort((left, right) => right[1] - left[1])[0]?.[0] || 'UNKNOWN';
  const maxCvss = matches.reduce((highest, record) => Math.max(highest, Number(record.cvss) || 0), 0);
  const sampleCves = [...new Set(matches.map((record) => record.cve_id))].slice(0, 5);

  return {
    topLabel,
    maxCvss,
    sampleCves,
    distribution
  };
}

function formatMatchLine(record) {
  return [
    `CVE: ${record.cve_id}`,
    `Product: ${record.product}`,
    `Version Rule: ${record.version_rule}`,
    `CVSS: ${record.cvss}`,
    `Risk: ${record.risk}`
  ].join('\n');
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    records: data.records.length,
    uniqueCves: data.byCve.size
  });
});

app.get('/api/ml/stats', (_req, res) => {
  res.json({
    records: data.records.length,
    uniqueCves: data.byCve.size,
    labelDistribution: labelDistribution(data.records)
  });
});

app.post('/api/ml/predict', (req, res) => {
  const payload = req.body || {};
  const label = predictRisk(payload);
  res.json({
    predicted_label: label,
    input: payload
  });
});

app.post('/api/ml/analyze-stack', (req, res) => {
  const product = normalizeText(req.body?.product);
  const version = normalizeText(req.body?.version);

  if (!product || !version) {
    return res.status(400).json({
      error: 'product and version are required'
    });
  }

  const matches = data.records.filter((record) => {
    const recordProduct = normalizeText(record.product);
    const recordVersion = normalizeText(record.version);
    return recordProduct === product && compareVersion(recordVersion, version);
  });

  const productOnlyMatches = data.records
    .filter((record) => normalizeText(record.product) === product)
    .sort((left, right) => (Number(right.cvss) || 0) - (Number(left.cvss) || 0));

  const responseMatches = (matches.length > 0 ? matches : productOnlyMatches).slice(0, 6);

  const detailedMatches = responseMatches.map((record) => {
    const operator = String(record.operator || '').trim();
    const versionField = String(record.version || '').trim();
    return {
      cve_id: record.cve_id,
      product: record.product,
      version_rule: operator ? `${operator} ${versionField}` : versionField,
      cvss: Number(record.cvss) || 0,
      risk: record.label
    };
  });

  const heading = matches.length > 0 ? 'Exact / Closest Version Matches' : 'Closest Product Matches';
  const body = detailedMatches.length > 0
    ? detailedMatches
        .map((entry, index) => [`${index + 1})`, formatMatchLine(entry)].join('\n'))
        .join('\n----------------------------------------\n')
    : 'No match records found for this input.';

  const responseText = [
    `Target: ${product} ${version}`,
    '',
    `${heading}:`,
    '',
    body
  ].join('\n');

  const summary = matches.length > 0
    ? summarizeMatches(matches)
    : {
        topLabel: 'UNKNOWN',
        maxCvss: 0,
        sampleCves: [],
        distribution: {}
      };

  const fallbackScore = Math.min(10, Math.max(0, version.length / 2 + (product.length > 8 ? 1 : 0)));
  const fallbackLabel = fallbackScore >= 8.5 ? 'CRITICAL' : fallbackScore >= 7 ? 'HIGH' : fallbackScore >= 4 ? 'MEDIUM' : 'LOW';

  res.json({
    input: { product, version },
    matchedRows: matches.length,
    predicted_label: matches.length > 0 ? summary.topLabel : fallbackLabel,
    confidence: matches.length > 0 ? Math.min(0.99, 0.45 + matches.length / 120) : 0.35,
    max_cvss: summary.maxCvss,
    sample_cves: summary.sampleCves,
    label_distribution: summary.distribution,
    detailed_matches: detailedMatches,
    response_text: responseText,
    summary: matches.length > 0
      ? `Found ${matches.length} dataset rows for ${product} ${version}. The most common label is ${summary.topLabel}.`
      : `No exact dataset match for ${product} ${version}. A heuristic fallback label of ${fallbackLabel} was generated from the input pattern.`
  });
});

app.post('/api/chat', (req, res) => {
  const text = String(req.body?.message || '');
  const lower = text.toLowerCase();

  const cveMatch = text.match(/cve-\d{4}-\d{4,7}/i);
  if (cveMatch) {
    const cveId = cveMatch[0].toUpperCase();
    const rows = data.byCve.get(cveId);

    if (!rows || rows.length === 0) {
      return res.json({
        reply: `No dataset rows found for ${cveId}.` 
      });
    }

    const first = rows[0];
    const response = [
      `${cveId}: ${first.description}`,
      `CVSS ${first.cvss}, vector ${first.attack_vector}, privileges ${first.privileges}, label ${first.label}.`,
      `Affected product sample: ${first.product} ${first.operator} ${first.version}.`,
      `Rows in dataset for this CVE: ${rows.length}.`
    ].join(' ');

    return res.json({ reply: response });
  }

  if (lower.includes('dataset') || lower.includes('stats')) {
    return res.json({
      reply: `Dataset loaded: ${data.records.length} rows, ${data.byCve.size} unique CVE IDs. Ask with a CVE ID (e.g., CVE-2024-0008) for targeted context.`
    });
  }

  if (lower.includes('predict') || lower.includes('risk')) {
    return res.json({
      reply: 'Use /api/ml/predict with cvss, attack_vector, privileges, and exploit to get a quick risk label. Example payload: {"cvss":8.2,"attack_vector":"NETWORK","privileges":"NONE","exploit":true}.'
    });
  }

  return res.json({
    reply: 'Cyber ML API online. Ask about dataset stats, include a CVE ID, or ask for prediction guidance.'
  });
});

app.listen(port, () => {
  console.log(`Cyber ML backend listening at http://localhost:${port}`);
});