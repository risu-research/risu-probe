/** P6-B10 prelocked new source holdout, copied into original upstream repo root.
 * No actual production data, credentials, live MCP server, or network service calls.
 * Records genuine upstream helper result strings; JSON-RPC framing is later reconstructed.
 */
import { writeFileSync } from 'node:fs';

const family = process.env.RISU_B10_FAMILY;
const output = process.env.RISU_B10_CAPTURE;
if (!output || !['GEONAMES28','OPENALEX128','MITRECWE16'].includes(family ?? '')) {
  throw new Error('Pinned public upstream family and output required');
}

let issue = { raw: '', rendered: '' };
let normal = { raw: '', rendered: '' };
if (family === 'GEONAMES28') {
  const { inlineText } = await import('./src/utils/inline-text.ts');
  const raw = 'www.example.com';
  issue = {raw, rendered: inlineText(raw)};
  const control = 'Harbor';
  normal = {raw: control, rendered: inlineText(control)};
} else if (family === 'OPENALEX128') {
  const { escapeMarkdown } = await import('./src/mcp-server/tools/escape-markdown.ts');
  const raw = 'alpha\nbeta';
  issue = {raw, rendered: escapeMarkdown(raw, 'inline')};
  const control = 'ordinary text';
  normal = {raw: control, rendered: escapeMarkdown(control, 'inline')};
} else if (family === 'MITRECWE16') {
  const { formatCatalog } = await import('./src/mcp-server/tools/shared.ts');
  const raw = 'CWE-80';
  issue = {raw, rendered: formatCatalog({literal: raw})[0].text.split('\\n\\n').at(-1)!};
  const control = 'ordinary';
  normal = {raw: control, rendered: formatCatalog({literal: control})[0].text.split('\\n\\n').at(-1)!};
}

writeFileSync(output, JSON.stringify({
  schema:'risu-p6b10-real-source-display-v1',
  family,
  origin:'REAL_PINNED_UPSTREAM_HELPER_OUTPUT_ADAPTER_JSONRPC_NOT_STDIO',
  issue,
  normal,
}, null, 2)+'\n', {encoding:'utf8',flag:'wx'});
console.log('RISU_B10_ACTUAL_UPSTREAM_RENDER_FUNCTION_EXECUTED',family);
