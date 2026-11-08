
/** RISU P6-B9 test-only, appended to original pinned upstream enrichment.test.ts.
 * Original product source unchanged. Uses its real handler and error builder.
 */
import { buildToolErrorResult as risuB9BuildError } from '@/mcp-server/tools/utils/toolResult.js';
import { JsonRpcErrorCode as RisuB9JsonRpcErrorCode } from '@/types-global/errors.js';

it('RISU P6B9 PINNED actual upstream component capture', async () => {
  const path = process.env.RISU_B9_CYAN_CAPTURE;
  const family = process.env.RISU_B9_CYAN_FAMILY;
  if (!path || (family !== 'CYAN760' && family !== 'CYAN785')) {
    throw new Error('Explicit B9 public source/family/capture required');
  }
  let record: Record<string, unknown> = {
    schema: 'risu-p6b9-cyan-authentic-framework-v1',
    family,
    component_origin: 'ACTUAL_UPSTREAM_SOURCE_UNIT_EXECUTION_NOT_WIRE',
  };
  if (family === 'CYAN760') {
    const issue = risuB9BuildError(
      RisuB9JsonRpcErrorCode.InternalError, 'No running app matches "A*p*".', undefined
    );
    const control = risuB9BuildError(
      RisuB9JsonRpcErrorCode.InternalError, 'No running app matches "Safari".', undefined
    );
    record = { ...record, issue, control };
  } else {
    const query = 'cat:astro-ph* AND submittedDate:[202601010000 TO 202602010000]';
    const normal = 'simple';
    async function invoke(value: string) {
      const def = tool('risu_b9_page', {
        description: 'Synthetic enrichment echo',
        input: z.object({}),
        output: z.object({ items: z.array(z.string()).describe('items') }),
        enrichment: { effectiveQuery: z.string().describe('query') },
        handler: (_input, ctx) => {
          ctx.enrich({ effectiveQuery: value });
          return { items: [] };
        },
      });
      const handler = createToolHandler(def as AnyToolDefinition, services, notifiers);
      return await handler({}, makeServerContext());
    }
    record = { ...record, issue: await invoke(query), control: await invoke(normal), raw_value: query };
  }
  const fs = await import('node:fs/promises');
  await fs.writeFile(path, JSON.stringify(record, null, 2)+'\n', 'utf8');
  expect(record.issue).toBeDefined();
});
