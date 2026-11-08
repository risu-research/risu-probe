
// Independent RISU P6-B8 holdout adapter. This is a test-only append to the
// pinned upstream checkout, not a modification of its product implementation.
it('RISU P6B8 CYAN846 frozen capture', async () => {
  const resultPath = process.env.RISU_B8_CAPTURE_PATH;
  if (!resultPath) throw new Error('RISU_B8_CAPTURE_PATH is required');
  const flagTool = tool('cyan846_flag', {
    description: 'Public synthetic parser regression',
    input: z.object({ flag: z.string().describe('Flag source') }),
    output: z.object({ flag: z.stringbool().describe('Parsed flag') }),
    handler: (args) => ({ flag: args.flag }) as never,
  });
  const server = new McpServer(
    { name: 'risu-frozen-cyan846', version: '0.0.0' },
    { capabilities: { tools: {} } },
  );
  await new ToolRegistry([flagTool], services).registerAll(server);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'risu-heldout-client', version: '0.0.0' });
  let capture: Record<string, unknown> = {
    case: 'CYAN846', transport: 'ACTUAL_SDK_IN_MEMORY_NOT_STDIO_WIRE',
  };
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const listing = await client.listTools();
    const args = { flag: 'true' };
    try {
      const actualResult = await client.callTool({ name: 'cyan846_flag', arguments: args });
      capture = {
        ...capture, status: 'SDK_RESULT',
        rows: [
          { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
          { jsonrpc: '2.0', id: 1, result: { tools: listing.tools } },
          { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'cyan846_flag', arguments: args } },
          { jsonrpc: '2.0', id: 2, result: actualResult },
        ],
      };
    } catch (e) {
      capture = {
        ...capture, status: 'SDK_CALL_THROWN',
        errorType: e instanceof Error ? e.name : 'Unknown',
      };
    }
  } finally {
    await client.close();
    await server.close();
  }
  const fs = await import('node:fs/promises');
  await fs.writeFile(resultPath, JSON.stringify(capture, null, 2)+'\n', 'utf8');
  expect(capture.status).toMatch(/SDK_RESULT|SDK_CALL_THROWN/);
});
