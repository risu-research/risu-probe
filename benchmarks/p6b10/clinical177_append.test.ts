
// P6-B10 test-only appended to original, pinned upstream Vitest file.
// Uses the genuine searchStudies enrichmentTrailer renderer, no service network.
it('RISU P6B10 CLINICAL177 originally pinned searchCriteria literal output', async () => {
  const output = process.env.RISU_P6B10_CLINICAL_CAPTURE;
  const revision = process.env.RISU_P6B10_CLINICAL_REV;
  if (!output || (revision !== 'old' && revision !== 'fixed')) throw Error('Missing capture settings');
  const render = searchStudies.enrichmentTrailer?.searchCriteria?.render;
  if (typeof render !== 'function') throw Error('Real upstream searchCriteria renderer unavailable');
  const value = 'SEARCH[Location](AREA[LocationCountry]"Mexico")';
  function echo(raw: string): string {
    const text = String(render({ locationQuery: raw }));
    const rows = text.split('\n').filter((line) => line.startsWith('- **locationQuery:** '));
    if (rows.length !== 1) throw Error('Expected exactly one original field output line');
    return rows[0].slice('- **locationQuery:** '.length);
  }
  const raw = { family: 'CLINICAL177', revision,
    source_execution: 'ACTUAL_PINNED_ENRICHMENT_RENDERER_TEST_ONLY',
    samples: [
      { id: 'location', raw: value, rendered: echo(value) },
      { id: 'plain', raw: 'asthma', rendered: echo('asthma') }
    ]
  };
  const fs = await import('node:fs/promises');
  await fs.writeFile(output, JSON.stringify(raw,null,2)+'\n','utf8');
  expect(raw.samples).toHaveLength(2);
});
