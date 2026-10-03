export function replacementDemo(stage) {
  if (!['before', 'after'].includes(stage)) throw new Error('Unknown replacement demo stage');
  const lodash = stage === 'before' ? '4.17.20' : '4.18.1';
  return { bomFormat: 'CycloneDX', specVersion: '1.7', version: stage === 'before' ? 1 : 2,
    serialNumber: 'urn:uuid:2c1787c5-668f-4f04-b1a6-a0d8ca53542d',
    components: [{ type: 'library', 'bom-ref': 'lodash', name: 'lodash', version: lodash, purl: `pkg:npm/lodash@${lodash}` },
      { type: 'library', 'bom-ref': 'minimist', name: 'minimist', version: '1.2.5', purl: 'pkg:npm/minimist@1.2.5' }] };
}
