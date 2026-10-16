import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareNetlist } from '../src/netlist.js';

function design({ input = 'a', type = '$not' } = {}) {
  return {
    modules: {
      main: {
        attributes: { top: 1 },
        ports: { [input]: { direction: 'input', bits: [2] }, y: { direction: 'output', bits: [3] } },
        cells: {
          u: {
            type,
            parameters: {},
            port_directions: { A: 'input', Y: 'output' },
            connections: { A: [2], Y: [3] },
          },
        },
        netnames: {},
      },
    },
  };
}

test('module type markup remains text through the full SVG rendering pipeline', async () => {
  const type = '</text><script>globalThis.__hdlabXss=1</script><text>';
  const result = await prepareNetlist(JSON.stringify(design({ type })));
  assert.ok(result?.svg, 'drawing should still succeed');
  assert.doesNotMatch(result.svg, /<script\b/i);
  assert.ok(result.svg.includes('&lt;script&gt;'), 'payload must be rendered as escaped text');
});

test('quotes in port names cannot introduce SVG event handlers', async () => {
  const input = 'x" onload="globalThis.__hdlabXss=1';
  const result = await prepareNetlist(JSON.stringify(design({ input })));
  assert.ok(result?.svg, 'drawing should still succeed');
  assert.doesNotMatch(result.svg, /\sonload="/i);
  assert.ok(result.svg.includes('&quot; onload=&quot;'), 'quotes must remain inside the attribute value');
});

test('ordinary gate labels and submodule hotspots survive escaping', async () => {
  const gate = await prepareNetlist(JSON.stringify(design()));
  assert.ok(gate?.svg.includes('>NOT</text>'));
  const module = await prepareNetlist(JSON.stringify(design({ type: 'alu&control' })));
  assert.ok(module?.svg.includes('alu&amp;control'));
  assert.equal(module.hotspots.length, 1);
  assert.equal(module.hotspots[0].cell, 'u');
});
