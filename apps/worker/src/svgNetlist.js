// netlistsvg/onml serializes names and labels without XML escaping. Escape all
// netlist strings, including object keys used as SVG IDs, at the rendering boundary.
// Keep the original netlist intact for hierarchy analysis and hotspot matching.
const escapeXml = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

export function escapeNetlistForSvg(value) {
  if (typeof value === 'string') return escapeXml(value);
  if (Array.isArray(value)) return value.map(escapeNetlistForSvg);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .map(([key, entry]) => [escapeXml(key), escapeNetlistForSvg(entry)]));
  }
  return value;
}
