// Explicit, offline data conversion. Download and inspect the two public source
// files separately; the application and this builder never upload observed IPs.
// node scripts/build-geo-data.mjs <dbip-country-lite-YYYY-MM.csv.gz> <natural-earth.geojson>
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { basename } from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { parseAddress, decodeDatabase } = require('../desktop/geolocation.cjs');
const [csvPath, earthPath] = process.argv.slice(2);
if (!csvPath || !earthPath) throw new Error('Supply DB-IP Lite country CSV.gz and Natural Earth 50m countries GeoJSON source paths.');
const release = basename(csvPath).match(/dbip-country-lite-(\d{4}-\d{2})\.csv\.gz$/)?.[1];
if (!release) throw new Error('Expected DB-IP Lite country monthly source filename.');
const [csvSource, earthSource] = await Promise.all([readFile(csvPath), readFile(earthPath)]);
const lines = gunzipSync(csvSource, { maxOutputLength: 60 * 1024 * 1024 }).toString('utf8').trim().split(/\r?\n/);
const rows = [[], []];
for (const line of lines) {
  const [startIp, endIp, country, ...extra] = line.split(',');
  const start = parseAddress(startIp), end = parseAddress(endIp);
  if (!start || !end || start.family !== end.family || !/^[A-Z]{2}$/.test(country) || extra.length) throw new Error('Invalid source row.');
  rows[start.family === 4 ? 0 : 1].push({ start: start.value, end: end.value, country });
}
rows.forEach((table) => table.sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
const buffer = Buffer.alloc(32 + rows[0].length * 10 + rows[1].length * 34);
buffer.write('LMGEO1\0\0', 0, 'ascii');
buffer.write(release, 8, 'ascii');
buffer.writeUInt32BE(rows[0].length, 16);
buffer.writeUInt32BE(rows[1].length, 20);
let offset = 32;
for (let index = 0; index < rows.length; index++) {
  for (const row of rows[index]) {
    if (index === 0) {
      buffer.writeUInt32BE(Number(row.start), offset);
      buffer.writeUInt32BE(Number(row.end), offset + 4);
      buffer.write(row.country, offset + 8, 'ascii');
      offset += 10;
    } else {
      for (const value of [row.start, row.end]) {
        buffer.writeBigUInt64BE(value >> 64n, offset);
        buffer.writeBigUInt64BE(value & 0xffffffffffffffffn, offset + 8);
        offset += 16;
      }
      buffer.write(row.country, offset, 'ascii');
      offset += 2;
    }
  }
}
decodeDatabase(buffer);
const compressed = gzipSync(buffer, { level: 9 });
const earth = JSON.parse(earthSource.toString('utf8'));
const countries = {};
const labelPopulations = {};
const project = ([longitude, latitude]) => [(longitude + 180) * 1000 / 360, (90 - latitude) * 500 / 180];
function simplify(points, first = 0, last = points.length - 1) {
  const a = points[first], b = points[last];
  const dx = b[0] - a[0], dy = b[1] - a[1];
  let maximum = 0.25 ** 2, at = -1;
  for (let i = first + 1; i < last; i++) {
    const p = points[i];
    const t = dx || dy ? Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy))) : 0;
    const distance = (p[0] - a[0] - t * dx) ** 2 + (p[1] - a[1] - t * dy) ** 2;
    if (distance > maximum) { maximum = distance; at = i; }
  }
  return at === -1 ? [a, b] : [...simplify(points, first, at).slice(0, -1), ...simplify(points, at, last)];
}
const paths = [];
for (const feature of earth.features) {
  const props = feature.properties;
  const code = /^[A-Z]{2}$/.test(props.ISO_A2_EH) ? props.ISO_A2_EH : props.ISO_A2;
  // Several Natural Earth features can share one ISO country code (Australia
  // and its external territories). Use the most populated feature's label;
  // otherwise source ordering can place the country dot on a tiny territory.
  if (/^[A-Z]{2}$/.test(code) && Number.isFinite(props.LABEL_X) && Number.isFinite(props.LABEL_Y) &&
      (!countries[code] || Number(props.POP_EST) > labelPopulations[code])) {
    countries[code] = { code, name: props.NAME_EN || props.ADMIN, nameDe: props.NAME_DE || props.NAME_EN || props.ADMIN, longitude: props.LABEL_X, latitude: props.LABEL_Y };
    labelPopulations[code] = Number(props.POP_EST) || 0;
  }
  const polygons = feature.geometry.type === 'Polygon' ? [feature.geometry.coordinates] : feature.geometry.coordinates;
  const path = polygons.map((polygon) => polygon.map((ring) => {
    const coordinates = simplify(ring.map(project)).map((point) => point.map((value) => value.toFixed(2))).filter((point, i, all) => !i || point.join(',') !== all[i - 1].join(','));
    return `M${coordinates.map((point) => point.join(',')).join('L')}Z`;
  }).join('')).join('');
  paths.push(`<path d="${path}"/>`);
}
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 500"><g fill="#19363b" stroke="#3c6065" stroke-width="0.45" stroke-linejoin="round">${paths.join('')}</g></svg>\n`;
const hash = (data) => createHash('sha256').update(data).digest('hex');
const provenance = {
  schema: 1,
  database: { provider: 'DB-IP Lite', release, source: `https://download.db-ip.com/free/dbip-country-lite-${release}.csv.gz`, sourceSha256: hash(csvSource), sourceRecords: lines.length, license: 'CC-BY-4.0', licenseUrl: 'https://creativecommons.org/licenses/by/4.0/', attributionUrl: 'https://db-ip.com', precision: 'country', ipv4Records: rows[0].length, ipv6Records: rows[1].length, file: 'geo-country.bin.gz', sha256: hash(compressed) },
  map: { provider: 'Natural Earth', source: 'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson', sourceSha256: hash(earthSource), license: 'Public domain', licenseUrl: 'https://www.naturalearthdata.com/about/terms-of-use/', scale: '1:50m', transformations: 'Country label coordinates and names extracted. Equirectangular map paths projected to 1000x500, simplified by 0.25 display units and rounded to 0.01 unit. Markers use country labels, never server coordinates.' },
};
await Promise.all([mkdir('desktop/data', { recursive: true }), mkdir('src/assets', { recursive: true })]);
await Promise.all([
  writeFile('desktop/data/geo-country.bin.gz', compressed),
  writeFile('desktop/data/geo-provenance.json', `${JSON.stringify(provenance, null, 2)}\n`),
  writeFile('src/assets/geo-countries.json', `${JSON.stringify(countries)}\n`),
  writeFile('src/assets/geo-world.svg', svg),
]);
console.log(JSON.stringify({ release, ranges: lines.length, countries: Object.keys(countries).length, compressedBytes: compressed.length, svgBytes: Buffer.byteLength(svg), sha256: hash(compressed) }));
