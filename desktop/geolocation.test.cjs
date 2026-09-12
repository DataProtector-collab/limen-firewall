'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createGeolocation, parseAddress, isPublicAddress, decodeDatabase, validateAddresses } = require('./geolocation.cjs');

test('GeoIP rejects hostnames, malformed IPs and oversized IPC requests', () => {
  for (const input of [undefined, {}, '8.8.8.8', [null], ['example.com'], ['8.8.8.8 '], ['010.0.0.1'], ['1.2.3.999'], ['::::'], Array(513).fill('8.8.8.8')]) {
    assert.throws(() => validateAddresses(input), /literal IP/);
  }
  assert.deepEqual(validateAddresses(['8.8.8.8', '8.8.8.8']), ['8.8.8.8']);
});

test('GeoIP handles IPv6 compression, mixed notation and excludes local / special ranges', () => {
  assert.deepEqual(parseAddress('2001:4860:4860::8888'), parseAddress('2001:4860:4860:0:0:0:0:8888'));
  assert.deepEqual(parseAddress('::ffff:8.8.8.8'), parseAddress('8.8.8.8'));
  assert.deepEqual(parseAddress('::ffff:808:808'), parseAddress('8.8.8.8'));
  for (const ip of ['0.0.0.0', '10.1.2.3', '100.64.1.1', '127.0.0.1', '169.254.1.1', '172.16.1.2', '192.168.2.3', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::', '::1', 'fe80::1%12', 'fc00::1', 'ff02::1', '2001:db8::1', '3fff::1', '2001:2::1', '2002:808:808::1', '::ffff:127.0.0.1']) {
    assert.equal(isPublicAddress(parseAddress(ip)), false, ip);
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '2001:4860:4860::8888', '2606:4700:4700::1111']) assert.equal(isPublicAddress(parseAddress(ip)), true, ip);
});

test('GeoIP database decoder rejects corruption, overlaps and impossible dimensions', () => {
  assert.throws(() => decodeDatabase(Buffer.from('bad')), /Invalid/);
  const buffer = Buffer.alloc(52);
  buffer.write('LMGEO1\0\0'); buffer.write('2026-09', 8); buffer.writeUInt32BE(2, 16);
  buffer.writeUInt32BE(10, 32); buffer.writeUInt32BE(20, 36); buffer.write('US', 40);
  buffer.writeUInt32BE(20, 42); buffer.writeUInt32BE(25, 46); buffer.write('DE', 50);
  assert.throws(() => decodeDatabase(buffer), /range/);
  buffer.writeUInt32BE(21, 42);
  const decoded = decodeDatabase(buffer);
  assert.equal(decoded.find({ family: 4, value: 10n }), 'US');
  assert.equal(decoded.find({ family: 4, value: 20n }), 'US');
  assert.equal(decoded.find({ family: 4, value: 21n }), 'DE');
  assert.equal(decoded.find({ family: 4, value: 25n }), 'DE');
  assert.equal(decoded.find({ family: 4, value: 26n }), null);
  assert.throws(() => decodeDatabase(buffer.subarray(0, 51)), /dimensions/);
});

test('Bundled offline database resolves IPv4, IPv6 and mapped IPv4 without network access', async () => {
  const geo = createGeolocation({ databasePath: path.join(__dirname, 'data/geo-country.bin.gz') });
  const result = await geo.lookup(['8.8.8.8', '::ffff:8.8.8.8', '2001:4860:4860::8888', '127.0.0.1', '2001:db8::1']);
  assert.equal(result.database.release, '2026-09');
  assert.equal(result.database.precision, 'country');
  // The September source CSV assigns Google's anycast IPv6 range to CA.
  // Assert the source attribution, not an invented physical server location.
  assert.deepEqual(result.results.slice(0, 3).map((row) => [row.status, row.countryCode]), [['located', 'US'], ['located', 'US'], ['located', 'CA']]);
  assert.deepEqual(result.results.slice(3).map((row) => row.status), ['non-public', 'non-public']);
});
