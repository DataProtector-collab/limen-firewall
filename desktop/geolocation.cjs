'use strict';

const { isIP } = require('node:net');
const { readFile } = require('node:fs/promises');
const { promisify } = require('node:util');
const { gunzip } = require('node:zlib');
const unzip = promisify(gunzip);
const MAGIC = Buffer.from('LMGEO1\0\0');
const MAX_ADDRESSES = 512;
const MAX_DATABASE_BYTES = 40 * 1024 * 1024;

function parseAddress(input) {
  if (typeof input !== 'string' || input.length > 64 || input !== input.trim()) return null;
  const family = isIP(input);
  if (!family) return null;
  let ip = input;
  if (family === 4) {
    return { family, value: ip.split('.').reduce((value, part) => value * 256n + BigInt(part), 0n) };
  }
  ip = ip.split('%')[0].toLowerCase();
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');
    const mapped = parseAddress(ip.slice(lastColon + 1));
    if (!mapped || mapped.family !== 4) return null;
    ip = `${ip.slice(0, lastColon + 1)}${(mapped.value >> 16n).toString(16)}:${(mapped.value & 65535n).toString(16)}`;
  }
  const halves = ip.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  const value = words.reduce((total, word) => (total << 16n) | BigInt(`0x${word}`), 0n);
  // Windows can expose IPv4 peers through IPv4-mapped IPv6 sockets.
  return value >> 32n === 65535n ? { family: 4, value: value & 0xffffffffn } : { family, value };
}

const v4Excluded = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 3],
].map(([ip, bits]) => ({ value: parseAddress(ip).value, shift: BigInt(32 - bits) }));
const v6Excluded = [
  ['2001::', 23], ['2001:db8::', 32], ['3fff::', 20], ['2002::', 16],
].map(([ip, bits]) => ({ value: parseAddress(ip).value, shift: BigInt(128 - bits) }));

function isPublicAddress(address) {
  if (address.family === 4) return !v4Excluded.some(({ value, shift }) => address.value >> shift === value >> shift);
  // Plot only native global-unicast space. Local, multicast, documentation and
  // transition addresses cannot establish a reliable country attribution.
  const value = address.value;
  if (value >> 125n !== 1n) return false;
  return !v6Excluded.some((excluded) => value >> excluded.shift === excluded.value >> excluded.shift);
}

function read128(buffer, offset) {
  return (buffer.readBigUInt64BE(offset) << 64n) | buffer.readBigUInt64BE(offset + 8);
}

function decodeDatabase(buffer) {
  if (buffer.length < 32 || buffer.length > MAX_DATABASE_BYTES || !buffer.subarray(0, 8).equals(MAGIC)) {
    throw new Error('Invalid offline geolocation database.');
  }
  const release = buffer.toString('ascii', 8, 15);
  const v4Count = buffer.readUInt32BE(16);
  const v6Count = buffer.readUInt32BE(20);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(release) || buffer.length !== 32 + v4Count * 10 + v6Count * 34) {
    throw new Error('Invalid offline geolocation database dimensions.');
  }
  const tables = [
    { family: 4, offset: 32, count: v4Count, stride: 10, width: 4 },
    { family: 6, offset: 32 + v4Count * 10, count: v6Count, stride: 34, width: 16 },
  ];
  for (const table of tables) {
    let previous = -1n;
    for (let index = 0; index < table.count; index++) {
      const offset = table.offset + index * table.stride;
      const start = table.family === 4 ? BigInt(buffer.readUInt32BE(offset)) : read128(buffer, offset);
      const end = table.family === 4 ? BigInt(buffer.readUInt32BE(offset + 4)) : read128(buffer, offset + 16);
      const code = buffer.toString('ascii', offset + table.width * 2, offset + table.width * 2 + 2);
      if (start <= previous || end < start || !/^[A-Z]{2}$/.test(code)) throw new Error('Invalid offline geolocation database range.');
      previous = end;
    }
  }
  function find(address) {
    const table = tables[address.family === 4 ? 0 : 1];
    let low = 0;
    let high = table.count - 1;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      const offset = table.offset + middle * table.stride;
      const start = table.family === 4 ? BigInt(buffer.readUInt32BE(offset)) : read128(buffer, offset);
      const end = table.family === 4 ? BigInt(buffer.readUInt32BE(offset + 4)) : read128(buffer, offset + 16);
      if (address.value < start) high = middle - 1;
      else if (address.value > end) low = middle + 1;
      else return buffer.toString('ascii', offset + table.width * 2, offset + table.width * 2 + 2);
    }
    return null;
  }
  return { release, find };
}

function validateAddresses(input) {
  if (!Array.isArray(input) || input.length > MAX_ADDRESSES || input.some((ip) => !parseAddress(ip))) {
    throw new Error('Geolocation accepts at most 512 literal IP addresses.');
  }
  return [...new Set(input)];
}

function createGeolocation({ databasePath }) {
  let database;
  async function load() {
    if (!database) {
      database = readFile(databasePath).then((compressed) => {
        if (compressed.length > MAX_DATABASE_BYTES) throw new Error('Offline geolocation database is too large.');
        return unzip(compressed, { maxOutputLength: MAX_DATABASE_BYTES });
      }).then(decodeDatabase).catch((error) => { database = null; throw error; });
    }
    return database;
  }
  return {
    async lookup(input) {
      const addresses = validateAddresses(input);
      const data = await load();
      return {
        database: { provider: 'DB-IP Lite', release: data.release, precision: 'country', attributionUrl: 'https://db-ip.com' },
        results: addresses.map((ip) => {
          const address = parseAddress(ip);
          if (!isPublicAddress(address)) return { ip, status: 'non-public' };
          const countryCode = data.find(address);
          return countryCode && !['ZZ', 'XX'].includes(countryCode)
            ? { ip, status: 'located', countryCode } : { ip, status: 'unknown' };
        }),
      };
    },
  };
}

module.exports = { createGeolocation, parseAddress, isPublicAddress, decodeDatabase, validateAddresses, MAX_ADDRESSES };
