'use strict';

const path = require('node:path');
const net = require('node:net');

const RULE_PREFIX = 'Limen-';
const RULE_GROUP = 'Limen Firewall';
const RULE_ID = /^Limen-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validateId(id) {
  if (typeof id !== 'string' || !RULE_ID.test(id)) throw new Error('Invalid Limen rule ID.');
  return id;
}

function validateRule(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('A rule object is required.');
  const fields = new Set(['program', 'action', 'direction', 'remoteAddress', 'protocol', 'remotePort', 'localPort']);
  if (Object.keys(input).some((key) => !fields.has(key))) throw new Error('Unsupported rule property.');
  const { program, action, direction, protocol } = input;
  // A drive-qualified path excludes UNC, device paths, relative paths and alternate streams.
  if (typeof program !== 'string' || program.length > 32700 || !/^[a-z]:\\/i.test(program)
    || [...program].some((character) => character.charCodeAt(0) < 32)
    || /[<>"|?*]/.test(program) || program.slice(2).includes(':')
    || program.includes('/') || program.includes('%') || /(?:^|\\)\.\.?(?:\\|$)/.test(program)
    || path.win32.extname(program).toLowerCase() !== '.exe') {
    throw new Error('Select a full local Windows .exe path.');
  }
  if (!['allow', 'block'].includes(action)) throw new Error('Action must be allow or block.');
  if (!['in', 'out'].includes(direction)) throw new Error('Direction must be in or out.');
  if (!['TCP', 'UDP', 'ANY'].includes(protocol)) throw new Error('Protocol must be TCP, UDP or ANY.');
  const result = { program: path.win32.normalize(program), action, direction, protocol };
  if (input.remoteAddress !== undefined) {
    if (typeof input.remoteAddress !== 'string' || !net.isIP(input.remoteAddress) || input.remoteAddress.includes('%')) {
      throw new Error('Remote address must be a literal IPv4 or IPv6 address without a zone ID.');
    }
    result.remoteAddress = input.remoteAddress;
  }
  for (const field of ['remotePort', 'localPort']) {
    if (input[field] !== undefined) {
      if (protocol === 'ANY' || !Number.isInteger(input[field]) || input[field] < 1 || input[field] > 65535) {
        throw new Error('Ports must be integers from 1 to 65535 and require TCP or UDP.');
      }
      result[field] = input[field];
    }
  }
  return result;
}

function validateRequest(operation, payload) {
  switch (operation) {
    case 'status': case 'snapshot': case 'processes': case 'list':
      if (payload !== undefined) throw new Error('This operation takes no arguments.');
      return undefined;
    case 'process-inspect':
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)
        || Object.keys(payload).some((key) => !['pid', 'startedAt'].includes(key))
        || !Number.isInteger(payload.pid) || payload.pid < 1 || payload.pid > 4294967295
        || !Number.isSafeInteger(payload.startedAt) || payload.startedAt < 1 || payload.startedAt > 8640000000000000) {
        throw new Error('An exact process ID and start time are required.');
      }
      return { pid: payload.pid, startedAt: payload.startedAt };
    case 'apply': return validateRule(payload);
    case 'remove': case 'inspect': return { id: validateId(payload) };
    case 'enabled':
      if (!payload || Object.keys(payload).some((key) => !['id', 'enabled'].includes(key)) || typeof payload.enabled !== 'boolean') {
        throw new Error('An ID and a boolean enabled value are required.');
      }
      return { id: validateId(payload.id), enabled: payload.enabled };
    default: throw new Error('Unsupported native operation.');
  }
}

module.exports = { RULE_PREFIX, RULE_GROUP, validateId, validateRule, validateRequest };
