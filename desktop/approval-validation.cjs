'use strict';

const { validateRule } = require('./validation.cjs');
const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[1-9][0-9]{0,9}$/i;
const DECISIONS = new Set(['allow-endpoint', 'allow-program', 'deny']);

function validateApprovalRequest(operation, payload) {
  if (['status', 'start', 'stop'].includes(operation)) {
    if (payload !== undefined) throw new Error('This approval operation takes no arguments.');
    return undefined;
  }
  if (operation === 'decide') {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || Object.keys(payload).some((key) => !['id', 'decision'].includes(key))
      || typeof payload.id !== 'string' || !ATTEMPT_ID.test(payload.id) || !DECISIONS.has(payload.decision)) {
      throw new Error('An exact pending attempt and a supported decision are required.');
    }
    return { id: payload.id, decision: payload.decision };
  }
  throw new Error('Unsupported approval operation.');
}

function validateTestProgram(program) {
  const normalized = validateRule({ program, action: 'block', direction: 'out', protocol: 'ANY' }).program;
  if (!/^LimenApprovalProbe-[a-z0-9-]+\.exe$/i.test(normalized.split('\\').at(-1))) {
    throw new Error('Use a dedicated LimenApprovalProbe executable for scoped tests.');
  }
  return normalized;
}

module.exports = { validateApprovalRequest, validateTestProgram };
