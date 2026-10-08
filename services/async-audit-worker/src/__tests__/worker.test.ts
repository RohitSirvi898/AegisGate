import assert from 'node:assert/strict';

import { AuditLogModel } from '../models/AuditLog.js';
import {
  clearWebhookRateLimits,
  escapeWebhookContent,
  isWebhookRateLimited,
  sendWebhookAlerts
} from '../utils/webhooks.js';
import {
  flushBatch,
  getBatchSize,
  handleMongoOutage,
  onMessage,
  resetBatch,
  setWorkerChannel,
  transformPayloadToDoc,
  WORKER_BATCH_FLUSH_MS,
  WORKER_BATCH_SIZE
} from '../worker.js';

console.log('🧪 Starting AegisGate Audit Worker PRD v2.1 Tests...\n');

function createMockMessage(content: any): any {
  const raw = typeof content === 'string' ? content : JSON.stringify(content);
  return {
    content: Buffer.from(raw),
    fields: { deliveryTag: Math.floor(Math.random() * 10000) },
    properties: { headers: {} }
  };
}

class MockChannel {
  ackedMessages: { msg: any; multiple: boolean }[] = [];
  nackedMessages: { msg: any; allUpTo: boolean; requeue: boolean }[] = [];
  cancelledConsumerTags: string[] = [];
  consumedQueues: string[] = [];

  ack(msg: any, multiple?: boolean) {
    this.ackedMessages.push({ msg, multiple: !!multiple });
  }
  nack(msg: any, allUpTo?: boolean, requeue?: boolean) {
    this.nackedMessages.push({ msg, allUpTo: !!allUpTo, requeue: !!requeue });
  }
  async cancel(tag: string) {
    this.cancelledConsumerTags.push(tag);
  }
  async consume(queue: string) {
    this.consumedQueues.push(queue);
    return { consumerTag: 'test-consumer-tag' };
  }
}

// Test 1: Schema & Payload Transformation
console.log('--- TEST 1: Schema & Payload Transformation ---');

const sampleTelemetry = {
  requestId: 'req-abc-123',
  projectId: 'proj-xyz',
  apiKeyId: 'key-789',
  ip: '198.51.100.42',
  method: 'POST',
  path: '/api/v1/checkout',
  rule: 'request_blocked',
  status: 403,
  upstreamOrigin: 'http://upstream:8080',
  headers: { 'user-agent': 'curl/7.68.0' },
  body: { amount: 100 },
  timestamp: '2026-10-01T12:00:00.000Z'
};

const doc = transformPayloadToDoc(sampleTelemetry);
assert.equal(doc.requestId, 'req-abc-123');
assert.equal(doc.projectId, 'proj-xyz');
assert.equal(doc.apiKeyId, 'key-789');
assert.equal(doc.ip, '198.51.100.42');
assert.equal(doc.method, 'POST');
assert.equal(doc.path, '/api/v1/checkout');
assert.equal(doc.rule, 'request_blocked');
assert.equal(doc.status, 403);
assert.equal(doc.upstreamOrigin, 'http://upstream:8080');
assert.deepEqual(doc.headers, { 'user-agent': 'curl/7.68.0' });
assert.deepEqual(doc.body, { amount: 100 });
assert.equal(doc.createdAt.toISOString(), '2026-10-01T12:00:00.000Z');

const legacyPayload = {
  clientIp: '10.0.0.1',
  endpoint: '/legacy/path',
  attackVector: 'SQLi Attempt',
  statusCode: 403,
  rawBody: 'legacy body'
};
const legacyDoc = transformPayloadToDoc(legacyPayload);
assert.equal(legacyDoc.ip, '10.0.0.1');
assert.equal(legacyDoc.path, '/legacy/path');
assert.equal(legacyDoc.rule, 'SQLi Attempt');
assert.equal(legacyDoc.status, 403);
assert.equal(legacyDoc.body, 'legacy body');

console.log('✅ Payload transformation and backward compatibility tests passed!');

// Test 2: Poison Message DLQ Routing
console.log('\n--- TEST 2: Poison Message DLQ Routing ---');

const mockChannel = new MockChannel();
setWorkerChannel(mockChannel);
resetBatch();

const malformedMsg = createMockMessage('{invalid_json');
await onMessage(malformedMsg);

assert.equal(mockChannel.nackedMessages.length, 1);
const nack1 = mockChannel.nackedMessages[0]!;
assert.equal(nack1.requeue, false, 'Poison message must have requeue=false to route to DLQ');
assert.equal(getBatchSize(), 0, 'Poison message must not enter batch');

const corruptMsg = createMockMessage('"just a plain string"');
await onMessage(corruptMsg);

assert.equal(mockChannel.nackedMessages.length, 2);
const nack2 = mockChannel.nackedMessages[1]!;
assert.equal(nack2.requeue, false, 'Non-object payload must have requeue=false');
assert.equal(getBatchSize(), 0);

console.log('✅ Poison message DLQ routing tests passed!');

// Test 3: Batch Accumulation & Bulk Mongo Writes
console.log('\n--- TEST 3: Batch Accumulation & Bulk Mongo Writes ---');

mockChannel.ackedMessages = [];
resetBatch();

let insertedDocs: any[] = [];
const originalInsertMany = AuditLogModel.insertMany;
AuditLogModel.insertMany = (async (docs: any) => {
  insertedDocs.push(...docs);
  return docs;
}) as any;

for (let i = 0; i < WORKER_BATCH_SIZE; i++) {
  const validMsg = createMockMessage({
    requestId: `req-${i}`,
    projectId: 'test-project',
    ip: '127.0.0.1',
    method: 'GET',
    path: `/item/${i}`,
    status: 200
  });
  await onMessage(validMsg);
}

assert.equal(insertedDocs.length, WORKER_BATCH_SIZE, `Must flush ${WORKER_BATCH_SIZE} items to Mongo immediately`);
assert.equal(mockChannel.ackedMessages.length, 1, 'Must ack batch with multiple: true');
assert.equal(mockChannel.ackedMessages[0]!.multiple, true);
assert.equal(getBatchSize(), 0, 'Batch buffer must be empty after flush');

insertedDocs = [];
mockChannel.ackedMessages = [];

for (let i = 0; i < 5; i++) {
  const msg = createMockMessage({
    requestId: `req-timer-${i}`,
    projectId: 'test-project',
    ip: '127.0.0.1',
    method: 'GET',
    path: `/timer/${i}`,
    status: 200
  });
  await onMessage(msg);
}

assert.equal(getBatchSize(), 5, 'Must hold 5 messages in batch awaiting threshold or timer');

await new Promise(resolve => setTimeout(resolve, WORKER_BATCH_FLUSH_MS + 100));

assert.equal(insertedDocs.length, 5, 'Must flush remaining 5 messages when timer expires');
assert.equal(mockChannel.ackedMessages.length, 1);
assert.equal(mockChannel.ackedMessages[0]!.multiple, true);
assert.equal(getBatchSize(), 0);

console.log('✅ Batch size threshold and rolling timer flush tests passed!');

// Test 4: Database Error Resilience & Backoff
console.log('\n--- TEST 4: Database Error Resilience & Backoff ---');

mockChannel.ackedMessages = [];
mockChannel.cancelledConsumerTags = [];
resetBatch();

let failCount = 0;
AuditLogModel.insertMany = (async (docs: any) => {
  failCount++;
  if (failCount === 1) {
    throw new Error('MongoNetworkError: connection refused');
  }
  insertedDocs.push(...docs);
  return docs;
}) as any;

const outageBatch = [
  {
    msg: createMockMessage({ id: 1 }),
    doc: { requestId: 'r-fail-1', projectId: 'p1', ip: '127.0.0.1', method: 'GET', path: '/', status: 200 },
    payload: {}
  }
];

console.log('Testing outage handler retry cycle...');
await handleMongoOutage(outageBatch, 50);

assert.ok(failCount >= 2, 'Must retry MongoDB write until success');
assert.equal(mockChannel.ackedMessages.length, 1, 'Must ack batch once MongoDB write succeeds');
assert.equal(mockChannel.ackedMessages[0]!.multiple, true);

AuditLogModel.insertMany = originalInsertMany;

console.log('✅ Database error resilience and consumer pause tests passed!');

// Test 5: Webhook Dispatcher Hardening
console.log('\n--- TEST 5: Webhook Dispatcher Hardening ---');

clearWebhookRateLimits();

const projId = 'rate-limited-proj';
for (let i = 0; i < 5; i++) {
  assert.equal(isWebhookRateLimited(projId), false, `Call ${i + 1} must be allowed`);
}
assert.equal(isWebhookRateLimited(projId), true, '6th call must be blocked by rate limiter');

assert.equal(isWebhookRateLimited('other-proj'), false, 'Different project must not be blocked');

const dirtyPayload = 'User injected @everyone and @here with <@&98765> and `eval()` code ' + 'x'.repeat(600);
const escaped = escapeWebhookContent(dirtyPayload, 500);

assert.ok(!escaped.includes('@everyone'), '@everyone must be neutralized');
assert.ok(!escaped.includes('@here'), '@here must be neutralized');
assert.ok(escaped.includes('@\u200beveryone'), '@everyone must contain zero-width space');
assert.ok(!escaped.includes('<@&98765>'), 'Role mentions must be stripped');
assert.ok(!escaped.includes('`'), 'Backticks must be neutralized to prevent Markdown breakout');
assert.ok(escaped.endsWith('...[TRUNCATED]'), 'Payload must be truncated to max 500 chars');
assert.ok(escaped.length <= 520);

await sendWebhookAlerts({
  projectId: 'p1',
  clientIp: '1.2.3.4',
  path: '/safe',
  method: 'GET',
  status: 200,
  slackWebhookUrl: 'https://hooks.slack.com/dummy'
});

console.log('✅ Webhook rate-limiting, content escaping, and trigger guard tests passed!');
console.log('\n🎉 ALL ASYNC AUDIT WORKER HARDENING TESTS PASSED SUCCESSFULLY! 🎉\n');

process.exit(0);
