import mongoose, { Schema, Document } from 'mongoose';

export interface IDeadLetter extends Document {
    projectId: string;
    clientIp: string;
    endpoint: string;
    method: string;
    timestamp: Date;
    rawBody: string;
    errorReason: string;
    retryCount: number;
    createdAt: Date;
}

const DeadLetterSchema = new Schema({
    projectId: { type: String, required: true, index: true },
    clientIp: { type: String, default: 'unknown' },
    endpoint: { type: String, default: '' },
    method: { type: String, default: 'POST' },
    timestamp: { type: Date, default: Date.now },
    rawBody: { type: String, default: '' },
    errorReason: { type: String, default: 'Exceeded maximum retries (3/3)' },
    retryCount: { type: Number, default: 3 },
    createdAt: { type: Date, default: Date.now }
});

export const DeadLetterModel = mongoose.model<IDeadLetter>('DeadLetter', DeadLetterSchema, 'dead_letters');
