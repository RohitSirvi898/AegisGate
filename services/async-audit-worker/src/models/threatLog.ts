import mongoose, { Schema, Document } from 'mongoose';

export interface IThreatLog extends Document {
    projectId: string;
    clientIp: string;
    endpoint: string;
    method: string;
    timestamp: Date;
    rawBody: string;
    attackVector: string;
    severity: string;
    summary: string;
    createdAt: Date;
}

const ThreatLogSchema: Schema = new Schema({
    projectId: { type: String, required: true, index: true },
    clientIp: { type: String, required: true },
    endpoint: { type: String, required: true },
    method: { type: String, required: true },
    timestamp: { type: Date, required: true },
    rawBody: { type: String, required: false },
    attackVector: { type: String, required: true },
    severity: { type: String, required: true },
    summary: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

export const ThreatLogModel = mongoose.model<IThreatLog>('ThreatLog', ThreatLogSchema, 'threat_logs');
