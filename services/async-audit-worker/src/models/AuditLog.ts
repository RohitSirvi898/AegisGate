import mongoose, { Document, Schema } from 'mongoose';

export interface IAuditLog extends Document {
  requestId: string;
  projectId: string;
  apiKeyId?: string;
  ip: string;
  method: string;
  path: string;
  rule?: string;
  status: number;
  upstreamOrigin?: string;
  headers?: Map<string, string>;
  body?: any;
  createdAt: Date;
}

const AuditLogSchema: Schema = new Schema(
  {
    requestId: { type: String, required: true, index: true },
    projectId: { type: String, required: true, index: true },
    apiKeyId: { type: String, required: false },
    ip: { type: String, required: true },
    method: { type: String, required: true },
    path: { type: String, required: true },
    rule: { type: String, required: false },
    status: { type: Number, required: true },
    upstreamOrigin: { type: String, required: false },
    headers: { type: Map, of: String, required: false },
    body: { type: Schema.Types.Mixed, required: false },
    createdAt: { type: Date, default: Date.now }
  },
  {
    collection: 'audit_logs',
    versionKey: false
  }
);

AuditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });
AuditLogSchema.index({ projectId: 1, createdAt: -1 });

export const AuditLogModel = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema, 'audit_logs');
export { AuditLogModel as AuditLog };
