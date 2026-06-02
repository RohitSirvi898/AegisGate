import mongoose, { Schema, Document } from 'mongoose';

export interface IProject extends Document {
    projectName: string;
    developerId: mongoose.Types.ObjectId;
    apiKey: string;
    createdAt: Date;
}

const ProjectSchema = new Schema({
    projectName: { type: String, required: true },
    developerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    apiKey: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

export const ProjectModel = mongoose.model<IProject>('Project', ProjectSchema, 'projects');

