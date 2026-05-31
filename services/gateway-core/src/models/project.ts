import mongoose, { Schema, Document } from 'mongoose';

export interface IProject extends Document {
    projectName: string;
    developerId: string;
    apiKey: string;
    createdAt: Date;
}

const ProjectSchema = new Schema({
    projectName: { type: String, required: true },
    developerId: { type: String, required: true },
    apiKey: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

export const ProjectModel = mongoose.model<IProject>('Project', ProjectSchema, 'projects');
