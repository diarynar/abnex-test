import { Document } from 'mongoose';

export interface IComment extends Document {
  readonly comment: string;
  readonly author: string;
  readonly car: string;
  readonly commentDate: Date;
}
