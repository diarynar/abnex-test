import * as mongoose from 'mongoose';
const Schema = mongoose.Schema;
export const CommentSchema = new Schema({
  comment: String,
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  car: {
    type: Schema.Types.ObjectId,
    ref: 'Car',
  },
  commentDate: {
    type: Date,
    default: Date.now,
  },
});
