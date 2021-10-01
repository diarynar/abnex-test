import * as mongoose from 'mongoose';
const Schema = mongoose.Schema;
export const CarSchema = new Schema({
  name: String,
  price: Number,
  mark: String,
  description: String,
  cover: String,
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  comments: [
    {
      type: Schema.Types.ObjectId,
      ref: 'Comment',
    },
  ],
  publicationDate: {
    type: Date,
    default: Date.now,
  },
});
