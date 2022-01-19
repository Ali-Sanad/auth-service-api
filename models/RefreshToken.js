import mongoose from 'mongoose';
const {Schema} = mongoose;
const refreshTokenSchema = new Schema({
  token: {
    type: String,
    required: true,
  },
  userId: {
    type: String,
    required: true,
  },
  createdAt: {type: Date, expires: '7d', default: Date.now},
});

refreshTokenSchema.index({createdAt: 1}, {expireAfterSeconds: 3600 * 24 * 7});
export default mongoose.model('refreshToken', refreshTokenSchema);
