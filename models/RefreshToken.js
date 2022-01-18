import mongoose from 'mongoose';
const {Schema} = mongoose;
const refreshTokenSchema = new Schema({
  token: {
    type: String,
    required: true,
  },
  // userId: {
  //   type: Schema.Types.ObjectId,
  //   ref: 'user',
  // },
  createdAt: {type: Date, expires: '1440m', default: Date.now},
});

export default mongoose.model('refreshToken', refreshTokenSchema);
