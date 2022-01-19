import mongoose from 'mongoose';
const {Schema} = mongoose;
const UserSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      enum: ['user', 'admin'],
      type: String,
      default: 'user',
    },

    refreshTokens: [
      {
        type: Schema.Types.ObjectId,
        ref: 'refreshToken',
      },
    ],
  },
  {timestamps: true}
);

export default mongoose.model('user', UserSchema);
