import dotenv from 'dotenv';
import mongoose from 'mongoose';

dotenv.config();

let mongoDBConnectionString;
if (process.env.NODE_ENV === 'development') {
  mongoDBConnectionString = process.env.MONGO_URI_CONNECTION_LOCAL;
} else {
  mongoDBConnectionString = process.env.MONGO_URI_CONNECTION_CLOUD;
}
const connectToDB = async () => {
  try {
    await mongoose.connect(mongoDBConnectionString, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB Connected Successfully...');
  } catch (err) {
    console.error(err.message);
    //Exit process with failure
    process.exit(1);
  }
};

export default connectToDB;
