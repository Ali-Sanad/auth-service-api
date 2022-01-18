import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import connectToDB from './database-connection.js';

//routes
import authRoutes from './routes/auth.js';
const app = express();
const PORT = 3000 || process.env.PORT;

connectToDB();
//enable cors for all routes
app.use(cors());

// for bodyparsing using both json and urlencoding
app.use(express.json({limit: '50mb'}));
app.use(express.urlencoded({limit: '50mb', extended: true}));
app.use(cookieParser());

//@define routes
app.use('/api/v1/auth', authRoutes);

app.listen(PORT, () => console.log(`listening on port:${PORT}`));
