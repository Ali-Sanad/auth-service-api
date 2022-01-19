import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import swaggerUI from 'swagger-ui-express';
import connectToDB from './database-connection.js';
import docs from './swagger.json';
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
app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send(`
  <br> <br> <br> <br>
  <h1 style="text-align:center">
    Auth Service API <a href="/docs"> Docs </a>
  </h1><hr>
    `);
});
app.use('/docs', swaggerUI.serve, swaggerUI.setup(docs));

//@define routes
app.use('/api/v1/auth', authRoutes);

app.listen(PORT, () => console.log(`listening on port:${PORT}`));
