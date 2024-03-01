// * IMPORTS
require('dotenv').config();
const express = require('express'); // import express
const app = express(); // create express app
const connectToDB = require('./db/mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// ROUTERS
const authRouter = require('./routes/auth.routes');

// * CONFIG
const PORT = 5000; // port number
const SERVER_URL = `http://localhost:${PORT}`; // server url

// * MIDDLEWARE
app.use(express.json()); // parse json data
app.use(cookieParser(process.env.JWT_SECRET));
app.use(
  cors({
    origin: 'http://localhost:4200',
    credentials: true,
  }),
);

// * ROUTES
app.use('/api/v1/auth', authRouter);

// * LISTEN
const start = async () => {
  try {
    await connectToDB(process.env.MONGODB_URL); // connect to database

    // listen to port only if database connection is successful
    app.listen(PORT, () => {
      console.log(`Server is running at: ${SERVER_URL}`);
    });
  } catch (err) {
    console.log(err); // log error
  }
};

start();
