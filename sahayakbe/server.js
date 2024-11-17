const express = require('express');
const cors = require('cors');
const connectDB = require('./db');
const userRoutes = require('./routes/userRoute');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = 5000;

connectDB();

app.use(cors({
  origin: 'http://localhost:3000',  // React app URL
  credentials: true,               // Allow cookies to be sent
}));
app.use(express.json());
app.use(cookieParser());  // Initialize cookie-parser middleware

app.use('/api/user', userRoutes);

app.listen(PORT, () => {
  console.log(`App is listening on PORT : ${PORT}`);
});
