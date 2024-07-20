// importing required modules
import express from 'express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';


// Create express application instance 
const app = express();
const PORT = 3000;

// Connecting to local MongoDB database 
mongoose.connect('mongodb://localhost:27017/mydatabase')
    .then(() => {
        console.log('Database Connected');
    }).catch((error) => {
        console.log('Error in connecting...', error);
    });

// Define Schema for Users collection
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
});

// Create User model based on User schema
const User = mongoose.model('User', userSchema);

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware for JWT validation
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.user = decoded; next();
    });
};

// Route to register a new user 
app.post('/api/register', async (req, res) => {
    try {
        console.log('Request body:', req.body); // Log incoming data

        // Check if password is provided
        if (!req.body.password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // Hash Password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Create a new user
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Route to authenticate and log in user 
app.post('/api/login', async (req, res) => {
    try {
        // Check if user exists
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ email: user.email }, 'secret');
        res.status(200).json({ token });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected route to get user details
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        // Fetch user details using decoded token
        const user = await User.findOne({ email: req.user.email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ username: user.username, email: user.email });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Default route
app.get('/', (req, res) => {
    res.send('Welcome to my User Registration and Login API!');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
