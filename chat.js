import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT1 || 3001;
const MISTRAL_API_KEY = 'Yva1DyR2n6ryTyXrNjiTjidjGSANUtrl';
// Update with the correct endpoint from Mistral AI documentation
const MISTRAL_ENDPOINT = 'https://api.mistral.ai/v1/chat/completions';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.',
});
app.use('/api/', limiter);

// Helper Function to Call Mistral AI API
const callMistral = async (conversation) => {
    if (!MISTRAL_API_KEY) {
        throw new Error('Mistral API key is not configured.');
    }

    try {
        const response = await fetch(MISTRAL_ENDPOINT, {
            method: 'POST', // Ensure POST is supported by the API
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${MISTRAL_API_KEY}`,
            },
            body: JSON.stringify({
                model: "mistral-7b", // Replace with the correct model name
                messages: conversation,
                max_tokens: 300,
                temperature: 0.7, // Controls response creativity
            }),
        });

        if (!response.ok) {
            const errorDetails = await response.text();
            throw new Error(
                `Mistral API Error: ${response.status} - ${response.statusText} | ${errorDetails}`
            );
        }

        const data = await response.json();
        if (!data.reply) {
            throw new Error('Invalid response format from Mistral AI.');
        }
        return data.reply.trim();
    } catch (error) {
        console.error('Error calling Mistral AI API:', error.message);
        throw error;
    }
};

// Routes
app.post('/api/chat', async (req, res) => {
    const { conversation } = req.body;

    if (!conversation || !Array.isArray(conversation)) {
        return res.status(400).json({ error: 'Invalid conversation format. It should be an array of messages.' });
    }

    try {
        const botReply = await callMistral(conversation);
        res.json({ reply: botReply });
    } catch (error) {
        console.error('Error processing chat request:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Health Check Route
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Server is healthy and running with Mistral AI integration.',
    });
});

// Default Route
app.get('/', (req, res) => {
    res.send('<h1>Welcome to the Chatbot Backend</h1><p>Powered by Mistral AI</p>');
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start Server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
