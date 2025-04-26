require('dotenv').config();

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware to parse JSON and URL encoded data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// YOUR Starlink Credentials - STORE THESE SAFELY
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Starlink API URLs
const authUrl = 'https://api.starlink.com/oauth/token'; // URL to get bearer token
const activationUrl = 'https://api.starlink.com/v1/activations'; // URL to activate kit

// Helper Function: Get Bearer Token
async function getBearerToken() {
    try {
        const response = await axios.post(authUrl, {
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        });

        return response.data.access_token; // Return the token
    } catch (error) {
        console.error('Error getting bearer token:', error.response.data || error.message);
        throw new Error('Failed to get bearer token');
    }
}

// Route: Activate Starlink Kit
app.post('/activate-starlink', async (req, res) => {
    try {
        const { kitId, serviceAddress, contactEmail } = req.body;

        if (!kitId || !serviceAddress || !contactEmail) {
            return res.status(400).json({ message: 'Missing required fields.' });
        }

        // Step 1: Authenticate
        const token = await getBearerToken();

        // Step 2: Activate
        const activationPayload = {
            kit_id: kitId,
            service_address: serviceAddress, // Should be a valid address object
            contact_email: contactEmail,
        };

        const headers = {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
        };

        const activationResponse = await axios.post(activationUrl, activationPayload, { headers });

        // Success
        res.status(200).json({
            message: 'Starlink kit activated successfully!',
            data: activationResponse.data,
        });
    } catch (error) {
        console.error('Error activating kit:', error.response?.data || error.message);
        res.status(500).json({
            message: 'Failed to activate Starlink kit.',
            error: error.message,
        });
    }
});

// Start the server

app.get('/', (req, res) => {
  res.send('Starlink Activation Server is running 🚀');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
