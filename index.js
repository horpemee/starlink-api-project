require('dotenv').config();

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const path = require("path")
const app = express();
const port = 3000;
const cache = {token : null, exp : 0};

// Middleware to parse JSON and URL encoded data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// YOUR Starlink Credentials - STORE THESE SAFELY
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Starlink API URLs
const authUrl = 'https://api.starlink.com/oauth/token'; // URL to get bearer token
const activationUrl = 'https://api.starlink.com/v1/activations'; // URL to activate kit


const swaggerSpec = swaggerJsdoc({
    definition: {
      openapi: '3.0.1',
      info: {
        title: 'Starlink Activation Gateway',
        version: '1.0.0',
        description:
          'Express wrapper around the Starlink Enterprise Activation API – docs generated from JSDoc.'
      },
      servers: [{ url: 'http://localhost:3000' }]
    },
    // Scan this file for JSDoc @swagger blocks
    apis: [path.join(__dirname, 'index.js')]
  });
  
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Helper Function: Get Bearer Token
async function getBearerToken() {
    if(cache.token && Date.now() < cache.exp) {
        console.log("using the token in cache");
        return cache.token
    };
    try {
        const response = await axios.post("https://www.starlink.com/api/auth/connect/token", {
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        }, {headers : {'Content-type': 'application/x-www-form-urlencoded'} });

        cache.token = response.data.access_token

        cache.exp = Date.now()  + (response.data.expires_in -60) * 1000;

        return cache.token 
    } catch (error) {
        console.error('Error getting bearer token:', error.response.data || error.message);
        throw new Error('Failed to get bearer token');
    }
}

async function makeAuthedGet(path) {
    const token = await getBearerToken();
    const { data } = await axios.get(
      `${process.env.STARLINK_BASE_URL}${path}`,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    return data;
  }
async function makeAuthedPost(path, body = {}) {
    const token = await getBearerToken();
    const { data } = await axios.post(
      `${process.env.STARLINK_BASE_URL}${path}`,
      body,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    return data;
  }


  const API = {
    createAddress: (acct, payload) => makeAuthedPost(`/v1/account/${acct}/addresses`, payload),
    getAvailableProducts: (acct) => makeAuthedGet(`/v1/account/${acct}/service-lines/available-products`),
    createServiceLine: (acct, payload) => makeAuthedPost(`/v1/account/${acct}/service-lines`, payload),
    listUserTerminals: (acct, params = '') => makeAuthedGet(`/v1/account/${acct}/user-terminals${params}`),
    attachTerminal: (acct, terminalId, serviceLineNumber) =>
      makeAuthedPost(`/v1/account/${acct}/user-terminals/${terminalId}/${serviceLineNumber}`, {})
  };

  async function activateStarlink({ accountNumber, address, productCode, userTerminalId }) {
    if (!accountNumber || !address || !productCode || !userTerminalId)
      throw new Error('accountNumber, address, productCode and userTerminalId are required');
  
    // 1. Create address
    const addressRes = await API.createAddress(accountNumber, address);
    const addressNumber = addressRes.addressNumber;
    if (!addressNumber) throw new Error('Address creation failed – missing addressNumber');
  
    // 2. Validate product code
    const products = await API.getAvailableProducts(accountNumber);
    const productOk = products.find((p) => p.productCode === productCode);
    if (!productOk) throw new Error('productCode not in available products list');
  
    // 3. Create service line
    const serviceLineRes = await API.createServiceLine(accountNumber, {
      addressNumber,
      productCode
    });
    const serviceLineNumber = serviceLineRes.serviceLineNumber;
    if (!serviceLineNumber) throw new Error('Service line creation failed – missing serviceLineNumber');
  
    // 4. Validate terminal ID
    const terminals = await API.listUserTerminals(accountNumber);
    const terminalOk = terminals.find((t) => t.userTerminalId === userTerminalId);
    if (!terminalOk) throw new Error('userTerminalId is not valid for this account');
  
    // 5. Attach terminal to service line
    const attachRes = await API.attachTerminal(accountNumber, userTerminalId, serviceLineNumber);
  
    return {
      address: addressRes,
      serviceLine: serviceLineRes,
      attach: attachRes
    };
  }



  app.get('/api/accounts', async (req, res) => {
    try {
      const data = await makeAuthedGet(`/v1/accounts?limit=50&page=0`);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || 'Could not fetch accounts' });
    }
  });
  

// (a) create address

/**
 * @swagger
 * components:
 *   schemas:
 *     AddressCreateRequest:
 *       type: object
 *       required: [street1, city, state, postalCode, countryCode]
 *       properties:
 *         street1: { type: string, example: "1 Rocket Road" }
 *         street2: { type: string, nullable: true }
 *         city:    { type: string, example: "Hawthorne" }
 *         state:   { type: string, example: "CA" }
 *         postalCode: { type: string, example: "90250" }
 *         countryCode: { type: string, example: "US" }
 *     AddressCreateResponse:
 *       type: object
 *       properties:
 *         addressNumber: { type: string, example: "A123456" }
 *     ServiceLineRequest:
 *       type: object
 *       required: [addressNumber, productCode]
 *       properties:
 *         addressNumber: { type: string, example: "A123456" }
 *         productCode: { type: string, example: "ENT-FIXED-1TB" }
 *     ServiceLineResponse:
 *       type: object
 *       properties:
 *         serviceLineNumber: { type: string, example: "SL7890" }
 *     UserTerminal:
 *       type: object
 *       properties:
 *         userTerminalId: { type: string, example: "UT-A1B2" }
 *         serialNumber: { type: string }
 *         nickname: { type: string }
 *         status: { type: string, example: "active" }
 *     ActivationRequest:
 *       allOf:
 *         - $ref: '#/components/schemas/ServiceLineRequest'
 *         - type: object
 *           required: [accountNumber, userTerminalId]
 *           properties:
 *             accountNumber: { type: string, example: "123456" }
 *             userTerminalId: { type: string, example: "UT-A1B2" }
 *     ActivationResponse:
 *       type: object
 *       properties:
 *         status: { type: string, example: "activated" }
 *         address: { $ref: '#/components/schemas/AddressCreateResponse' }
 *         serviceLine: { $ref: '#/components/schemas/ServiceLineResponse' }
 *         attach: { type: object }
 */

/**
 * @swagger
 * /api/accounts/{account}/addresses:
 *   post:
 *     summary: Create an address
 *     tags: [Address]
 *     parameters:
 *       - in: path
 *         name: account
 *         schema: { type: string }
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema: { $ref: '#/components/schemas/AddressCreateRequest' }
 *     responses:
 *       200:
 *         description: Address created
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/AddressCreateResponse' }
 */
app.post('/api/accounts/:account/addresses', async (req, res) => {
    try {
      const data = await API.createAddress(req.params.account, req.body);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });
  
  // (b) get available products (already existed but keeping consistent path)

  /**
 * @swagger
 * /api/accounts/{account}/products:
 *   get:
 *     summary: List available products for an account
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: List of products }
 */
  app.get('/api/accounts/:account/products', async (req, res) => {
    try {
      const data = await API.getAvailableProducts(req.params.account);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });
  
  // (c) create service line
/**
 * @swagger
 * /api/accounts/{account}/service-lines:
 *   post:
 *     summary: Create a service line
 *     tags: [ServiceLines]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema: { $ref: '#/components/schemas/ServiceLineRequest' }
 *     responses:
 *       200:
 *         description: Service line created
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/ServiceLineResponse' }
 */
  app.post('/api/accounts/:account/service-lines', async (req, res) => {
    try {
      const data = await API.createServiceLine(req.params.account, req.body);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });
  
  // (d) list user terminals
/**
 * @swagger
 * /api/accounts/{account}/user-terminals:
 *   get:
 *     summary: List user terminals
 *     tags: [UserTerminals]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Array of terminals
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/UserTerminal' }
 */
  app.get('/api/accounts/:account/user-terminals', async (req, res) => {
    try {
      const data = await API.listUserTerminals(req.params.account);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });
  
  // (e) attach terminal to service line
  /**
 * @swagger
 * /api/accounts/{account}/user-terminals/{terminalId}/{serviceLineNumber}:
 *   post:
 *     summary: Attach a user terminal to a service line
 *     tags: [UserTerminals]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: terminalId
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: serviceLineNumber
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Terminal attached }
 */
  app.post('/api/accounts/:account/user-terminals/:terminalId/:serviceLineNumber', async (req, res) => {
    try {
      const data = await API.attachTerminal(req.params.account, req.params.terminalId, req.params.serviceLineNumber);
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });
  
  // (f) one‑shot activation
  /**
 * @swagger
 * /api/activate:
 *   post:
 *     summary: One‑shot activation (address → service‑line → attach)
 *     tags: [Activation]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema: { $ref: '#/components/schemas/ActivationRequest' }
 *     responses:
 *       200:
 *         description: Activation succeeded
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/ActivationResponse' }
 *       400: { description: Validation error }
 */
  app.post('/api/activate', async (req, res) => {
    const { accountNumber, address, productCode, userTerminalId } = req.body;
    try {
      const result = await activateStarlink({ accountNumber, address, productCode, userTerminalId });
      res.json({ status: 'activated', ...result });
    } catch (err) {
      console.error(err);
      res.status(400).json({ error: err.message || 'Activation failed' });
    }
  });

app.get('/', async (req, res) => {
    
  res.send({message : 'Starlink Activation Server is running 🚀', token: await getBearerToken()});
  
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
