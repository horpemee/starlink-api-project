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

const mapkey = process.env.GOOGLE_MAP_KEY

// Starlink API URLs
const authUrl = 'https://www.starlink.com/api/auth/connect/token'; // URL to get bearer token
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
 async function reversePlusCode(pluscode){
  const result =  await axios.get(
    `https://plus.codes/api?address=${pluscode}&key=${mapkey}`
  )  

  return result.data

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
   console.log("[makeAuthedPost] called with ::", path, body)
    const token = await getBearerToken();
    const response = await axios.post(
      `${process.env.STARLINK_BASE_URL}${path}`,
      body,
      {
        headers: { Authorization: `Bearer ${token}` },
        validateStatus : () => true
      },
    );
    return response.data;
  }


  const API = {
    createAddress: async (acct, payload) => {
/*
administrativeAreaCode
regionCode
formattedAddress
latitude
longitude
REF -> 009eae09-031c-4e23-8297-1e8d827f56c6
SERVICELINENUMBER __> SL-4657821-74968-92
*/
/*
 formattedAddress: { type: string, example: "1 Rocket Road, Hawthorne, CA 90250-6844, US" }
 *         
 *         administrativeAreaCode:   { type: string, example: "CA" }
 *         postalCode: { type: string, example: "90250" }
 *         regionCode: { type: string, example: "US" }
 *         googlePlusCode : {type : string, example : "H9XV+MF Lagos"}

*/
     
     

     const reversedAddress  = await reversePlusCode(payload.googlePlusCode)
     
     console.log("Reversed PlusCode", reversedAddress)
     if(reversedAddress.status != "OK"){
         return  { "message" : "Error occurred while creating address", data : reversedAddress}
     }
     
        let newPayload  = {
            administrativeAreaCode : payload.administrativeAreaCode,
            regionCode : payload.regionCode,
            addressLines : [payload.formattedAddress],
            formattedAddress : payload.formattedAddress,
            latitude : reversedAddress.plus_code.geometry.bounds.northeast.lat,
            longitude : reversedAddress.plus_code.geometry.bounds.northeast.lng
        }

        return makeAuthedPost(`/v1/account/${acct}/addresses`, newPayload)
    },
    getAvailableProducts: (acct) => {
      // return makeAuthedGet(`/v1/account/${acct}/service-lines/available-products`)

      return  {
        "content": {
          "totalCount": 1,
          "pageIndex": 0,
          "limit": 50,
          "isLastPage": true,
          "results": [
            {
              "productReferenceId": "ng-enterprise-starlink-impact-plan-usd",
              "name": "Starlink Impact Plan",
              "price": 64.5,
              "isoCurrencyCode": "USD",
              "isSla": false,
              "maxNumberOfUserTerminals": 1,
              "dataProducts": null
            }
          ]
        },
        "errors": [],
        "warnings": [],
        "information": [],
        "isValid": true
      }
    },
    createServiceLine: (acct, payload) => {

      // makeAuthedPost(`/v1/account/${acct}/service-lines`, payload)

      return {
        
  "content": {
    "addressReferenceId": "45ff18f6-d44d-48c7-9630-c23e408d29f6",
    "serviceLineNumber": "SL-4668820-36443-79",
    "nickname": null,
    "productReferenceId": "ng-enterprise-starlink-impact-plan-usd",
    "delayedProductId": null,
    "optInProductId": null,
    "startDate": "2025-05-05T16:51:18.596009+00:00",
    "endDate": null,
    "publicIp": false,
    "active": true,
    "aviationMetadata": null,
    "dataBlocks": {
      "recurringBlocksCurrentBillingCycle": [],
      "recurringBlocksNextBillingCycle": [],
      "delayedProductRecurringBlocksNextCycle": [],
      "topUpBlocksOptInPurchase": [],
      "topUpBlocksOneTimePurchase": []
    }
  },
  "errors": [],
  "warnings": [],
  "information": [],
  "isValid": true
      }
    },
    updateServiceLineNickname : (acct, serviceLineNumber, body) => makeAuthedPost(`/v1/account/${acct}/service-lines/${serviceLineNumber}/nickname`, body),
    listUserTerminals: (acct, params = '') => makeAuthedGet(`/v1/account/${acct}/user-terminals${params}`),
    addUserTerminal : (acct, deviceId) => makeAuthedPost(`/v1/account/${acct}/user-terminals/${deviceId}`),
    attachTerminal: (acct, terminalId, serviceLineNumber) =>
      makeAuthedPost(`/v1/account/${acct}/user-terminals/${terminalId}/${serviceLineNumber}`, {})
  };


  async function activateStarlink({ accountNumber, address, kitNumber, nickname }) {
    console.log("[activateStarlink] called with :::")
    if (!accountNumber || !address || !kitNumber || !nickname)
      throw new Error('accountNumber, address, productCode and userTerminalId are required');
  
    // 1. Create address
    const addressRes = await API.createAddress(accountNumber, address);
    const addressNumber = addressRes.content.addressReferenceId;
    if (!addressNumber) throw new Error('Address creation failed – missing addressNumber');
  
    // 2. Validate product code
    const products = await API.getAvailableProducts(accountNumber);
    console.log("products::::", products)
    const prods = products.content.results
    if (prods.length === 0) throw new Error('no product available for the supplied account number');
    
  
    // 3. Create service line
    const serviceLineRes = await API.createServiceLine(accountNumber, {
      "addressReferenceId": addressNumber,
      "productReferenceId": prods[0].productReferenceId,
    });
    const serviceLineNumber = serviceLineRes.content.serviceLineNumber;
    if (!serviceLineNumber) throw new Error('Service line creation failed – missing serviceLineNumber');

    //3.x Add nickname to serviceline :::::
    const nicknameRes =  await API.updateServiceLineNickname(accountNumber, serviceLineNumber, {nickname})

    if(nicknameRes.errors.length > 0){
      throw Error(nicknameRes.errors[0].errorMessage);
    }

    const userTerminalRes =  await API.addUserTerminal(accountNumber, kitNumber);

    if(userTerminalRes.errors.length > 0 ) {
      throw Error(userTerminalRes.errors[0].errorMessage)
    }

    const allTerminals = await API.listUserTerminals(accountNumber,`?searchString=${kitNumber}`)

    console.log(allTerminals)

    if(allTerminals.errors.length > 0) {
       throw Error(allTerminals.errors[0].errorMessage)
    }

    const myTerminal  =  allTerminals.content.results.filter(x=> x.kitSerialNumber === kitNumber)
    console.log(myTerminal)
    if(myTerminal.length <= 0){
      throw Error("Terminal has not been added to account")
    }
    const userTerminalId = myTerminal[0].userTerminalId

  
    // 4. Add device to account 


  
    // 5. Attach terminal to service line
    const attachRes = await API.attachTerminal(accountNumber, userTerminalId, serviceLineNumber);
  
    return {
      address: addressRes,
      serviceLine: serviceLineRes,
      userTerminal : userTerminalRes,
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
 *       required: [addressLines, city, administrativeAreaCode , postalCode, regionCode, google]
 *       properties:
 *         formattedAddress: { type: string, example: "1 Rocket Road, Hawthorne, CA 90250-6844, US" }
 *         
 *         administrativeAreaCode:   { type: string, example: "CA" }
 *         postalCode: { type: string, example: "90250" }
 *         regionCode: { type: string, example: "US" }
 *         googlePlusCode : {type : string, example : "H9XV+MF Lagos"}
 * 
 * 
 *     AddressCreateResponse:
 *       type: object
 *       properties:
 *         addressNumber: { type: string, example: "A123456" }
 *     ServiceLineRequest:
 *       type: object
 *       required: [addressReferenceId, productReferenceId]
 *       properties:
 *         addressReferenceId: { type: string, example: "A123456" }
 *         productReferenceId: { type: string, example: "ENT-FIXED-1TB" }
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
 *         - type: object
 *           required: [accountNumber, address]
 *           properties:
 *             address: { $ref: '#/components/schemas/AddressCreateRequest' } 
 *             accountNumber: { type: string, example: "ACC-4635460-74859-26" }
 *             kitNumber : { type : string, example : "KIT304125447"}
 *             nickname : { type : string, example : "OPE-STARRLINK-VIA-API"}
 * 
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

    /**
 * @swagger
 * /api/accounts:
 *   get:
 *     summary: List available accounts
 *     tags: [Accounts]
 *     responses:
 *       200: { description: List of accounts }
 */

  app.get('/api/accounts', async (req, res) => {
    try {
      const data = await makeAuthedGet("/v1/accounts")
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
  });

  
  
/**
 * @swagger
 * /api/accounts/{account}/servicelines:
 *   get:
 *     summary: List available service lines 
 *     tags: [Accounts]
 *     parameters:
 *      - in : path
 *        name : account
 *        required : true
 *        schema : {type : string }
 *     responses:
 *       200: { description: List of service lines }
 */

app.get('/api/accounts/:account/servicelines', async (req, res) => {
    try {
      const data = await makeAuthedGet(`/v1/account/${req.params.account}/service-lines`)
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


  app.patch('/api/accounts/:account/service-lines/:serviceid', async (req, res) => {
    try {
      const data = await API.updateServiceLineNickname(req.params.account,req.params.serviceid, req.body);
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
    const { accountNumber, address, kitNumber, nickname} = req.body;
    try {
      const result = await activateStarlink({ accountNumber, address, kitNumber, nickname });
      res.json({ status: 'activated', ...result });
    } catch (err) {
      console.error(err);
      res.status(400).json({ error: err.message || 'Activation failed' });
    }
  });

app.get('/', async (req, res) => {
    
  res.send({message : 'Starlink Activation Server is running 🚀', code : await getBearerToken()});
  
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
