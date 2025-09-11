require("dotenv").config();

const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const path = require("path");
const cors = require("cors");
const Mailjet = require("node-mailjet");
const bcrypt = require('bcrypt');
const { Pool } = require("pg");
const app = express();
const port = 3000;
const cache = { token: null, exp: 0 };
const saltRounds = 10;


// Mailjet configuration
const mailjet = new Mailjet({
  apiKey: process.env.MJ_APIKEY_PUBLIC,
  apiSecret: process.env.MJ_APIKEY_PRIVATE,
});

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:8080";

// const FRONTEND_URL = process.env.FRONTEND_URL || 'https://unconnected.support';

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// Middleware to parse JSON and URL encoded data
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });

// YOUR Starlink Credentials - STORE THESE SAFELY
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const mapkey = process.env.GOOGLE_MAP_KEY;

const MockAPI = require("./mocks/mock");

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.1",
    info: {
      title: "Starlink Activation Gateway",
      version: "1.0.0",
      description:
        "Express wrapper around the Starlink Enterprise Activation API – docs generated from JSDoc.",
    },
    // servers: [{ url: 'http://localhost:3000' }, { url: "https://starlink-api-project.onrender.com/" }]
    servers: [
      { url: "http://localhost:3000" },
      { url: "https://api.unconnected.support/" },
    ],
  },
  // Scan this file for JSDoc @swagger blocks
  apis: [path.join(__dirname, "index.js")],
});

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// PostgreSQL Pool Configuration
const pool = new Pool({
  user: process.env.PG_USER || "postgres",
  host: process.env.PG_HOST || "localhost",
  database: process.env.PG_DATABASE || "starlink_activation",
  password: process.env.PG_PASSWORD || "your_postgres_password",
  port: process.env.PG_PORT || 5432,
});

// Helper Function: Get Bearer Token
async function getBearerToken() {
  if (cache.token && Date.now() < cache.exp) {
    console.log("using the token in cache");
    return cache.token;
  }
  try {
    const response = await axios.post(
      "https://www.starlink.com/api/auth/connect/token",
      {
        grant_type: "client_credentials",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      },
      { headers: { "Content-type": "application/x-www-form-urlencoded" } }
    );

    cache.token = response.data.access_token;

    cache.exp = Date.now() + (response.data.expires_in - 60) * 1000;

    return cache.token;
  } catch (error) {
    console.error('Error getting bearer token:', error.response?.data || error.message);
    throw new Error("Failed to get bearer token");
  }
}

// Signup Endpoint
app.post("/api/auth/signup", async (req, res) => {
  const { name, company, email, country, phone, password } = req.body;
  try {
    // Check if email is already verified (exists in users table)
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rowCount > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Generate and store OTP without inserting user yet
    const otp = Math.floor(100000 + Math.random() * 900000).toString().substring(0, 6);
    const exp = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
    await pool.query(
      "INSERT INTO otps (email, otp, exp) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET otp = $2, exp = $3",
      [email, otp, exp]
    );

    // Send OTP via Mailjet with improved error handling
    const request = mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: { Email: "support@unconnected.org", Name: "Unconnected - Signup" },
          To: [{ Email: email }],
          Subject: "Your OTP for Signup",
          TextPart: `Your OTP is ${otp}. It expires in 5 minutes.`,
        },
      ],
    });
    const response = await request;
    console.log("Mailjet response:", response.body);

    res.json({ message: "OTP sent" });
  } catch (error) {
    console.error("Signup error:", error);
    if (error.response) {
      console.error("Mailjet error:", error.response.body);
    }
    // Cleanup OTP on failure
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);
    res.status(500).json({ error: "Failed to process signup", details: error.message });
  }
});

// Verify OTP Endpoint

app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM otps WHERE email = $1 AND otp = $2 AND exp > $3",
      [email, otp, Date.now()]
    );
    if (result.rowCount === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // Check if user already exists (in case of retry)
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rowCount > 0) {
      await pool.query("DELETE FROM otps WHERE email = $1", [email]);
      return res.status(400).json({ error: "User already exists" });
    }

    // Since user data isn't sent with OTP, you may need to store it temporarily during signup
    // For simplicity, let's assume frontend resends the data or you store it in a temporary table
    // For now, return a success message and let frontend handle user creation
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);
    res.json({ message: "OTP verified", data: { email } });
  } catch (error) {
    console.error("OTP verification error:", error);
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);
    res.status(500).json({ error: "Failed to verify OTP", details: error.message });
  }
});

// Login Endpoint
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rowCount === 0) {
      return res.status(400).json({ error: "Email not found" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Incorrect password" });
    }

    res.json({ message: "Login successful", data: user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Failed to process login" });
  }
});

/**
 * @swagger
 * /api/auth/create-user:
 *   post:
 *     summary: Create user after OTP verification
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               company:
 *                 type: string
 *               email:
 *                 type: string
 *               country:
 *                 type: string
 *               phone:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User created"
 *                 data:
 *                   type: object
 *       400:
 *         description: Email already exists
 *       500:
 *         description: Server error
 */
app.post("/api/auth/create-user", async (req, res) => {
  const { name, company, email, country, phone, password } = req.body;
  try {
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rowCount > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userResult = await pool.query(
      `
      INSERT INTO users (name, company, email, country, phone, password)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
      `,
      [name, company, email, country, phone, hashedPassword]
    );

    res.json({ message: "User created", data: userResult.rows[0] });
  } catch (error) {
    console.error("User creation error:", error);
    res.status(500).json({ error: "Failed to create user", details: error.message });
  }
});

async function reversePlusCode(pluscode) {
  const result = await axios.get(
    `https://maps.googleapis.com/maps/api/geocode/json?address=${pluscode}&key=${mapkey}`
  );
  return result.data;
}
async function makeAuthedGet(path) {
  const token = await getBearerToken();
  const { data } = await axios.get(`${process.env.STARLINK_BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return data;
}

async function makeAuthedPut(path, body = {}) {
  console.log("[makeAuthedPost] called with ::", path, body);
  const token = await getBearerToken();
  const response = await axios.put(
    `${process.env.STARLINK_BASE_URL}${path}`,
    body,
    {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    }
  );
  return response.data;
}
async function makeAuthedDelete(path) {
  console.log("[makeAuthedDelete] called with ::", path);
  const token = await getBearerToken();
  const response = await axios.delete(
    `${process.env.STARLINK_BASE_URL}${path}`,
    {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    }
  );
  return response.data;
}

async function makeAuthedPost(path, body = {}) {
  console.log("[makeAuthedPost] called with ::", path, body);
  const token = await getBearerToken();
  const response = await axios.post(
    `${process.env.STARLINK_BASE_URL}${path}`,
    body,
    {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    }
  );
  return response.data;
}

// Send OTP Email via Mailjet
async function sendOtpEmail(email, otp, purpose = "signup") {
  try {
    if (!process.env.MJ_APIKEY_PUBLIC || !process.env.MJ_APIKEY_PRIVATE || !process.env.EMAIL_USER) {
      console.error('Mailjet configuration missing:', {
        MJ_APIKEY_PUBLIC: !!process.env.MJ_APIKEY_PUBLIC,
        MJ_APIKEY_PRIVATE: !!process.env.MJ_APIKEY_PRIVATE,
        EMAIL_USER: !!process.env.EMAIL_USER
      });
      throw new Error('Mailjet configuration missing');
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.error('Invalid email format:', email);
      throw new Error('Invalid email format');
    }
    const subject = purpose === "signup" ? "Your Signup OTP" : "Your Password Reset OTP";
    const text = `Your OTP for ${purpose} is: ${otp}. It expires in 10 minutes.`;
    const html = `<p>Your OTP for ${purpose} is: <strong>${otp}</strong>. It expires in 10 minutes.</p>`;

    const response = await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: {
            Email: process.env.EMAIL_USER,
            Name: "Starlink Activation Gateway",
          },
          To: [{ Email: email }],
          Subject: subject,
          TextPart: text,
          HTMLPart: html
       }]
    }, {
      timeout: 10000, // 10-second timeout
      retries: 2 // Retry twice on failure
    });
    console.log("Mailjet response:", JSON.stringify(response.body, null, 2));
    return response;
  } catch (error) {
    console.error(
      "Error sending OTP email:",
     {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
      code: error.code,
      stack: error.stack
    });
    if (error.code === 'ENOTFOUND' || error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      console.warn('Network error detected, bypassing email sending for testing');
      return { body: { Messages: [{ Status: 'bypassed' }] } }; // Fallback response
    }
    throw new Error(`Failed to send ${purpose} OTP email: ${error.message}`);
  }
}

// Send Report Confirmation Email via Mailjet
async function sendReportConfirmationEmail(email, reportData) {
  try {
    const text = `Thank you for submitting your impact report.\n\nDetails:\nKit Number: ${reportData.kitNumber}\nCompany: ${reportData.company}\nRegion: ${reportData.region}`;
    const html = `<p>Thank you for submitting your impact report.</p><p><strong>Details:</strong></p><ul><li>Kit Number: ${reportData.kitNumber}</li><li>Company: ${reportData.company}</li><li>Region: ${reportData.region}</li></ul>`;

    await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: {
            Email: process.env.MAILJET_SENDER_EMAIL,
            Name: "Starlink Activation Gateway",
          },
          To: [{ Email: email }],
          Subject: "Impact Report Submission Confirmation",
          TextPart: text,
          HTMLPart: html,
        },
      ],
    });
  } catch (error) {
    console.error("Error sending report confirmation email:", error);
    throw new Error("Failed to send report confirmation email");
  }
}

 
 
/**
 * @swagger
 * /api/auth/reset-password-request:
 *   post:
 *     summary: Request password reset OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email: { type: string }
 *     responses:
 *       200: { description: Password reset OTP sent }
 *       404: { description: Email not found }
 */

app.post("/api/auth/reset-password-request", async (req, res) => {
  const { email } = req.body;
  try {
    // Check if user exists
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rowCount === 0) {
      return res.status(400).json({ error: "Email not found" });
    }

    // Generate and store OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString().substring(0, 6);
    const exp = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
    await pool.query(
      "INSERT INTO otps (email, otp, exp) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET otp = $2, exp = $3",
      [email, otp, exp]
    );

    // Send OTP via Mailjet
    const request = mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: { Email: "support@unconnected.org", Name: "Unconnected - Password Reset" },
          To: [{ Email: email }],
          Subject: "Your Password Reset OTP",
          TextPart: `Your OTP is ${otp}. It expires in 5 minutes.`,
        },
      ],
    });
    await request;

    res.json({ message: "OTP sent" });
  } catch (error) {
    console.error("Reset password request error:", error);
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);
    res.status(500).json({ error: "Failed to send reset OTP", details: error.message });
  }
});


/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password with OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email: { type: string }
 *               otp: { type: string }
 *               newPassword: { type: string }
 *     responses:
 *       200: { description: Password reset successful }
 *       400: { description: Invalid OTP or email }
 */

// app.post("/api/auth/reset-password", async (req, res) => {
//   const { email, otp, newPassword } = req.body;
//   if (!email || !otp || !newPassword) {
//     return res
//       .status(400)
//       .json({ error: "Email, OTP, and new password are required" });
//   }

//   const storedOtp = otps.get(email);
//   if (!storedOtp || storedOtp.otp !== otp || Date.now() > storedOtp.exp) {
//     return res.status(400).json({ error: "Invalid or expired OTP" });
//   }

//   const user = users.get(email);
//   if (!user) {
//     return res.status(400).json({ error: "User not found" });
//   }
//   const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
//   users.set(email, { ...user, password: newPassword });
//   otps.delete(email);
//   res.json({ success: true, message: "Password reset successful" });
// });
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    // Verify OTP
    const result = await pool.query(
      "SELECT * FROM otps WHERE email = $1 AND otp = $2 AND exp > $3",
      [email, otp, Date.now()]
    );
    if (result.rowCount === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // Hash new password and update user
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2",
      [hashedPassword, email]
    );

    // Clean up OTP
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);

    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ error: "Failed to reset password", details: error.message });
  }
});



/**
 * @swagger
 * /api/report:
 *   post:
 *     summary: Submit an impact report
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               kitNumber: { type: string }
 *               company: { type: string }
 *               reporterName: { type: string }
 *               reporterEmail: { type: string }
 *               region: { type: string }
 *               peopleCovered: { type: number }
 *               peopleAccessing: { type: number }
 *               civicLocation: { type: string }
 *               otherLocation: { type: string }
 *               freeAccessUsers: { type: string }
 *               additionalComments: { type: string }
 *               infraPhotos: { type: array, items: { type: string, format: binary } }
 *     responses:
 *       201: { description: Report submitted successfully }
 *       400: { description: Invalid request }
 */

app.post("/api/report", upload.array("infraPhotos"), async (req, res) => {
  const {
    kitNumber,
    company,
    reporterName,
    reporterEmail,
    region,
    peopleCovered,
    peopleAccessing,
    civicLocation,
    otherLocation,
    freeAccessUsers,
    additionalComments,
  } = req.body;

  if (
    !kitNumber ||
    !company ||
    !reporterName ||
    !reporterEmail ||
    !region ||
    !peopleCovered ||
    !peopleAccessing ||
    !civicLocation ||
    (civicLocation === "Other" && !otherLocation)
  ) {
    return res
      .status(400)
      .json({ error: "All required fields must be provided" });
  }

  const reportData = {
    kitNumber,
    company,
    reporterName,
    reporterEmail,
    region,
    peopleCovered: parseInt(peopleCovered),
    peopleAccessing: parseInt(peopleAccessing),
    civicLocation,
    otherLocation: civicLocation === "Other" ? otherLocation : undefined,
    freeAccessUsers,
    additionalComments,
    infraPhotos: req.files ? req.files.map((file) => file.buffer) : [],
  };

  try {
    await sendReportConfirmationEmail(reporterEmail, reportData);
    res
      .status(201)
      .json({ success: true, message: "Report submitted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const API =
  process.env.NODE_ENV === "development"
    ? MockAPI
    : {
        createAddress: async (acct, payload) => {
          // Reverse the google plus code to get address details
          const reversedAddress = await reversePlusCode(payload.googlePlusCode);
          if (
            reversedAddress.status !== "OK" ||
            !reversedAddress.results ||
            reversedAddress.results.length === 0
          ) {
            return {
              message: "Error occurred while retrieving address details",
              data: reversedAddress,
            };
          }
          const googleResult = reversedAddress.results[0];
          const formattedAddress = googleResult.formatted_address;
          const parts = formattedAddress.split(",");
          const administrativeAreaCode =
            parts.length >= 2 ? parts[1].trim() : payload.regionCode;
          const latitude = googleResult.geometry.location.lat;
          const longitude = googleResult.geometry.location.lng;

    // Build new payload with required Starlink API parameters
    // Reverse regionCode to actual region code
    const accountRenames = {
      'ACC-6814367-50278-22': 'PH',
      'ACC-7580055-64428-19': 'PH',
      'ACC-7071161-50554-7': 'PH',
      'ACC-7393314-12390-10': 'NG',
    }
    const regionCode = accountRenames[acct] || payload.regionCode;
    console.log("[createAddress] called with ::", acct, payload, formattedAddress, administrativeAreaCode, regionCode, latitude, longitude)



          const newPayload = {
            accountNumber: acct,
            addressLines: [formattedAddress],
            administrativeAreaCode,
            regionCode: regionCode,
            formattedAddress,
            latitude,
            longitude,
          };

          return makeAuthedPost(`/v1/account/${acct}/addresses`, newPayload);
        },
        getAvailableProducts: (acct) => {
          return makeAuthedGet(
            `/v1/account/${acct}/service-lines/available-products`
          );
        },
        createServiceLine: async (acct, payload) => {
          return makeAuthedPost(`/v1/account/${acct}/service-lines`, payload);
        },
        updateServiceLineNickname: (acct, serviceLineNumber, body) =>
          makeAuthedPut(
            `/v1/account/${acct}/service-lines/${serviceLineNumber}/nickname`,
            body
          ),
        listUserTerminals: (acct, params = "") =>
          makeAuthedGet(`/v1/account/${acct}/user-terminals${params}`),
        addUserTerminal: (acct, deviceId) =>
          makeAuthedPost(`/v1/account/${acct}/user-terminals/${deviceId}`),
        attachTerminal: (acct, terminalId, serviceLineNumber) =>
          makeAuthedPost(
            `/v1/account/${acct}/user-terminals/${terminalId}/${serviceLineNumber}`,
            {}
          ),

        removeDeviceFromAccount: (acct, deviceId) => {
          return makeAuthedDelete(
            `/v1/account/${acct}/user-terminals/${deviceId}`
          );
        },
      };

async function activateStarlink({
  accountNumber,
  address,
  kitNumber,
  nickname,
}) {
  console.log("[activateStarlink] called with :::");
  if (!accountNumber || !address || !kitNumber || !nickname)
    throw new Error(
      "accountNumber, address, productCode and userTerminalId are required"
    );

  // 1. Create address
  const addressRes = await API.createAddress(accountNumber, address);
  const addressNumber = addressRes.content.addressReferenceId;
  if (!addressNumber)
    throw new Error("Address creation failed – missing addressNumber");

  // 2. Validate product code
  const products = await API.getAvailableProducts(accountNumber);
  console.log("products::::", products);
  const prods = products.content.results;
  if (prods.length === 0)
    throw new Error("no product available for the supplied account number");

  // 3. Create service line
  // const serviceLineRes = await API.createServiceLine(accountNumber, {
  //   "addressReferenceId": addressNumber,
  //   "productReferenceId": prods[0].productReferenceId,
  // });
  const serviceLineNumber = "SL-5125237-18809-76 "; //serviceLineRes.content.serviceLineNumber;
  if (!serviceLineNumber)
    throw new Error("Service line creation failed – missing serviceLineNumber");

  //3.x Add nickname to serviceline :::::
  const nicknameRes = await API.updateServiceLineNickname(
    accountNumber,
    serviceLineNumber,
    { nickname }
  );

  if (nicknameRes.errors.length > 0) {
    throw Error(nicknameRes.errors[0].errorMessage);
  }

  const userTerminalRes = await API.addUserTerminal(accountNumber, kitNumber);

  if (userTerminalRes.errors.length > 0) {
    throw Error(userTerminalRes.errors[0].errorMessage);
  }

  const allTerminals = await API.listUserTerminals(
    accountNumber,
    `?searchString=${kitNumber}`
  );

  console.log(allTerminals);

  if (allTerminals.errors.length > 0) {
    throw Error(allTerminals.errors[0].errorMessage);
  }

  const myTerminal = allTerminals.content.results.filter(
    (x) => x.kitSerialNumber === kitNumber
  );
  console.log(myTerminal);
  if (myTerminal.length <= 0) {
    throw Error("Terminal has not been added to account");
  }
  const userTerminalId = myTerminal[0].userTerminalId;

  // 4. Add device to account

  // 5. Attach terminal to service line
  const attachRes = await API.attachTerminal(
    accountNumber,
    userTerminalId,
    serviceLineNumber
  );

  return {
    address: addressRes,
    serviceLine: serviceLineRes,
    userTerminal: userTerminalRes,
    attach: attachRes,
  };
}

app.delete(
  "/api/accounts/:account/user-terminals/:deviceId",
  async (req, res) => {
    try {
      const { account, deviceId } = req.params;
      const result = await API.removeDeviceFromAccount(account, deviceId);
      res.json(result);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || err.message });
    }
  }
);

app.get("/api/accounts", async (req, res) => {
  try {
    const data = await makeAuthedGet(`/v1/accounts?limit=50&page=0`);
const unwantedAccounts = [
  'ACC-3196223-39704-14',
  'ACC-2959688-22725-30',
  'ACC-8653096-80387-28',
  'ACC-2963072-59271-18',
  'ACC-2866843-91611-20',
  'ACC-7071161-50554-7',
  'ACC-6814367-50278-22',
  'ACC-7393314-12390-10',
  'ACC-7580055-64428-19'
];
    // Filter out unwanted accounts
    data.content.results = data.content.results.filter(
      (account) => !unwantedAccounts.includes(account.accountNumber)
    );

    // account number to rename mapping
    const accountRenames = {
      'ACC-6814367-50278-22': 'Unconnected Partner 1',
      'ACC-7580055-64428-19': 'Unconnected Partner 2',
      'ACC-7071161-50554-7': 'Unconnected Partner 3',
      'ACC-7393314-12390-10': 'TESTER API ACCOUNT',
    }
    // Rename accounts based on mapping
    data.content.results = data.content.results.map((account) => {
      if (accountRenames[account.accountNumber]) {
        return {
          ...account,
          regionCode: accountRenames[account.accountNumber],
        };
      }
      return account;
    });

    // Sort the results alphabetically by the regionCode
    data.content.results.sort((a, b) => {
      return a.regionCode.localeCompare(b.regionCode);
    });


    // Sort the results alphabetically by the regionCode
    data.content.results.sort((a, b) => {
      return a.regionCode.localeCompare(b.regionCode);
    });

    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || "Could not fetch accounts" });
  }
});

// (a) create address

/**
 * @swagger
 * components:
 *   schemas:
 *     AddressCreateRequest:
 *       type: object
 *       required: [regionCode, googlePlusCode]
 *       properties:
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
app.post("/api/accounts/:account/addresses", async (req, res) => {
  try {
    const data = await API.createAddress(req.params.account, req.body);
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
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
app.get("/api/accounts/:account/products", async (req, res) => {
  try {
    const data = await API.getAvailableProducts(req.params.account);
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
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

app.get("/api/accounts", async (req, res) => {
  try {
    const data = await makeAuthedGet("/v1/accounts");
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
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

app.get("/api/accounts/:account/servicelines", async (req, res) => {
  try {
    const data = await makeAuthedGet(
      `/v1/account/${req.params.account}/service-lines`
    );
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
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
app.post("/api/accounts/:account/service-lines", async (req, res) => {
  try {
    const data = await API.createServiceLine(req.params.account, req.body);
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
  }
});

app.patch(
  "/api/accounts/:account/service-lines/:serviceid",
  async (req, res) => {
    try {
      const data = await API.updateServiceLineNickname(
        req.params.account,
        req.params.serviceid,
        req.body
      );
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || err.message });
    }
  }
);

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
app.get("/api/accounts/:account/user-terminals", async (req, res) => {
  try {
    const data = await API.listUserTerminals(req.params.account);
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
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
app.post(
  "/api/accounts/:account/user-terminals/:terminalId/:serviceLineNumber",
  async (req, res) => {
    try {
      const data = await API.attachTerminal(
        req.params.account,
        req.params.terminalId,
        req.params.serviceLineNumber
      );
      res.json(data);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || err.message });
    }
  }
);

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
app.post("/api/activate", async (req, res) => {
  const { accountNumber, address, kitNumber, nickname } = req.body;
  try {
    const result = await activateStarlink({
      accountNumber,
      address,
      kitNumber,
      nickname,
    });
    res.json({ status: "activated", ...result });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message || "Activation failed" });
  }
});

/**
 * @swagger
 * /api/accounts/{account}/user-terminals/{deviceId}:
 *   post:
 *     summary: Add a user terminal to an account
 *     tags: [UserTerminals]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Terminal added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userTerminalId: { type: string }
 */
app.post(
  "/api/accounts/:account/user-terminals/:deviceId",
  async (req, res) => {
    try {
      // First add the terminal
      const addResult = await API.addUserTerminal(
        req.params.account,
        req.params.deviceId
      );

      if (addResult.errors && addResult.errors.length > 0) {
        throw new Error(addResult.errors[0].errorMessage);
      }

      // Then get the terminal ID by listing and filtering
      const terminals = await API.listUserTerminals(
        req.params.account,
        `?searchString=${req.params.deviceId}`
      );

      if (terminals.errors && terminals.errors.length > 0) {
        throw new Error(terminals.errors[0].errorMessage);
      }

      const terminal = terminals.content.results.find(
        (t) => t.kitSerialNumber === req.params.deviceId
      );

      if (!terminal) {
        throw new Error("Terminal not found after adding kit");
      }

      res.json({
        userTerminalId: terminal.userTerminalId,
        kitSerialNumber: terminal.kitSerialNumber,
      });
    } catch (err) {
      console.error(err);
      res.status(400).json({ error: err.message || "Failed to add terminal" });
    }
  }
);

/**
 * @swagger
 * /api/notifications/activation:
 *   post:
 *     summary: Send activation notification email
 *     tags: [Notifications]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [contactEmail, accountNumber, serviceLineId, terminalId, kitNumber, siteName, estimatedNumber, googlePlusCode, regionLabel, companyName, regionCode]
 *             properties:
 *               contactEmail:
 *                 type: string
 *                 example: "me@emailexample.com"
 *               accountNumber:
 *                 type: string
 *                 example: "ACC-4635460-74859-26"
 *               serviceLineId:
 *                 type: string
 *                 example: "SL7890"
 *               terminalId:
 *                 type: string
 *                 example: "UT-A1B2"
 *               kitNumber:
 *                 type: string
 *                 example: "KIT304125"
 *               siteName:
 *                 type: string
 *                 example: "My Site"
 *               estimatedNumber:
 *                 type: string
 *                 example: "100"
 *               googlePlusCode:
 *                 type: string
 *                 example: "H9XV+MF Lagos"
 *               regionLabel:
 *                 type: string
 *                 example: "Lagos"
 *               companyName:
 *                 type: string
 *                 example: "My Company"
 *               regionCode:
 *                 type: string
 *                 example: "NG"
 *     responses:
 *       200:
 *         description: Activation notification email sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Activation notification email sent successfully"
 *       400:
 *         description: Failed to send activation notification
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 error:
 *                   type: string
 *                   example: "Failed to send activation notification"
 */
app.post("/api/notifications/activation", async (req, res) => {
  try {
    const {
      contactEmail,
      accountNumber,
      serviceLineId,
      terminalId,
      kitNumber,
      siteName,
      estimatedNumber,
      googlePlusCode,
      regionLabel,
      companyName,
      regionCode,
      dishOrigin,
    } = req.body;

    const htmlTemplate = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee;">
        <h1 style="color: #2c3e50; text-align: center;">New Starlink Activation Complete 🛰️</h1>
        
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Activation Details</h2>
          <p style="margin: 5px 0;"><strong>Account Number:</strong> ${accountNumber}</p>
          <p style="margin: 5px 0;"><strong>Service Line ID:</strong> ${serviceLineId}</p>
          <p style="margin: 5px 0;"><strong>Terminal ID:</strong> ${terminalId}</p>

        </div>
  
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Terminal &amp; Kit Details</h2>
          <p style="margin: 5px 0;"><strong>Kit Number:</strong> ${kitNumber}</p>
          <p style="margin: 5px 0;"><strong>Dish Origin:</strong> ${
            dishOrigin ? dishOrigin : "Not specified"
          }</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Site Information</h2>
          <p style="margin: 5px 0;"><strong>Company Name:</strong> ${companyName}</p>
          <p style="margin: 5px 0;"><strong>Google Plus Code:</strong> ${googlePlusCode}</p>
          <p style="margin: 5px 0;"><strong>Region Code:</strong> ${regionCode}</p>
          <p style="margin: 5px 0;"><strong>Account Name:</strong> ${regionLabel}</p>
          <p style="margin: 5px 0;"><strong>Site Name:</strong> ${siteName}</p>
          <p style="margin: 5px 0;"><strong>Estimated Number:</strong> ${estimatedNumber}</p>
        </div>
  
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Contact Details</h2>
          <p style="margin: 5px 0;"><strong>Contact Email:</strong> ${contactEmail}</p>
        </div>
  
        <p style="color: #7f8c8d; font-size: 12px; text-align: center; margin-top: 20px;">
          This is an automated message from the Starlink Activation System
        </p>
      </div>
    `;

    const mailjet = new Mailjet({
      apiKey: process.env.MJ_APIKEY_PUBLIC,
      apiSecret: process.env.MJ_APIKEY_PRIVATE,
    });

    const request = await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: {
            Email: process.env.EMAIL_USER,
            Name: "Opeyemi Arifo",
          },
          To: [
            {
              Email: "support@unconnected.org",
              Name: "Unconnected.Org",
            },
          ],
          Subject: `New Starlink Activation - ${kitNumber}`,
          HTMLPart: htmlTemplate,
        },
      ],
    });

    res.json({
      success: true,
      message: "Activation notification email sent successfully",
    });
  } catch (error) {
    console.error("Email notification error:", error);
    res.status(400).json({
      success: false,
      error: error.message || "Failed to send activation notification",
    });
  }
});

/**
 * @swagger
 * /api/accounts/{account}/validate-kit/{kitNumber}:
 *   get:
 *     summary: Validate if a kit number is registered to an account
 *     tags: [UserTerminals]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema:
 *           type: string
 *         description: Account number to check
 *       - in: path
 *         name: kitNumber
 *         required: true
 *         schema:
 *           type: string
 *         description: Kit number to validate
 *     responses:
 *       200:
 *         description: Kit validation result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isRegistered:
 *                   type: boolean
 *                   description: Whether the kit is registered
 *                 terminal:
 *                   type: object
 *                   description: Terminal details if registered
 *       404:
 *         description: Kit not found
 *       400:
 *         description: Invalid request
 */
app.get("/api/accounts/:account/validate-kit/:kitNumber", async (req, res) => {
  try {
    const { account, kitNumber } = req.params;

    // Search for terminals with the given kit number
    // const terminals = await API.listUserTerminals(account, `?searchString=${kitNumber}`);

    // if (terminals.errors && terminals.errors.length > 0) {
    //   throw new Error(terminals.errors[0].errorMessage);
    // }

    // const terminal = terminals.content.results.find(t => t.active  == true);

    // if (!terminal) {
    //   return res.json({
    //     isRegistered: false,
    //     message: 'Kit number not registered to this account'
    //   });
    // }

    //add the kitNumber to account, return error or don't

    /* 
    - If they bought the dish from us, automatically starlink adds the kits into the account for us so we want to always check if it is added to the account then continue activation
    - But if they didn’t buy the dish from us, then while they are activating, we should add the kit to their account and then activate
    
    */

    const result = await API.addUserTerminal(account, kitNumber);
    const userTerminals = await API.listUserTerminals(
      account,
      `?searchString=${kitNumber}`
    );

    if (userTerminals.errors && userTerminals.errors.length > 0) {
      throw new Error(userTerminals.errors[0].errorMessage);
    }
    const terminal = userTerminals.content.results.find(
      (t) => t.kitSerialNumber === kitNumber && t.active === true
    );

    if (result.errors && result.errors.length > 0) {
      // if adding to account failed and terminal does not exist, then it maybe has been added to the wrong account
      if (!terminal) {
        return res.status(400).json({
          isRegistered: false,
          error:
            result.errors[0].errorMessage ||
            "Kit number not registered to this account",
          message:
            result.errors[0].errorMessage ||
            "Kit number not registered to this account",
        });
      }
      // if adding to account failed but terminal exists, then it has been added to the account maybe by starlink: we continue activation
      // OR a previously failed activation attempt has added the terminal to the account
      else {
        return res.json({
          isRegistered: true,
          existing: true,
          terminalDetails: terminal,
        });
      }
    }

    // If adding to account succeeded and terminal exists, then it has been added to the account by us: we continue activation

    return res.json({
      isRegistered: false,
      terminalDetails: terminal,
      existing: false,
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({
      error: err.message || "Failed to validate kit number",
    });
  }
});
app.get("/", async (req, res) => {
  res.send({ message: "Starlink Activation Server is running 🚀" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`API listening on ${port}`);
});
