require("dotenv").config();

const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const path = require("path");
const cors = require("cors");
const Mailjet = require("node-mailjet");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const Papa = require("papaparse");
const { stringify } = require("csv-stringify/sync"); // For generating CSV
const AdmZip = require("adm-zip");
const app = express();
const port = 3000;
const cache = { token: null, exp: 0 };
const saltRounds = 10;
// Per-account v2 token cache: Map<accountKey, { token, exp }>
const v2TokenCache = new Map();

// Mailjet configuration
const mailjet = new Mailjet({
  apiKey: process.env.MJ_APIKEY_PUBLIC,
  apiSecret: process.env.MJ_APIKEY_PRIVATE,
});

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:8080";

// const FRONTEND_URL = process.env.FRONTEND_URL || "https://unconnected.support";

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// Middleware to parse JSON and URL encoded data
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url}`);
  next();
});

const multer = require("multer");
const fs = require("fs");
const upload = multer({ dest: "uploads/" });
// const upload = multer({ storage: multer.memoryStorage() });

// YOUR Starlink Credentials - STORE THESE SAFELY
// const CLIENT_ID = process.env.CLIENT_ID;
// const CLIENT_SECRET = process.env.CLIENT_SECRET;
 // Near the top, after other env vars
const SHARED_SECRET = process.env.STARLINK_SHARED_CLIENT_SECRET;
const ACCOUNTS_MAP_JSON = process.env.STARLINK_V2_ACCOUNTS || '{}';

// Parse once at startup
let accountsMap;
try {
  accountsMap = JSON.parse(ACCOUNTS_MAP_JSON);
} catch (err) {
  console.error("Failed to parse STARLINK_V2_ACCOUNTS:", err.message);
  accountsMap = {};
}

function getV2Credentials(accountKey) {
  const key = accountKey || "__default__";

  if (!SHARED_SECRET) {
    throw new Error("Missing STARLINK_SHARED_CLIENT_SECRET in .env");
  }

  const clientId = accountsMap[key];
  if (!clientId) {
    // Optional: fallback to old single/default vars if you keep them
    // if (process.env.V2_CLIENT_ID && process.env.V2_CLIENT_SECRET) {
    //   return {
    //     clientId: process.env.V2_CLIENT_ID,
    //     clientSecret: process.env.V2_CLIENT_SECRET
    //   };
    // }
    throw new Error(`No clientId found for account '${key}' in STARLINK_V2_ACCOUNTS`);
  }

  return {
    clientId,
    clientSecret: SHARED_SECRET
  };
}

const mapkey = process.env.GOOGLE_MAP_KEY;
// Optional override for Starlink v2 API base; falls back to v1 base if not set
const STARLINK_BASE_URL_V2 =
  process.env.STARLINK_BASE_URL_V2 || "https://starlink.com/api/public";
// Optional default v2 credentials (used only if no per-account entry is found)
// const V2_DEFAULT_CLIENT_ID = process.env.V2_CLIENT_ID;
// const V2_DEFAULT_CLIENT_SECRET = process.env.V2_CLIENT_SECRET;
// const V2_CREDENTIALS_JSON = process.env.STARLINK_V2_CREDENTIALS || "{}";
 

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
    servers: [{ url: 'http://localhost:3000' }, { url: "https://starlink-api-project.onrender.com/" }]
    // servers: [
    //   { url: "http://localhost:3000" },
    //   { url: "https://api.unconnected.support/" },
    // ],
  },
  // Scan this file for JSDoc @swagger blocks
  apis: [path.join(__dirname, "index.js")],
});

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// PostgreSQL Pool Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Allow self-signed certs for testing
  },
});

pool.on("error", (err, client) => {
  console.error("Unexpected error on idle client", err);
});

// Multer for photo uploads (max 10 files)

app.post("/api/report", upload.array("infraPhotos", 10), async (req, res) => {
  try {
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

    // Validate required fields
    if (
      !kitNumber ||
      !company ||
      !reporterName ||
      !reporterEmail ||
      !region ||
      !peopleCovered ||
      !peopleAccessing ||
      !civicLocation ||
      (civicLocation === "Others" && !otherLocation) ||
      !freeAccessUsers ||
      !additionalComments ||
      !req.files ||
      req.files.length === 0
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Handle photos (save and get paths)
    let photoPaths = [];
    if (req.files && req.files.length > 0) {
      photoPaths = req.files.map((file) => {
        const newPath = path.join(
          "uploads",
          `${Date.now()}-${file.originalname}`
        );
        fs.renameSync(file.path, newPath);
        return newPath;
      });
    }

    // Insert into reports table
    const result = await pool.query(
      `
      INSERT INTO public.reports (
        kit_number, company, reporter_name, reporter_email, region,
        people_covered, people_accessing, civic_location, other_location,
        free_access_users, additional_comments, infra_photos
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id;
    `,
      [
        kitNumber,
        company,
        reporterName,
        reporterEmail,
        region,
        parseInt(peopleCovered),
        parseInt(peopleAccessing),
        civicLocation,
        otherLocation,
        parseInt(freeAccessUsers),
        additionalComments,
        photoPaths,
      ]
    );

    // Prepare photo attachments
    const attachments = [];
    photoPaths.forEach((path) => {
      const fileContent = fs.readFileSync(path);
      const base64Content = fileContent.toString("base64");
      const fileName = path.split("/").pop();
      const contentType = fileName.match(/\.png$/i)
        ? "image/png"
        : fileName.match(/\.gif$/i)
        ? "image/gif"
        : "image/jpeg"; // Default to JPEG for jpg/jpeg
      attachments.push({
        ContentType: contentType,
        Filename: fileName,
        Base64Content: base64Content,
      });
    });
    // Optional: Email notification (using your Mailjet setup)

    // Add Mailjet code here if desired, e.g., notify admin of new report

    const baseUrl =
      process.env.API_BASE_URL || "https://api.unconnected.support";
    const photoLinks = photoPaths
      .map((path) => `${baseUrl}/${path}`)
      .join("<br/>");

    const htmlTemplate = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee;">
        <h1 style="color: #2c3e50; text-align: center;">New Impact Report Submitted </h1>
        
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Reporter Details</h2>
          <p style="margin: 5px 0;"><strong>Name:</strong> ${reporterName}</p>
          <p style="margin: 5px 0;"><strong>Email:</strong> ${reporterEmail}</p>
          <p style="margin: 5px 0;"><strong>Name of company:</strong> ${company}</p>
        </div>
  
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Report Details</h2>
          <p style="margin: 5px 0;"><strong>Kit number:</strong> ${kitNumber}</p>
          <p style="margin: 5px 0;"><strong>Region:</strong> ${region}</p>
          <p style="margin: 5px 0;"><strong>Number of people covered:</strong> ${peopleCovered}</p>
          <p style="margin: 5px 0;"><strong>Number of people accessing infrastructure:</strong> ${peopleAccessing}</p>
          <p style="margin: 5px 0;"><strong>Civic location:</strong> ${civicLocation}${
      otherLocation ? ` (${otherLocation})` : ""
    }</p>
          <p style="margin: 5px 0;"><strong>Number of people accessing for free:</strong> ${freeAccessUsers}</p>
          <p style="margin: 5px 0;"><strong>Additional comments:</strong> ${additionalComments}</p>
        </div>
  
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <h2 style="color: #34495e; margin-top: 0;">Infrastructure Photos</h2>
          ${
            photoPaths.length > 0
              ? photoPaths
                  .map(
                    (path, index) => `
            <p style="margin: 5px 0;"><a href="${baseUrl}/${path}" target="_blank">View Photo ${
                      index + 1
                    }</a></p>
          `
                  )
                  .join("")
              : "<p>No photos uploaded</p>"
          }
        </div>
  
        <p style="color: #7f8c8d; font-size: 12px; text-align: center; margin-top: 20px;">
          This is an automated message from the Unconnected.org impact reporting system
        </p>
      </div>
    `;

    try {
      const mailRequest = await mailjet
        .post("send", { version: "v3.1" })
        .request({
          Messages: [
            {
              From: {
                Email: process.env.EMAIL_USER || "support@unconnected.org",
                Name: "Unconnected Impact Reporting",
              },
              To: [
                {
                  Email: "support@unconnected.org",
                  Name: "Unconnected Support",
                },
              ],
              Subject: `New Impact Report - ${kitNumber}`,
              HTMLPart: htmlTemplate,
            },
          ],
        });

      console.log("Mailjet response:", mailRequest.body);

      res.json({
        success: true,
        message: "Report submitted",
        reportId: result.rows[0].id,
      });
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
    }

    res.json({
      success: true,
      message: "Report submitted",
      reportId: result.rows[0].id,
    });
  } catch (error) {
    console.error("Report error:", error);
    res
      .status(500)
      .json({ error: "Failed to submit report", details: error.stack });
  }
});

app.get("/api/reports", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, kit_number, company, reporter_name, reporter_email, region,
        people_covered, people_accessing, civic_location, other_location,
        free_access_users, additional_comments, infra_photos, created_at
      FROM public.reports
      ORDER BY created_at DESC;
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// NEW: Serve images from uploads folder statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

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
    console.error(
      "Error getting bearer token:",
      error.response?.data || error.message
    );
    throw new Error("Failed to get bearer token");
  }
}

async function getBearerTokenV2(account) {
  const accountKey = account || "__default__";
  const cached = v2TokenCache.get(accountKey);
  if (cached && Date.now() < cached.exp) {
    return cached.token;
  }

  const creds = getV2Credentials(accountKey);
  if (!creds) {
    throw new Error(
      `No v2 credentials configured for account '${accountKey}'. Set STARLINK_V2_CREDENTIALS or V2_CLIENT_ID/V2_CLIENT_SECRET.`
    );
  }

  try {
    const response = await axios.post(
      "https://www.starlink.com/api/auth/connect/token",
      {
        grant_type: "client_credentials",
        client_id: creds.clientId,
        client_secret: creds.clientSecret,
      },
      { headers: { "Content-type": "application/x-www-form-urlencoded" } }
    );

    const token = response.data.access_token;
    const exp = Date.now() + (response.data.expires_in - 60) * 1000;
    v2TokenCache.set(accountKey, { token, exp });
    return token;
  } catch (error) {
    console.error(
      `Error getting v2 bearer token for account '${accountKey}':`,
      error.response?.data || error.message
    );
    throw new Error("Failed to get v2 bearer token");
  }
}

// Signup Endpoint
app.post("/api/auth/signup", async (req, res) => {
  const { name, company, email, country, phone, password } = req.body;
  try {
    // Check if email is already verified (exists in users table)
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (userCheck.rowCount > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Generate and store OTP without inserting user yet
    const otp = Math.floor(100000 + Math.random() * 900000)
      .toString()
      .substring(0, 6);
    const exp = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
    await pool.query(
      "INSERT INTO otps (email, otp, exp) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET otp = $2, exp = $3",
      [email, otp, exp]
    );

    // Send OTP via Mailjet with improved error handling
    const request = mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: {
            Email: "support@unconnected.org",
            Name: "Unconnected - Signup",
          },
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
    res
      .status(500)
      .json({ error: "Failed to process signup", details: error.message });
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
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
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
    res
      .status(500)
      .json({ error: "Failed to verify OTP", details: error.message });
  }
});

// Login Endpoint
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
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

// HTML escape function
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
// New Bulk Endpoint
app.post(
  "/api/reports/bulk",
  upload.fields([
    { name: "csvFile", maxCount: 1 },
    { name: "photosZip", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { company, reporterName, reporterEmail, region } = req.body;
      const csvFile = req.files["csvFile"] ? req.files["csvFile"][0] : null;
      const photosZip = req.files["photosZip"]
        ? req.files["photosZip"][0]
        : null;

      if (!csvFile) {
        return res.status(400).json({ error: "CSV file is required" });
      }

      if (!photosZip) {
        return res.status(400).json({ error: "Zip file is required" });
      }

      if (!company || !reporterName || !reporterEmail || !region) {
        return res
          .status(400)
          .json({ error: "Missing required common fields" });
      }

      // Parse CSV
      const csvData = Papa.parse(fs.readFileSync(csvFile.path, "utf8"), {
        header: true,
        skipEmptyLines: true,
      }).data;

      if (csvData.length === 0) {
        return res.status(400).json({ error: "CSV file is empty" });
      }

      console.log(`Processing ${csvData.length} reports from CSV`);

      // Validate each report fully
      const requiredFields = [
        "kitNumber",
        "peopleCovered",
        "peopleAccessing",
        "civicLocation",
        "freeAccessUsers",
        "additionalComments",
      ];
      csvData.forEach((row, index) => {
        requiredFields.forEach((field) => {
          if (!row[field])
            throw new Error(`Row ${index + 1} missing field: ${field}`);
        });
        if (row.civicLocation === "Others" && !row.otherLocation) {
          throw new Error(
            `Row ${index + 1} (kit ${
              row.kitNumber
            }): otherLocation required for civicLocation="Others"`
          );
        }
        // Type checks (basic)
        if (
          isNaN(row.peopleCovered) ||
          isNaN(row.peopleAccessing) ||
          isNaN(row.freeAccessUsers)
        ) {
          throw new Error(
            `Invalid numeric value in row for kit ${row.kitNumber}`
          );
        }
      });

      // Handle ZIP if provided
      const photoMap = {}; // kitNumber -> [paths]
      let photoCount = 0;

      //  let extractPath;
      if (!photosZip) {
        console.warn("No ZIP file provided, proceeding without photos");
      } else {
        try {
          console.log("Processing ZIP file:", photosZip.path);
          const zip = new AdmZip(photosZip.path);
          const zipEntries = zip.getEntries();
          const extractPath = "Uploads";
          if (!fs.existsSync(extractPath)) {
            fs.mkdirSync(extractPath, { recursive: true });
          }

          console.log(
            "ZIP Entries:",
            zipEntries.map((e) => e.entryName)
          );

          // let photoCount = 0;
          zipEntries.forEach((entry) => {
            if (
              !entry.isDirectory &&
              entry.entryName.match(/\.(jpg|jpeg|png|gif)$/i)
            ) {
              const fileName = entry.entryName.split("/").pop();
              const savePath = path.join(extractPath, fileName);
              zip.extractEntryTo(entry.entryName, extractPath, false, true);
              if (!photoMap["all"]) photoMap["all"] = [];
              photoMap["all"].push(savePath);
              photoCount++;
              console.log(`Processed image: ${fileName}`);
            } else {
              console.warn(
                `Skipping entry ${entry.entryName}: Not an image or is a directory`
              );
            }
          });
        } catch (zipError) {
          console.error("ZIP processing error:", zipError);
          return res.status(500).json({ error: "Failed to process ZIP file" });
        }
      }

      // Insert in transaction

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const insertedIds = [];
        const values = [];
        csvData.forEach((row) => {
          const photoPaths = photoMap[row.kitNumber.toUpperCase()] || [];
          values.push([
            row.kitNumber,
            escapeHtml(company),
            escapeHtml(reporterName),
            escapeHtml(reporterEmail),
            escapeHtml(region),
            parseInt(row.peopleCovered),
            parseInt(row.peopleAccessing),
            escapeHtml(row.civicLocation),
            row.otherLocation ? escapeHtml(row.otherLocation) : null,
            parseInt(row.freeAccessUsers),
            escapeHtml(row.additionalComments),
            photoPaths,
          ]);
        });

        // Bulk insert (use a library like pg-copy-stream for even larger batches if needed, but this is fine for 600)
        for (let i = 0; i < values.length; i += 100) {
          // Batch in chunks of 100 to avoid query size limits
          const chunk = values.slice(i, i + 100);
          const flatValues = chunk.flat();
          const placeholders = chunk
            .map(
              (_, idx) =>
                `(${Array.from(
                  { length: 12 },
                  (_, j) => `$${idx * 12 + j + 1}`
                ).join(",")})`
            )
            .join(",");
          const result = await client.query(
            `
          INSERT INTO public.reports (
            kit_number, company, reporter_name, reporter_email, region,
            people_covered, people_accessing, civic_location, other_location,
            free_access_users, additional_comments, infra_photos
          ) VALUES ${placeholders}
          RETURNING id;
        `,
            flatValues
          );
          insertedIds.push(...result.rows.map((r) => r.id));
        }
        await client.query("COMMIT");

        // Cleanup temp files
        if (csvFile) fs.unlinkSync(csvFile.path);
        if (photosZip) fs.unlinkSync(photosZip.path);

        // Get original file names from Multer
        const csvOriginalName = req.files["csvFile"][0].originalname;
        const zipOriginalName = req.files["photosZip"] ? req.files["photosZip"][0].originalname : null;

        // Generate summary CSV for download/attachment
        const summaryData = csvData.map((row, idx) => ({
          reportId: insertedIds[idx],
          kitNumber: row.kitNumber,
          company,
          reporterName,
          reporterEmail,
          region,
          peopleCovered: row.peopleCovered,
          peopleAccessing: row.peopleAccessing,
          civicLocation: row.civicLocation,
          otherLocation: row.otherLocation || "",
          freeAccessUsers: row.freeAccessUsers,
          additionalComments: row.additionalComments,
          infraPhotos: (photoMap[row.kitNumber.toUpperCase()] || []).join(", "),
        }));

        const csvContent = stringify(summaryData, { header: true });
        const timestamp = Date.now();
        const csvBaseName = csvOriginalName.replace(/\.csv$/i, '');
        const csvFilePath = path.join("uploads", `${csvBaseName}.csv`);
        // const csvFilePath = path.join(
        //   "uploads",
        //   `bulk_summary_${timestamp}.csv`
        // );
        fs.writeFileSync(csvFilePath, csvContent);
        const downloadUrl = `${
          process.env.API_BASE_URL || "https://api.unconnected.support"
        }/${csvFilePath}`;
        const csvBase64 = Buffer.from(csvContent).toString("base64");

        // Create ZIP for email attachment
        let photosZipBase64 = null;
        let photosZipPath = null;
        let photosZipDownloadUrl = null;
        if (photosZip) {
          // photosZipPath = path.join("uploads", `bulk_photos_${timestamp}.zip`);
          const zipBaseName = zipOriginalName.replace(/\.zip$/i, '');   
          photosZipPath = path.join("uploads", `${zipBaseName}.zip`);
          const outputZip = new AdmZip();
          if (photoCount > 0) {
            Object.values(photoMap).forEach((photoPaths) => {
              photoPaths.forEach((path) => {
                const fileName = path.split("/").pop();
                outputZip.addFile(fileName, fs.readFileSync(path));
              });
            });
          } else {
            outputZip.addFile(
              "no_images.txt",
              Buffer.from("No valid images found in the uploaded ZIP.")
            );
          }
          outputZip.writeZip(photosZipPath);
          photosZipBase64 = fs.readFileSync(photosZipPath).toString("base64");
          photosZipDownloadUrl = `${
            process.env.API_BASE_URL || "https://api.unconnected.support"
          }/${photosZipPath}`;
          // fs.unlinkSync(photosZipPath);
        }

        // Bulk Email Notification (summary)
        const baseUrl =
          process.env.API_BASE_URL || "https://api.unconnected.support";
        const summary = csvData
          .map((r) => {
            const photos = photoMap[r.kitNumber.toUpperCase()] || [];

            return ` ${escapeHtml(r.kitNumber)}: ${
              r.peopleCovered
            } covered, ${escapeHtml(
              r.additionalComments.substring(0, 50)
            )}... (${photos.length} photos)`;
          })
          .join("<br/>");
        const htmlTemplate = `
         <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee;">
          <h1 style="color: #2c3e50; text-align: center;">${company} Impact Reports (${
          csvData.length
        } kits)</h1>
          <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <h2 style="color: #34495e; margin-top: 0;">Reporter Details</h2>
            <p><strong>Name:</strong> ${escapeHtml(reporterName)}</p>
            <p><strong>Email:</strong> ${escapeHtml(reporterEmail)}</p>
            <p><strong>Company:</strong> ${escapeHtml(company)}</p>
            <p><strong>Region:</strong> ${escapeHtml(region)}</p>

          </div>
          <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <h2 style="color: #34495e; margin-top: 0;">Summary</h2>
            ${summary}
          </div>
          <p>Download Report: <a href="${downloadUrl}">${path.basename(csvFilePath)}</a></p>
          ${
            photosZipDownloadUrl
              ? `<p>Download infrastructure photos: <a href="${photosZipDownloadUrl}">${path.basename(photosZipPath)}</a></p>`
              : `<p>No photos uploaded</p>`
          }
        
          </div>
      `;

        const attachments = [
          {
            ContentType: "text/csv",
            Filename: `${path.basename(csvFilePath)}`,
            Base64Content: csvBase64,
          },
        ];
        if (photosZipBase64) {
          attachments.push({
            ContentType: "application/zip",
            Filename: ` ${path.basename(photosZipPath)}`,
            Base64Content: photosZipBase64,
          });
        }

        let emailStatus = "success";
        try {
          console.log(
            "Sending bulk email to support@unconnected.org with attachment"
          );

          const mailRequest = await mailjet
            .post("send", { version: "v3.1" })
            .request({
              Messages: [
                {
                  From: {
                    Email: process.env.EMAIL_USER || "support@unconnected.org",
                    Name: "Unconnected Impact Reporting",
                  },
                  To: [
                    {
                      Email: "support@unconnected.org",
                      Name: "Unconnected Support",
                    },
                  ],
                  Subject: `New Bulk Impact Reports (${csvData.length} kits)`,
                  HTMLPart: htmlTemplate,
                  Attachments: attachments,
                },
              ],
            });
          console.log("Bulk email sent successfully:", mailRequest.body);
        } catch (emailError) {
          emailStatus = "failed";
          console.error("Failed to send bulk email:", {
            message: emailError.message,
            response: emailError.response?.data,
            status: emailError.response?.status,
            stack: emailError.stack,
          });
        }

        res.json({
          success: true,
          message: "Bulk reports submitted",
          insertedCount: insertedIds.length,
          reportIds: insertedIds,
          emailStatus,
          downloadUrl, // Users can download the summary file from this URL
          photosZipDownloadUrl,
          photos: photoMap,
        });
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error("Bulk report error:", error);
      res
        .status(500)
        .json({ error: error.message || "Failed to submit bulk reports" });
    }
  }
);


app.post("/api/auth/create-user", async (req, res) => {
  const { name, company, email, country, phone, password } = req.body;
  try {
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
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
    res
      .status(500)
      .json({ error: "Failed to create user", details: error.message });
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

// Starlink v2 helpers (separate base to allow dual-stack)
async function makeAuthedGetV2(account, path) {
  const token = await getBearerTokenV2(account);
  const { data } = await axios.get(`${STARLINK_BASE_URL_V2}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return data;
}

async function makeAuthedPutV2(account, path, body = {}) {
  console.log("[makeAuthedPutV2] called with ::", path, body);
  const token = await getBearerTokenV2(account);
  const response = await axios.put(
    `${STARLINK_BASE_URL_V2}${path}`,
    body,
    {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    }
  );
  return response.data;
}

async function makeAuthedDeleteV2(account, path) {
  console.log("[makeAuthedDeleteV2] called with ::", path);
  const token = await getBearerTokenV2(account);
  const response = await axios.delete(
    `${STARLINK_BASE_URL_V2}${path}`,
    {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    }
  );
  return response.data;
}

async function makeAuthedPostV2(account, path, body = {}) {
  console.log("[makeAuthedPostV2] called with ::", path, body);
  const token = await getBearerTokenV2(account);
  const response = await axios.post(
    `${STARLINK_BASE_URL_V2}${path}`,
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
    if (
      !process.env.MJ_APIKEY_PUBLIC ||
      !process.env.MJ_APIKEY_PRIVATE ||
      !process.env.EMAIL_USER
    ) {
      console.error("Mailjet configuration missing:", {
        MJ_APIKEY_PUBLIC: !!process.env.MJ_APIKEY_PUBLIC,
        MJ_APIKEY_PRIVATE: !!process.env.MJ_APIKEY_PRIVATE,
        EMAIL_USER: !!process.env.EMAIL_USER,
      });
      throw new Error("Mailjet configuration missing");
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.error("Invalid email format:", email);
      throw new Error("Invalid email format");
    }
    const subject =
      purpose === "signup" ? "Your Signup OTP" : "Your Password Reset OTP";
    const text = `Your OTP for ${purpose} is: ${otp}. It expires in 10 minutes.`;
    const html = `<p>Your OTP for ${purpose} is: <strong>${otp}</strong>. It expires in 10 minutes.</p>`;

    const response = await mailjet.post("send", { version: "v3.1" }).request(
      {
        Messages: [
          {
            From: {
              Email: process.env.EMAIL_USER,
              Name: "Starlink Activation Gateway",
            },
            To: [{ Email: email }],
            Subject: subject,
            TextPart: text,
            HTMLPart: html,
          },
        ],
      },
      {
        timeout: 10000, // 10-second timeout
        retries: 2, // Retry twice on failure
      }
    );
    console.log("Mailjet response:", JSON.stringify(response.body, null, 2));
    return response;
  } catch (error) {
    console.error("Error sending OTP email:", {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
      code: error.code,
      stack: error.stack,
    });
    if (
      error.code === "ENOTFOUND" ||
      error.code === "ETIMEDOUT" ||
      error.code === "ECONNREFUSED"
    ) {
      console.warn(
        "Network error detected, bypassing email sending for testing"
      );
      return { body: { Messages: [{ Status: "bypassed" }] } }; // Fallback response
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
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (userCheck.rowCount === 0) {
      return res.status(400).json({ error: "Email not found" });
    }

    // Generate and store OTP
    const otp = Math.floor(100000 + Math.random() * 900000)
      .toString()
      .substring(0, 6);
    const exp = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
    await pool.query(
      "INSERT INTO otps (email, otp, exp) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET otp = $2, exp = $3",
      [email, otp, exp]
    );

    // Send OTP via Mailjet
    const request = mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: {
            Email: "support@unconnected.org",
            Name: "Unconnected - Password Reset",
          },
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
    res
      .status(500)
      .json({ error: "Failed to send reset OTP", details: error.message });
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
    await pool.query("UPDATE users SET password = $1 WHERE email = $2", [
      hashedPassword,
      email,
    ]);

    // Clean up OTP
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);

    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res
      .status(500)
      .json({ error: "Failed to reset password", details: error.message });
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
            "ACC-6814367-50278-22": "PH",
            "ACC-7580055-64428-19": "PH",
            "ACC-7071161-50554-7": "PH",
            "ACC-DF-9012567-86171-1": "PH",
            "ACC-DF-9012511-23590-86": "PH",
            "ACC-7393314-12390-10": "NG",
            "ACC-DF-9012430-88305-91": "NG",
            "ACC-DF-8910267-22774-3": "MX",
            "ACC-DF-8944908-16857-17": "MX",
            "ACC-DF-8914998-17079-20": "KE",
          };
          const regionCode = accountRenames[acct] || payload.regionCode;
          console.log(
            "[createAddress] called with ::",
            acct,
            payload,
            formattedAddress,
            administrativeAreaCode,
            regionCode,
            latitude,
            longitude
          );

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

const API_V2 =
  process.env.NODE_ENV === "development"
    ? MockAPI
    : {
        createAddress: async (acct, payload) => {
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

          const accountRenames = {
            "ACC-6814367-50278-22": "PH",
            "ACC-7580055-64428-19": "PH",
            "ACC-7071161-50554-7": "PH",
            "ACC-DF-9012567-86171-1": "PH",
            "ACC-DF-9012511-23590-86": "PH",
            "ACC-7393314-12390-10": "NG",
            "ACC-DF-9012430-88305-91": "NG",
            "ACC-DF-8910267-22774-3": "MX",
            "ACC-DF-8944908-16857-17": "MX",
            "ACC-DF-8914998-17079-20": "KE",
          };
          const regionCode = accountRenames[acct] || payload.regionCode;

          const newPayload = {
            addressLines: [formattedAddress],
            administrativeAreaCode,
            regionCode: regionCode,
            formattedAddress,
            latitude,
            longitude,
          };

          return makeAuthedPostV2(acct, `/v2/addresses`, newPayload);
        },
        getAvailableProducts: (acct) => {
          return makeAuthedGetV2(
            acct,
            `/v2/products`
          );
        },
        createServiceLine: async (acct, payload) => {
          return makeAuthedPostV2(acct, `/v2/service-lines`, payload);
        },
        updateServiceLineNickname: (acct, serviceLineNumber, body) =>
          makeAuthedPutV2(
            acct,
            `/v2/service-lines/${serviceLineNumber}/nickname`,
            body
          ),
        listUserTerminals: (acct, params = "") =>
          makeAuthedGetV2(acct, `/v2/user-terminals${params}`),
        addUserTerminal: (acct, deviceId) =>
          makeAuthedPostV2(acct, `/v2/user-terminals`, { deviceId }),
        attachTerminal: (acct, deviceId, serviceLineNumber) =>
          makeAuthedPostV2(
            acct,
            `/v2/service-lines/${serviceLineNumber}/user-terminals`,
            { deviceId}
          ),

        removeDeviceFromAccount: (acct, deviceId) => {
          return makeAuthedDeleteV2(
            acct,
            `/v2/user-terminals/${deviceId}`
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
    throw new Error("Address creation failed - missing addressNumber");

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
    throw new Error("Service line creation failed - missing serviceLineNumber");

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

async function activateStarlinkV2({
  accountNumber,
  address,
  kitNumber,
  nickname,
}) {
  console.log("[activateStarlinkV2] Starting activation:", { accountNumber, kitNumber, nickname });

  if (!accountNumber || !address || !kitNumber || !nickname) {
    throw new Error("accountNumber, address, kitNumber and nickname are required");
  }

  // ─── Helper: Wait for terminal to become visible after add ──────────────────
  async function waitForTerminalVisible(maxAttempts = 12, delayMs = 5000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      console.log(`Checking if terminal ${kitNumber} is visible (attempt ${attempt}/${maxAttempts})`);

      const terminalsRes = await API_V2.listUserTerminals(
        accountNumber,
        `?searchString=${kitNumber}`
      );

      if (terminalsRes.errors && terminalsRes.errors.length > 0) {
        throw new Error(terminalsRes.errors[0].errorMessage || "Failed to list terminals");
      }

      const terminals = terminalsRes.content?.results || [];
      const found = terminals.find(
        (t) => t.kitSerialNumber === kitNumber || t.serialNumber === kitNumber
      );

      if (found) {
        console.log(`Terminal ${kitNumber} now visible after ${attempt} attempts`);
        return found;
      }

      if (attempt === maxAttempts) {
        throw new Error(
          `HTTP error! status. Device ${kitNumber} already assigned.`
        );
      }

      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

console.log(`Checking if terminal ${kitNumber} already exists...`);
  const initialTerminalsRes = await API_V2.listUserTerminals(
    accountNumber,
    `?searchString=${kitNumber}`
  );

  if (initialTerminalsRes.errors && initialTerminalsRes.errors.length > 0) {
    throw new Error(initialTerminalsRes.errors[0].errorMessage || "Failed to list terminals");
  }

  const initialTerminals = initialTerminalsRes.content?.results || [];
  const existingTerminal = initialTerminals.find(
    (t) => t.kitSerialNumber === kitNumber || t.serialNumber === kitNumber
  );

  let terminal;
  if (existingTerminal) {
    // Check if already assigned/activated (adjust fields based on actual API response; serviceLineNumber is likely the key indicator)
    if (
      existingTerminal.serviceLineNumber ||  // Primary check: if attached to a service line
      existingTerminal.serviceLineReferenceId ||  // Alternative if API uses this field
      existingTerminal.status?.toLowerCase() === "active" ||
      existingTerminal.status?.toLowerCase() === "online" ||  // Common values from Starlink dish/telemetry APIs
      existingTerminal.status?.toLowerCase() === "connected"
    ) {
      throw new Error("The kit has already been assigned");
    }
    // If exists but not assigned, use it without adding
    console.log(`Terminal ${kitNumber} exists but not assigned, proceeding...`);
    terminal = existingTerminal;
  } else {
    // If not found, add it
    console.log(`Adding terminal ${kitNumber} to account...`);
    const addRes = await API_V2.addUserTerminal(accountNumber, kitNumber);

    if (addRes.errors && addRes.errors.length > 0) {
      throw new Error(addRes.errors[0].errorMessage || "Failed to add terminal");
    }

    // Wait until it's visible
    terminal = await waitForTerminalVisible();
  }

  // 3. Create address
  const addressRes = await API_V2.createAddress(accountNumber, address);
  const addressNumber = addressRes.content?.addressReferenceId ||
                       addressRes.addressReferenceId;
  if (!addressNumber) throw new Error("Missing addressReferenceId");

  // 4. Get products & create service line
  const products = await API_V2.getAvailableProducts(accountNumber);
  const prods = products.content?.results || products.results || [];
  if (prods.length === 0) throw new Error("No products available");

  const serviceLineRes = await API_V2.createServiceLine(accountNumber, {
    addressReferenceId: addressNumber,
    productReferenceId: prods[0].productReferenceId,
  });

  const serviceLineNumber = serviceLineRes.content?.serviceLineNumber ||
                           serviceLineRes.serviceLineNumber;
  if (!serviceLineNumber) throw new Error("Missing serviceLineNumber");

  // 5. Set nickname
  const nicknameRes = await API_V2.updateServiceLineNickname(
    accountNumber,
    serviceLineNumber,
    { nickname }
  );
  if (nicknameRes.errors?.length > 0) {
    throw new Error(nicknameRes.errors[0].errorMessage);
  }

  // 6. Attach using kitNumber (this is correct for v2!)
  console.log(`Attaching terminal ${kitNumber} to service line ${serviceLineNumber}`);
  const attachRes = await API_V2.attachTerminal(
    accountNumber,
    kitNumber,              // ← correct: use kitNumber here
    serviceLineNumber
  );

  if (attachRes.errors?.length > 0) {
    throw new Error(attachRes.errors[0].errorMessage || "Attach failed");
  }

  return {
    success: true,
    address: addressRes,
    serviceLine: serviceLineRes,
    attach: attachRes,
    terminal: terminal,
    message: `Activated ${kitNumber} on service line ${serviceLineNumber}`
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

// app.get("/api/accounts", async (req, res) => {
//   try {
//     const data = await makeAuthedGet(`/v1/accounts?limit=50&page=0`);
//     const unwantedAccounts = [
//       "ACC-3196223-39704-14",
//       "ACC-2959688-22725-30",
//       "ACC-8653096-80387-28",
//       "ACC-2963072-59271-18",
//       "ACC-2866843-91611-20",
//       // "ACC-7393314-12390-10",
//       "ACC-DF-9022857-69501-2",
//       "ACC-DF-9012430-88305-91",
//       // "ACC-4635460-74859-26",
//       "ACC-DF-8914998-17079-20",
//     ];
//     // Filter out unwanted accounts
//     data.content.results = data.content.results.filter(
//       (account) => !unwantedAccounts.includes(account.accountNumber)
//     );

//     // account number to rename mapping
//     const accountRenames = {
//       "ACC-6814367-50278-22": "PCSWiFi4Every1",
//       "ACC-7071161-50554-7": "WirelessLink",
//       "ACC-DF-8910267-22774-3": "Comnet",
//       "ACC-DF-8944908-16857-17": "CMC Network",
//       "ACC-DF-8914998-17079-20": "KakumaVentures",
//       "ACC-DF-9012567-86171-1": "Yuno Network",
//       "ACC-DF-9012430-88305-91": "Eritel",
//       "ACC-DF-9012511-23590-86": "Globe",
//       "ACC-7580055-64428-19": "ISOC Resilience",
//       // 'ACC-7580055-64428-19': 'Unconnected Partner 3',
//       "ACC-7393314-12390-10": "TESTER API ACCOUNT",
//     };
//     // Rename accounts based on mapping
//     data.content.results = data.content.results.map((account) => {
//       if (accountRenames[account.accountNumber]) {
//         return {
//           ...account,
//           regionCode: accountRenames[account.accountNumber],
//         };
//       }
//       return account;
//     });

//     // Sort the results alphabetically by the regionCode
//     data.content.results.sort((a, b) => {
//       return a.regionCode.localeCompare(b.regionCode);
//     });

//     res.json(data);
//   } catch (err) {
//     console.error(err.response?.data || err.message);
//     res
//       .status(err.response?.status || 500)
//       .json({ error: err.response?.data || "Could not fetch accounts" });
//   }
// });

// app.get("/api/accounts", (req, res) => {
//   try {
//     // Debug logs – very useful right now
//     console.log("[/api/accounts] Loaded raw accounts from env:", 
//       Object.keys(accountsMap || {}));
    
//     if (!accountsMap || Object.keys(accountsMap).length === 0) {
//       console.warn("[/api/accounts] No accounts configured – check .env STARLINK_V2_ACCOUNTS");
//       return res.json({  success: true,
//         content: { results: [] },
//         message: "No partner accounts configured in .env (STARLINK_V2_ACCOUNTS)" });
//     }

//     // Accounts to completely hide (add/remove as needed)
//     const unwanted = new Set([
//       "ACC-3196223-39704-14",
//       "ACC-2959688-22725-30",
//       "ACC-8653096-80387-28",
//       "ACC-2963072-59271-18",
//       "ACC-2866843-91611-20",
//       "ACC-DF-9022857-69501-2",
//       "ACC-DF-8914998-17079-20",
//       // Keep ones you want visible, e.g. don't add "ACC-DF-9012430-88305-91" if you want Eritel
//     ]);

//     // Friendly names + region codes (your source of truth for dropdown display)
//     // Update this object whenever you add a new account to .env
//     const partners = {
//       "ACC-6814367-50278-22": { accountName: "PCSWiFi4Every1", regionCode: "PH" },
//       "ACC-7071161-50554-7":  { accountName: "WirelessLink",   regionCode: "PH" },
//       "ACC-DF-9012567-86171-1": { accountName: "Yuno Network", regionCode: "PH" },
//       "ACC-DF-9012511-23590-86": { accountName: "Globe",       regionCode: "PH" },
//       "ACC-7580055-64428-19": { accountName: "ISOC Resilience", regionCode: "PH" },
//       "ACC-7393314-12390-10": { accountName: "TESTER API ACCOUNT", regionCode: "NG" },
//       "ACC-DF-9012430-88305-91": { accountName: "Eritel",      regionCode: "NG" },
//       "ACC-DF-8910267-22774-3": { accountName: "Comnet",       regionCode: "MX" },
//       "ACC-DF-8944908-16857-17": { accountName: "CMC Network", regionCode: "MX" },
//       // "ACC-DF-8914998-17079-20": { accountName: "KakumaVentures", regionCode: "KE" },
//       // ↑ Add new entries here as you onboard more partners
//     };

//     const results = [];

//     for (const accNumber of Object.keys(accountsMap)) {
//       if (unwanted.has(accNumber)) continue;

//       const info = partners[accNumber] || {
//         accountName: accNumber,   // fallback: show raw ID if not mapped yet
//         regionCode: "??"
//       };

//       results.push({
//         accountNumber: accNumber,
//         regionCode: info.regionCode,
//         accountName: info.accountName
//       });
//     }

//     // Sort alphabetically by the name that appears in dropdown
//     results.sort((a, b) => a.accountName.localeCompare(b.accountName));

//     console.log("[/api/accounts] Sending", results.length, "partners to frontend");

//     res.json({
//       success: true,
//       content: {
//         results
//       }
//     });
//   } catch (err) {
//    console.error("[/api/accounts] Error:", err.message, err.stack);
//     res.status(500).json({
//       success: false,
//       error: "Could not load partner accounts",
//       details: err.message
//     });
//   }
// });
/**
 * @swagger
 * /api/v2/account:
 *   get:
 *     summary: Get account info (v2)
 *     description: Retrieves Starlink account details for a specific account key
 *     parameters:
 *       - in: query
 *         name: account
 *         required: true
 *         schema:
 *           type: string
 *         description: Account identifier from your service accounts (e.g. ACC-4635460-74859-26)
 *     responses:
 *       200:
 *         description: Account details from Starlink API
 *       400:
 *         description: Missing or invalid account parameter
 *       401:
 *         description: Authentication failed
 *       500:
 *         description: Server or upstream error
 */
app.get("/api/v2/account", async (req, res) => {
  console.log("HIT /api/v2/account");
  console.log("Full query object:", req.query);
  console.log("account param:", req.query.account);
  console.log("account param type:", typeof req.query.account);

  try {
    const account = req.query.account;

    if (!account) {
      return res.status(400).json({
        error: "account query parameter is required (e.g. ?account=ACC-4635460-74859-26)"
      });
    }

    console.log("Using account key:", account);

    // Your existing call
    const data = await makeAuthedGetV2(account, `/v2/account`);  // ← adjust path if needed
    res.json(data);
  } catch (err) {
    console.error("Error in /api/v2/account:", err.message);
    console.error("Full error:", err);
    res.status(500).json({ error: err.message || "Internal Server Error" });
  }
});
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

/**
 * @swagger
 * /api/v2/accounts/{account}/addresses:
 *   post:
 *     summary: Create an address (v2)
 *     tags: [Address v2]
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
 *       200: { description: Address created }
 */
app.post("/api/v2/accounts/:account/addresses", async (req, res) => {
  try {
    const data = await API_V2.createAddress(req.params.account, req.body);
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
 * /api/v2/accounts/{account}/products:
 *   get:
 *     summary: List available products for an account (v2)
 *     tags: [Products v2]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: List of products }
 */
app.get("/api/v2/accounts/:account/products", async (req, res) => {
  try {
    const data = await API_V2.getAvailableProducts(req.params.account);
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

/**
 * @swagger
 * /api/v2/accounts/{account}/servicelines:
 *   get:
 *     summary: List available service lines (v2)
 *     tags: [ServiceLines v2]
 *     parameters:
 *      - in : path
 *        name : account
 *        required : true
 *        schema : {type : string }
 *     responses:
 *       200: { description: List of service lines }
 */
app.get("/api/v2/accounts/:account/servicelines", async (req, res) => {
  try {
    const data = await makeAuthedGetV2(
      req.params.account,
      `/v2/service-lines`
    );
    res.json(data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res
      .status(err.response?.status || 500)
      .json({ error: err.response?.data || err.message });
  }
});
// app.get("/api/v2/accounts/list", (req, res) => {
//   try {
//     // This is the full list of accounts from your .env file (the source of truth)
//    const accountKeys = Object.keys(accountsMap || {});
//     const partnersInfo = {
//       "ACC-6814367-50278-22": { regionCode: "PH", displayName: "PCSWiFi4Every1" },
//       "ACC-7580055-64428-19": { regionCode: "PH", displayName: "ISOC Resilience" },
//       "ACC-7071161-50554-7": { regionCode: "PH", displayName: "WirelessLink" },
//       "ACC-DF-9012567-86171-1": { regionCode: "PH", displayName: "Yuno Network" },
//       "ACC-DF-9012511-23590-86": { regionCode: "PH", displayName: "Globe" },
//       "ACC-7393314-12390-10": { regionCode: "NG", displayName: "TESTER API ACCOUNT" },
//       "ACC-DF-9012430-88305-91": { regionCode: "NG", displayName: "Eritel" },
//       "ACC-DF-8910267-22774-3": { regionCode: "MX", displayName: "Comnet" },
//       "ACC-DF-8944908-16857-17": { regionCode: "MX", displayName: "CMC Network" },
//       "ACC-DF-8914998-17079-20": { regionCode: "KE", displayName: "KakumaVentures" },
//       // add remaining accounts...
//     };
//    const results = accountKeys.map(key => {
//       const info = partnersInfo[key] || { regionCode: "??",
//         displayName: key };
//       return {
//         accountNumber: key,
//         regionCode: info.regionCode,
//         accountName: info.displayName,
//       };
//     });
//     res.json({
//       success: true,
//       data: {
//         content: {
//           results: results
         
        
//         }
//       }
//     });
//   } catch (err) {
//     res.status(500).json({ error: "Failed to list accounts" });
//   }
// });
// (c) create service line
// app.get("/api/v2/accounts/list", (req, res) => {
//   try {
//     console.log("[/api/v2/accounts/list] === START ===");
//     console.log("accountsMap keys:", Object.keys(accountsMap || {}));

//     if (!accountsMap || Object.keys(accountsMap).length === 0) {
//       return res.json({
//         success: true,
//         content: { results: [] },
//         message: "No v2 accounts in .env"
//       });
//     }

//     const unwanted = new Set([
//       "ACC-3196223-39704-14",
//       "ACC-2959688-22725-30",
//       "ACC-8653096-80387-28",
//       "ACC-2963072-59271-18",
//       "ACC-2866843-91611-20",
//       "ACC-DF-9022857-69501-2",
//       "ACC-DF-8914998-17079-20",
//     ]);

//     // Friendly names (keep these)
//     const partners = {
//       "ACC-6814367-50278-22": { accountName: "PCSWiFi4Every1", regionCode: "PH" },
//       "ACC-7580055-64428-19": { accountName: "ISOC Resilience", regionCode: "PH" },
//       "ACC-7071161-50554-7":  { accountName: "WirelessLink", regionCode: "PH" },
//       "ACC-DF-9012567-86171-1": { accountName: "Yuno Network", regionCode: "PH" },
//       "ACC-DF-9012511-23590-86": { accountName: "Globe", regionCode: "PH" },
//       "ACC-7393314-12390-10": { accountName: "TESTER API ACCOUNT", regionCode: "NG" },
//       "ACC-DF-9012430-88305-91": { accountName: "Eritel", regionCode: "NG" },
//       "ACC-DF-8910267-22774-3": { accountName: "Comnet", regionCode: "MX" },
//       "ACC-DF-8944908-16857-17": { accountName: "CMC Network", regionCode: "MX" },
//     };

//     // Simple region guesser — expand this as you learn more patterns
//     function guessRegionCode(acc) {
//       if (acc.includes("7393314") || acc.includes("9012430") || acc.includes("4635460")) return "NG";
//       if (acc.includes("6814367") || acc.includes("7071161") || acc.includes("9012567") || acc.includes("9012511")) return "PH";
//       if (acc.includes("8910267") || acc.includes("8944908")) return "MX";
//       if (acc.includes("3853061")) return "CO";     // Colombia
//       if (acc.includes("4375925")) return "MW";     // Malawi (your example)
//       // Add more patterns here when you see new accounts
//       return "??";
//     }

//     const unique = new Map();

//     Object.keys(accountsMap).forEach(acc => {
//       if (unwanted.has(acc)) return;

//       const entry = partners[acc];

//       if (entry) {
//         unique.set(acc, {
//           accountNumber: acc,
//           regionCode: entry.regionCode,
//           accountName: entry.accountName
//         });
//       } else {
//         const region = guessRegionCode(acc);
//         unique.set(acc, {
//           accountNumber: acc,
//           regionCode: region,
//           accountName: region  // ← this is the key line: use code as name
//         });

//         console.log(`[Unmapped → code] ${acc} → accountName set to "${region}"`);
//       }
//     });

//     const results = Array.from(unique.values()).sort((a, b) =>
//       a.accountName.localeCompare(b.accountName)
//     );

//     console.log(`Returning ${results.length} accounts`);

//     res.json({
//       success: true,
//       content: {
//         results
//       }
//     });

//   } catch (err) {
//     console.error("[/api/v2/accounts/list] ERROR:", err);
//     res.status(500).json({ success: false, error: "Failed to list accounts" });
//   }
// });

app.get("/api/v2/accounts/list", (req, res) => {
  try {
    console.log("[/api/v2/accounts/list] === START ===");
    console.log("accountsMap keys:", Object.keys(accountsMap || {}));

    if (!accountsMap || Object.keys(accountsMap).length === 0) {
      return res.json({
        success: true,
        content: { results: [] },
        message: "No v2 accounts in .env"
      });
    }

    const unwanted = new Set([
      "ACC-3196223-39704-14",
      "ACC-2959688-22725-30",
      "ACC-8653096-80387-28",
      "ACC-2963072-59271-18",
      "ACC-2866843-91611-20",
      "ACC-DF-9022857-69501-2",
      "ACC-DF-8914998-17079-20",
    ]);

    // Friendly names (keep these)
    const partners = {
      "ACC-6814367-50278-22": { accountName: "PCSWiFi4Every1", regionCode: "PH" },
      "ACC-7580055-64428-19": { accountName: "ISOC Resilience", regionCode: "PH" },
      "ACC-7071161-50554-7":  { accountName: "WirelessLink", regionCode: "PH" },
      "ACC-DF-9012567-86171-1": { accountName: "Yuno Network", regionCode: "PH" },
      "ACC-DF-9012511-23590-86": { accountName: "Globe", regionCode: "PH" },
      "ACC-7393314-12390-10": { accountName: "TESTER API ACCOUNT", regionCode: "NG" },
      "ACC-DF-9012430-88305-91": { accountName: "Eritel", regionCode: "NG" },
      "ACC-DF-8910267-22774-3": { accountName: "Comnet", regionCode: "MX" },
      "ACC-DF-8944908-16857-17": { accountName: "CMC Network", regionCode: "MX" },
    };

    // Simple region guesser — expanded to cover all your .env accounts
    function guessRegionCode(acc) {
      if (acc.includes("7393314") || acc.includes("9012430") || acc.includes("4635460")) return "NG";
      if (acc.includes("6814367") || acc.includes("7071161") || acc.includes("9012567") || acc.includes("9012511") || acc.includes("7580055")) return "PH";
      if (acc.includes("8910267") || acc.includes("8944908")) return "MX";
      if (acc.includes("3853061")) return "CO";     // Colombia
      if (acc.includes("4375925") || acc.includes("4375960")) return "MW";     // Malawi (expanded)
      if (acc.includes("4628113")) return "??";
      if (acc.includes("5217980")) return "??";
      // Add more patterns here when you see new accounts
      return "??";
    }

    const unique = new Map();

    Object.keys(accountsMap).forEach(acc => {
      if (unwanted.has(acc)) return;

      const entry = partners[acc];

      if (entry) {
        unique.set(acc, {
          accountNumber: acc,
          regionCode: entry.regionCode,
          accountName: entry.accountName
        });
        console.log(`[Mapped] ${acc} → "${entry.accountName}"`);
      } else {
        const region = guessRegionCode(acc);
        unique.set(acc, {
          accountNumber: acc,
          regionCode: region,
          accountName: region  // Use country code as name
        });
        console.log(`[Unmapped] ${acc} → "${region}"`);
      }
    });

    const results = Array.from(unique.values()).sort((a, b) =>
      a.accountName.localeCompare(b.accountName)
    );

    console.log(`Returning ${results.length} accounts`);

    res.json({
      success: true,
      content: {
        results
      }
    });

  } catch (err) {
    console.error("[/api/v2/accounts/list] ERROR:", err);
    res.status(500).json({ success: false, error: "Failed to list accounts" });
  }
});
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
 
/**
 * @swagger
 * /api/v2/accounts/{account}/user-terminals/{deviceId}:
 *   delete:
 *     summary: Remove a device from an account (v2)
 *     tags: [UserTerminals v2]
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
 *       200: { description: Device removed }
 */
app.delete(
  "/api/v2/accounts/:account/user-terminals/:deviceId",
  async (req, res) => {
    try {
      const { account, deviceId } = req.params;
      const result = await API_V2.removeDeviceFromAccount(account, deviceId);
      res.json(result);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || err.message });
    }
  }
);

/**
 * @swagger
 * /api/v2/accounts/{account}/user-terminals/{terminalId}/{serviceLineNumber}:
 *   post:
 *     summary: Attach a terminal to a service line (v2)
 *     tags: [UserTerminals v2]
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
  "/api/v2/accounts/:account/user-terminals/:terminalId/:serviceLineNumber",
  async (req, res) => {
    try {
      const { account, terminalId, serviceLineNumber } = req.params;
      const result = await API_V2.attachTerminal(
        account,
        terminalId,
        serviceLineNumber
      );
      res.json(result);
    } catch (err) {
      console.error(err.response?.data || err.message);
      res
        .status(err.response?.status || 500)
        .json({ error: err.response?.data || err.message });
    }
  }
);

/**
 * @swagger
 * /api/v2/accounts/{account}/service-lines:
 *   post:
 *     summary: Create a service line (v2)
 *     tags: [ServiceLines v2]
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
 *       200: { description: Service line created }
 */
app.post("/api/v2/accounts/:account/service-lines", async (req, res) => {
  try {
    const data = await API_V2.createServiceLine(req.params.account, req.body);
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
 * /api/v2/accounts/{account}/service-lines/{serviceid}:
 *   patch:
 *     summary: Update a service line nickname (v2)
 *     tags: [ServiceLines v2]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: serviceid
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nickname: { type: string }
 *     responses:
 *       200: { description: Service line updated }
 */
app.patch(
  "/api/v2/accounts/:account/service-lines/:serviceid",
  async (req, res) => {
    try {
      const data = await API_V2.updateServiceLineNickname(
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


// (e) attach terminal to service line
  
                 
 

  

/**
 * @swagger
 * /api/v2/activate:
 *   post:
 *     summary: Activate a Starlink terminal via v2 APIs
 *     tags: [Activation v2]
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
 *       400: { description: Activation failed }
 */
app.post("/api/v2/activate", async (req, res) => {
  const { accountNumber, address, kitNumber, nickname } = req.body;
  try {
    const result = await activateStarlinkV2({
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
 * /api/v2/accounts/{account}/user-terminals/{deviceId}:
 *   post:
 *     summary: Add a user terminal to an account (v2)
 *     tags: [UserTerminals v2]
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
 *       200: { description: Terminal added successfully }
 */
app.post(
  "/api/v2/accounts/:account/user-terminals/:deviceId",
  async (req, res) => {
    try {
      const addResult = await API_V2.addUserTerminal(
        req.params.account,
        req.params.deviceId
      );
      res.json(addResult);
    } catch (err) {
      console.error(err);
      res.status(400).json({
        error: err.message || "Failed to add terminal (v2)",
      });
    }
  }
);

/**
 * @swagger
 * /api/v2/notifications/activation:
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
app.post("/api/v2/notifications/activation", async (req, res) => {
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
      impactType,
      otherImpactType,
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
          <p style="margin: 5px 0;"><strong>Impact Type:</strong> ${impactType}${
      otherImpactType ? ` (${otherImpactType})` : ""
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
/**
 * @swagger
 * /api/v2/accounts/{account}/validate-kit/{kitNumber}:
 *   get:
 *     summary: Validate if a kit number is registered to an account (v2)
 *     tags: [UserTerminals v2]
 *     parameters:
 *       - in: path
 *         name: account
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: kitNumber
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Kit validation result }
 *       400: { description: Validation failed }
 */
app.get("/api/v2/accounts/:account/validate-kit/:kitNumber", async (req, res) => {
  try {
    const { account, kitNumber } = req.params;
    
    // Step 1: Check if terminal already exists in account
    const userTerminals = await API_V2.listUserTerminals(
      account,
      `?searchString=${kitNumber}`
    );

    if (userTerminals.errors && userTerminals.errors.length > 0) {
      throw new Error(userTerminals.errors[0].errorMessage);
    }

    const terminal = (userTerminals.content?.results || []).find(
      (t) => t.kitSerialNumber === kitNumber || t.serialNumber === kitNumber
    );

    // If terminal exists and is already attached to a service line, it's already activated
    if (terminal) {
      if (terminal.serviceLineNumber || terminal.serviceLineReferenceId) {
        return res.status(400).json({
          isRegistered: false,
          existing: true,
          alreadyActivated: true,
          terminalDetails: terminal,
          error: "This kit has already been activated and is attached to a service line",
        });
      }
      
      // Terminal exists but not yet activated - this is good, proceed with activation
      return res.json({
        isRegistered: true,
        existing: true,
        alreadyActivated: false,
        terminalDetails: terminal,
        message: "Kit found in account, ready for activation",
      });
    }

    // Step 2: Terminal not found, try to add it
    // Note: Starlink's addUserTerminal doesn't validate kit numbers - it always succeeds
    // The only way to verify validity is to check if it appears in listUserTerminals after adding
    const addResult = await API_V2.addUserTerminal(account, kitNumber);

    // If add operation returned errors, handle them (though this rarely happens)
    if (addResult.errors && addResult.errors.length > 0) {
      return res.status(400).json({
        isRegistered: false,
        existing: false,
        alreadyActivated: false,
        terminalDetails: null,
        error: addResult.errors[0].errorMessage || "Failed to add kit to account",
      });
    }

    // Step 3: Verify the kit is now visible in the account
    // This is the ONLY reliable way to confirm the kit number is valid
    const verifyTerminals = await API_V2.listUserTerminals(
      account,
      `?searchString=${kitNumber}`
    );

    if (verifyTerminals.errors && verifyTerminals.errors.length > 0) {
      throw new Error(verifyTerminals.errors[0].errorMessage);
    }

    const addedTerminal = (verifyTerminals.content?.results || []).find(
      (t) => t.kitSerialNumber === kitNumber || t.serialNumber === kitNumber
    );

    if (addedTerminal) {
      // Successfully added and verified - kit is valid
      return res.json({
        isRegistered: true,
        existing: false,
        alreadyActivated: false,
        terminalDetails: addedTerminal,
        message: "Kit successfully added to account, ready for activation",
      });
    }

    // Add succeeded but terminal is NOT visible - this means the kit number is invalid
    return res.status(400).json({
      isRegistered: false,
      existing: false,
      alreadyActivated: false,
      terminalDetails: null,
      error: "Kit number is invalid or does not belong to this account",
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      isRegistered: false,
      existing: false,
      terminalDetails: null,
      error: err.message || "Failed to validate kit number",
    });
  }
});
app.get("/", async (req, res) => {
  res.send({ message: "Starlink Activation Server is running 🚀" });
});

/**
 * @swagger
 * /api/v2/test/kit-validation:
 *   post:
 *     summary: Test kit validation behavior empirically
 *     description: Attempts to add various invalid kit numbers and logs raw API responses to understand Starlink's validation behavior
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               account:
 *                 type: string
 *                 description: Account identifier (e.g., ACC-xxx-xxx-xx)
 *               testKits:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of kit numbers to test (default includes invalid patterns)
 *     responses:
 *       200:
 *         description: Test results with raw API responses from each attempt
 */
app.post("/api/v2/test/kit-validation", async (req, res) => {
  try {
    const { account, testKits } = req.body;
    
    if (!account) {
      return res.status(400).json({ error: "account parameter is required" });
    }

    // Default test kit numbers covering various invalid patterns
    const kitsToTest = testKits || [
      "INVALID123",           // Completely invalid format
      "000000000000",         // All zeros
      "999999999999",         // All nines
      "12345",                // Too short
      "ABCDEFGHIJKLMNOP",     // Random letters
      "TEST-KIT-001",         // Random with dashes
      "KIT0000000001",        // Kit prefix with zeros
    ];

    console.log(`\n[TEST] Starting kit validation test for account ${account}`);
    const results = [];

    for (const kitNumber of kitsToTest) {
      console.log(`\n[TEST] Testing kit: ${kitNumber}`);
      const testResult = {
        kitNumber,
        steps: [],
      };

      try {
        // Step 1: Try to add the kit
        console.log(`  Step 1: Attempting to add kit ${kitNumber}...`);
        const addResponse = await API_V2.addUserTerminal(account, kitNumber);
        testResult.steps.push({
          step: "addUserTerminal",
          rawResponse: addResponse,
          hasErrors: !!(addResponse.errors && addResponse.errors.length > 0),
          errors: addResponse.errors || [],
        });
        console.log(`  Add response:`, JSON.stringify(addResponse, null, 2));

        // Step 2: If add didn't error, check if it's now searchable
        if (!addResponse.errors || addResponse.errors.length === 0) {
          console.log(`  Step 2: Checking if ${kitNumber} is now searchable...`);
          const listResponse = await API_V2.listUserTerminals(
            account,
            `?searchString=${kitNumber}`
          );
          testResult.steps.push({
            step: "listUserTerminals (after add)",
            rawResponse: listResponse,
            hasErrors: !!(listResponse.errors && listResponse.errors.length > 0),
            errors: listResponse.errors || [],
            resultsCount: (listResponse.content?.results || []).length,
            results: listResponse.content?.results || [],
          });
          console.log(`  Search response:`, JSON.stringify(listResponse, null, 2));
        }
      } catch (stepError) {
        testResult.steps.push({
          step: "error",
          error: stepError.message,
          stack: stepError.stack,
        });
        console.error(`  Error during test:`, stepError.message);
      }

      results.push(testResult);
    }

    console.log(`\n[TEST] Kit validation test complete for account ${account}\n`);

    res.json({
      account,
      testDate: new Date().toISOString(),
      message: "Kit validation test completed. Check backend logs for detailed raw responses.",
      testSummary: results.map((r) => ({
        kitNumber: r.kitNumber,
        stepCount: r.steps.length,
        hasErrors: r.steps.some((s) => s.hasErrors || s.error),
        steps: r.steps.map((s) => ({
          step: s.step,
          hasErrors: s.hasErrors || !!s.error,
          errors: s.errors || [],
          resultsCount: s.resultsCount,
        })),
      })),
      fullResults: results, // Full details in response
    });
  } catch (error) {
    console.error("[TEST] Kit validation test failed:", error);
    res.status(500).json({
      error: "Test failed",
      message: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
});

app.get("/api/v2/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`API listening on ${port}`);
});
