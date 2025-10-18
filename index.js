//
//
//
//
//
//// server.js (DEV version — keep your original logic, add logout + rate limit + helpful comments)
// ============================================================
// server.js - Full app with local + Railway Postgres
// ============================================================

/// server.js (DEV version — keep your original logic, add logout + rate limit + helpful comments)
// ------------------------------------------------------------------
// Purpose: Development-friendly version of your app. Not hardened for production.
// When ready to go-live, follow the "GO-LIVE CHECKLIST" comments at the bottom.
// Purpose: Development-friendly version of your app. Not hardened for production.
// Purpose: Development-friendly version of your app. Not hardened for production.
// When ready to go-live, follow the "GO-LIVE CHECKLIST" comments at the bottom.
// ------------------------------------------------------------------

import express from "express";
import bodyParser from "body-parser";
import pkg from "pg";
import bcrypt from "bcrypt"; // hashing
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv";
import path, { dirname } from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit"; // important
import flash from "connect-flash";
import cron from "node-cron";

// NOTE: In this DEV file we do NOT enable helmet/compression/connect-pg-simple etc.
// Those are listed in the GO-LIVE notes below.

// Load .env variables
dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const saltRounds = 12;

// ---------- Middleware ----------

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // public folder for css/js/images

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Basic in-memory session (dev). Keep simple for testing.
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: true,
    cookie: {
      // maxAge: 1000 * 60 * 60 * 24, // 1 day (for testing convenience)
      maxAge: 1000 * 60 * 60, // 60 minutes
    },
  })
);

// Passport must be initialized after session
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

// --- Make flash messages available to all views ---
app.use((req, res, next) => {
  res.locals.message = req.flash("error"); // passport sets 'error' flash on failure
  next();
});

// Rate limiter: basic protection while testing
const limiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 200, // 200 requests per 30 minutes per IP (adjust as needed)
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests — slow down a bit.",
});
app.use(limiter);

// ---------- Postgres (dev client) ----------
// ============================

// Ensure PORT environment variable is defined
const port = process.env.PORT;
if (!port) {
  throw new Error("PORT environment variable is not defined.");
}

const { Client } = pkg;

// Production Postgres (dev client)
const db = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Railway SSL
  },
});

db.connect().catch((err) => {
  console.error("Postgres connection error:", err);
});

// Optional test query
db.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("Postgres query error:", err);
  } else {
    console.log("Connected! Time:", res.rows[0]);
  }
});

/* 
// Alternative local Postgres client configuration (commented out)
// const db = new pg.Client({
//   user: process.env.PGUSER,
//   host: process.env.PGHOST,
//   database: process.env.PGDATABASE,
//   password: process.env.PGPASSWORD,
//   port: process.env.PGPORT,
// });
// db.connect().catch((err) => {
//   console.error("Local Postgres connection error:", err);
// });

// Optional: test local connection
// db.query("SELECT NOW()", (err, res) => {
//   if (err) console.error("Local Postgres query error:", err);
//   else console.log("Local Postgres connected! Current time:", res.rows[0]);
// });

// Example query for local DB
// db.query("SELECT * FROM my_user", (err, res) => {
//   if (err) console.error("Local query error:", err);
//   else console.log("Local my_user rows:", res.rows);
// });
*/

/*
// Railway Postgres (production client) - commented out
// const prodDb = new pg.Client({
//   connectionString: process.env.DATABASE_URL,
//   ssl: { rejectUnauthorized: false }, // required for Railway
// });
// prodDb.connect().catch((err) => {
//   console.error("Railway Postgres connection error:", err);
// });

// Optional: test Railway connection
// prodDb.query("SELECT NOW()", (err, res) => {
//   if (err) console.error("Railway Postgres query error:", err);
//   else console.log("Railway Postgres connected! Current time:", res.rows[0]);
// });

// Example query for Railway DB
// prodDb.query("SELECT * FROM my_user", (err, res) => {
//   if (err) console.error("Railway query error:", err);
//   else console.log("Railway my_user rows:", res.rows);
// });
*/

// ============================
// Notes
// ============================
// 1. Local DB
// ============================
// Notes
// ============================
// 1. Local DB (db) works exactly as before. Do not touch local code.
// 2. Railway DB (prodDb) is separate, only used for production.
// 3. No import/export inside this file → avoids circular references.
// 4. Push updates to GitHub → Railway redeploys.
// 5. Local Postgres data and Railway data remain separate.

// Scheduled cleanup: delete cliinfo records older than 5 days at midnight
// Note: table does not support NOW() function, but PostgreSQL does, so this should work if 'time' is timestamp
cron.schedule("0 0 * * *", async () => {
  console.log(
    "⏰ Running cleanup: deleting cliinfo records older than 5 days..."
  );
  try {
    const result = await db.query(
      `DELETE FROM cliinfo WHERE time < NOW() - INTERVAL '5 days'`
    );
    console.log(`✅ Deleted ${result.rowCount} old record(s) from cliinfo.`);
  } catch (error) {
    console.error("❌ Error deleting old records:", error.message);
  }
});

// ---------- Helper: password validation ----------
function isValidPassword(password) {
  const minLength = 8;
  const hasNumber = /\d/;
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/;
  const hasUppercase = /[A-Z]/;

  if (!password || typeof password !== "string") return false;

  return (
    password.length >= minLength &&
    hasNumber.test(password) &&
    hasSpecialChar.test(password) &&
    hasUppercase.test(password)
  );
}

// Home route
app.get("/", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("index.ejs", { defaultDate: today });
});

// About page
app.get("/about", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("about.ejs", { defaultDate: today });
});

// Contact page (GET)
app.get("/contact", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("contact.ejs", { defaultDate: today, thanks: null });
});

// Contact form submission (POST)
app.post("/contact", async (req, res) => {
  const { name, phone, email, communication: commu, text: comment } = req.body;

  try {
    await db.query(
      "INSERT INTO cliinfo (name, phone, email, commu, comment) VALUES ($1, $2, $3, $4, $5)",
      [name, phone, email, commu, comment]
    );

    const today = new Date().toISOString().split("T")[0];
    res.render("contact.ejs", {
      defaultDate: today,
      thanks: "Thank you for your message",
    });
  } catch (error) {
    console.error("Contact insert error:", error);
    res.status(500).send("Error saving contact message");
  }
});

// Link pages
app.get("/link", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("link.ejs", { defaultDate: today });
});

app.get("/anotherlink", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("anotherlink.ejs", { defaultDate: today });
});

app.get("/otherlink", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("otherlink.ejs", { defaultDate: today });
});

// Calculator page
app.get("/calculate", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("calculator.ejs", { defaultDate: today });
});

// Mortgage page
app.get("/mortgage", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("mortgage.ejs", { defaultDate: today });
});

// Hana page
app.get("/hana", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("hana.ejs", { defaultDate: today });
});

// Admin emails from environment variable
const adminEmails = process.env.ADMIN_EMAILS
  ? process.env.ADMIN_EMAILS.split(",").map((email) => email.trim())
  : [];

console.log(adminEmails); // Example output: ['cc@mail.com', 'la@mail.com']

// Authentication middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next(); // Proceed to route handler
  }
  res.redirect("/login"); // Redirect unauthenticated users
}

// Tax page (protected)
app.get("/tax", ensureAuthenticated, async (req, res) => {
  console.log("req.user:", req.user); // Debug: logged in user info

  const today = new Date().toISOString().split("T")[0]; // Format YYYY-MM-DD

  try {
    // Query tax data from database
    const result = await db.query("SELECT * FROM taxrate_2025 ORDER BY id");
    // Render tax page with data
    // (You probably want to add res.render here, I can help with that next)

    // Render tax page with data
    res.render("tax.ejs", {
      defaultDate: today,
      taxData: result.rows,
    });
  } catch (err) {
    console.error("Error loading tax data:", err);
    res.status(500).send("Error loading tax data");
  }
});

// ====================
// MES Page (Admin only)
// ====================
app.get("/mes", ensureAuthenticated, async (req, res) => {
  console.log("req.user:", req.user); // Debug: logged-in user info
  const today = new Date().toISOString().split("T")[0];

  // Check if user email is allowed admin email (see line 467 for adminEmails array)
  if (!adminEmails.includes(req.user.email)) {
    // User is logged in but NOT authorized to view this page
    return res.status(403).render("denied.ejs", {
      // denied.ejs 👈
      defaultDate: today,
      message: "Access denied: You are not authorized to view this page.",
    });
  }

  try {
    // Query message data from database
    const result = await db.query("SELECT * FROM cliinfo ORDER BY id");

    // Render admin mes page with data
    res.render("mes.ejs", {
      defaultDate: today,
      mes: result.rows,
    });
  } catch (err) {
    console.error("Error loading data:", err);
    res.status(500).send("Error loading data");
  }
});
// End /mes route

// ===============================
// Login / Signup / Change Password
// ===============================

// Login page
app.get("/login", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  // const messages = req.flash("error"); // Uncomment if flash messages needed
  res.render("login.ejs", {
    defaultDate: today,
    // message: messages[0], // Pass first flash message if any
  });
});

// Signup page
app.get("/signup", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("register.ejs", { errors: {}, defaultDate: today, formData: {} });
});

// Change password page
app.get("/chapw", (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  res.render("chapw.ejs", { defaultDate: today, message: null });
});

// ----------- Logout (fixed for Passport 0.6+) -----------
app.get("/logout", (req, res, next) => {
  // Passport 0.6+ requires a callback in logout
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    // Destroy session and clear cookie (good dev-friendly behavior)
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      // Redirect to home or login — here we redirect to home
      res.redirect("/");
    });
  });
});

// ----------- Signup logic -----------
app.post("/signup", async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const email = req.body.username;
  const password = req.body.password;
  const errors = {};
  const formData = { email };

  try {
    // Step 1: Check if email already exists — return early if it does
    const checkUser = await db.query("SELECT * FROM my_user WHERE email = $1", [
      email,
    ]);
    if (checkUser.rows.length > 0) {
      return res.render("register.ejs", {
        errors: { email: "Email already exists. Please sign in instead." },
        defaultDate: today,
        formData,
      });
    }

    // Step 2: Validate password — only if email was OK
    if (!isValidPassword(password)) {
      return res.render("register.ejs", {
        errors: {
          password:
            "Password must be at least 8 characters long and include at least one number, one special character, and one uppercase letter.",
        },
        defaultDate: today,
        formData,
      });
    }

    // Step 3: Proceed with hashing and creating user
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.status(500).send("Error creating user");
      }

      try {
        const result = await db.query(
          "INSERT INTO my_user (email, pw) VALUES ($1, $2) RETURNING *",
          [email, hash]
        );
        const user = result.rows[0];

        req.login(user, (loginErr) => {
          if (loginErr) {
            console.error("Login after signup error:", loginErr);
            return res.redirect("/login");
          }
          res.redirect("/tax");
        });
      } catch (insertErr) {
        console.error("Error inserting user:", insertErr);
        res.status(500).send("Error creating user");
      }
    });
  } catch (error) {
    console.error("Signup route error:", error);
    res.status(500).send("Error signing up");
  }
});
// ---------- Passport Local Strategy ----------
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM my_user WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.pw;

        bcrypt.compare(password, storedHashedPassword, (err, match) => {
          if (err) return cb(err);
          if (match) {
            return cb(null, user);
          } else {
            return cb(null, false); // Password mismatch
          }
        });
      } else {
        // User not found — don't reveal this explicitly
        return cb(null, false);
      }
    } catch (err) {
      return cb(err);
    }
  })
);

// Serialize / Deserialize user to support login sessions
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// ---------- Login Route ----------
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err); // Pass error to Express error handler
    }
    if (!user) {
      // Authentication failed
      req.flash("error", info?.message || "Invalid username or password.");
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) return next(err);

      // Store admin status in session for later use
      req.session.isAdmin = adminEmails.includes(user.email);

      // Redirect based on admin status
      if (req.session.isAdmin) {
        return res.redirect("/mes"); // Admin dashboard
      } else {
        return res.redirect("/tax"); // Regular user page
      }
    });
  })(req, res, next);
});

// ---------- Change Password Route ----------
app.post("/chapw", async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const { email, newPassword, confirmPassword } = req.body;

  // Basic validations
  if (!email || !newPassword || !confirmPassword) {
    return res.render("chapw.ejs", {
      message: "All fields are required",
      defaultDate: today,
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render("chapw.ejs", {
      message: "Passwords do not match",
      defaultDate: today,
    });
  }

  if (!isValidPassword(newPassword)) {
    return res.render("chapw.ejs", {
      message:
        "Password must be at least 8 characters and include a number, special character, and a capital letter",
      defaultDate: today,
    });
  }

  try {
    // Check if user exists
    const userResult = await db.query(
      "SELECT * FROM my_user WHERE email = $1",
      [email]
    );
    if (userResult.rows.length === 0) {
      return res.render("chapw.ejs", {
        message: "Email not registered",
        defaultDate: today,
      });
    }

    // Hash new password and update DB
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await db.query("UPDATE my_user SET pw = $1 WHERE email = $2", [
      hashedPassword,
      email,
    ]);

    res.render("chapw.ejs", {
      message: "Password updated successfully!",
      defaultDate: today,
    });
  } catch (err) {
    console.error("Error updating password:", err);
    res.render("chapw.ejs", {
      message: "Something went wrong, try again later",
      defaultDate: today,
    });
  }
});

// ---------- Global Error Handler ----------
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).send("Server error");
});

// ---------- Admin Authentication Middleware ----------
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && adminEmails.includes(req.user.email)) {
    return next();
  }
  return res.status(403).render("HN.ejs", {
    message: "Thank you for visiting Hieu Nguyen Page.",
    defaultDate: new Date().toISOString().split("T")[0],
  });
}

// ---------- Track Visitor IP and Counts ----------
app.get("/track-visitor", async (req, res) => {
  try {
    // Get visitor IP from headers or connection info
    const ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress || req.ip;

    // Check if visitor exists
    const existingVisitor = await db.query(
      "SELECT * FROM visitors WHERE ip_address = $1",
      [ipAddress]
    );

    if (existingVisitor.rows.length === 0) {
      // New visitor: insert IP and timestamp
      await db.query(
        "INSERT INTO visitors (ip_address, visited_at) VALUES ($1, NOW())",
        [ipAddress]
      );
      // Update total count and timestamp in visits table
      await db.query(
        "UPDATE visits SET total_count = total_count + 1, last_updated = NOW() WHERE id = 1"
      );
    } else {
      // Existing visitor: update last visit timestamp
      await db.query(
        "UPDATE visitors SET visited_at = NOW() WHERE ip_address = $1",
        [ipAddress]
      );
    }

    res.send("Visitor tracked");
  } catch (error) {
    console.error("Error tracking visitor:", error);
    res.status(500).send("Internal server error");
  }
});

// ---------- Admin Visitor Stats Page with Pagination and Filters ----------

app.get("/suothong", ensureAdmin, async (req, res) => {
  try {
    // Pagination setup
    const limit = 20;
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * limit;

    // Get filter params from query string
    const { startDate, endDate, search } = req.query;

    // Base SQL query and params array
    let baseQuery = "FROM visitors WHERE 1=1";
    const params = [];
    let paramIndex = 1;

    // 4. Add date range filter if startDate provided
    if (startDate) {
      baseQuery += ` AND visited_at >= $${paramIndex}`;
      params.push(startDate);
      paramIndex++;
    }

    // 5. Add date range filter if endDate provided (include full day until 23:59:59)
    if (endDate) {
      baseQuery += ` AND visited_at <= $${paramIndex}`;
      params.push(endDate + " 23:59:59");
      paramIndex++;
    }

    // 6. Add IP address search filter (case-insensitive)
    if (search) {
      baseQuery += ` AND ip_address ILIKE $${paramIndex}`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    // 7. Get total count for pagination
    const countResult = await db.query(`SELECT COUNT(*) ${baseQuery}`, params);
    const totalVisitors = parseInt(countResult.rows[0].count, 10);
    const totalPages = Math.ceil(totalVisitors / limit);

    // 8. Fetch filtered visitors with pagination
    // Add LIMIT and OFFSET params
    // Add limit/offset to params before using $paramIndex in the query
    params.push(limit); // LIMIT → $paramIndex
    params.push(offset); // OFFSET → $paramIndex + 1
    const visitorsResult = await db.query(
      `SELECT ip_address, visited_at ${baseQuery} ORDER BY visited_at DESC LIMIT $${paramIndex} OFFSET $${
        paramIndex + 1
      }`,
      [...params, limit, offset]
    );

    // 9. Fetch total_count and last_updated from visits table
    const visitsResult = await db.query(
      "SELECT total_count, last_updated FROM visits WHERE id = 1"
    );
    const visitStats = visitsResult.rows[0] || {
      total_count: 0,
      last_updated: null,
    };

    // Render results with filters and pagination info
    res.render("thongsuot.ejs", {
      totalCount: visitStats.total_count,
      lastUpdated: visitStats.last_updated,
      visitors: visitorsResult.rows,
      defaultDate: new Date().toISOString().split("T")[0],
      startDate: startDate || "",
      endDate: endDate || "",
      search: search || "",
      currentPage: page,
      totalPages,
      adminEmail: req.user?.email || "Admin",
      message: "Visitor statistics loaded successfully.",
    });
  } catch (error) {
    console.error("Error fetching visitor stats:", error);
    res.status(500).send("Internal server error");
  }
});

// Server listen
app.listen(port, () => {
  const mode = process.env.NODE_ENV || "production";
  console.log(`✅ Server running in ${mode} mode on port ${port}`);
});
