import { PrismaClient } from "@prisma/client";

import * as bodyParser from "body-parser";
import express from "express";
import session from "express-session";

import bcrypt from "bcryptjs";

import { User } from "@prisma/client";

const prisma = new PrismaClient();
const app = express();

// Config for user sessions. User sessions are stored on the server
const sessionConfig = {
   name: "session",
   secret: process.env.SESSION_SECRET || "session secret!",
   resave: false,
   saveUninitialized: process.env.SEND_COOKIES === "false" ? false : true,
   cookie: {
      maxAge: 1000 * 60 * 10, // good for 10 mins in ms
      secure: process.env.USE_SECURE_COOKIES === "true" ? true : false, // Requires HTTPS to send/store cookies
      httpOnly: true, // The JS client can't see the cookie
   },
};

// Parse json from user requests
app.use(bodyParser.json());
// Apply a cookie session to request (only cookie id is stored on user side)
app.use(session(sessionConfig));

/**
 * Authenticator middleware for express requests
 * @param req
 * @param res
 * @param next
 */
const authenticator = (
   req: express.Request,
   res: express.Response,
   next: express.NextFunction
) => {
   if (req && req.session && req.session.loggedIn) {
      next();
   } else {
      res.status(401).json({
         message: "User not authorized. Please register or log in.",
      });
   }
};

/**
 * Get all users (if authenticated)
 */
app.get("/users", authenticator, async (req, res) => {
   const users: User[] = await prisma.user.findMany();
   res.status(200).json(users);
});

/**
 * Route for logins. The user password input will be hashed then compared to the
 * hashed password on the database.
 */
app.post("/auth/login", async (req, res) => {
   // Find the user by username in database, return
   const user: User | null = await prisma.user.findOne({
      where: {
         username: req.body.username,
      },
   });

   // Compare the hashes of the passwords if the user is found (not null)
   if (
      user !== null &&
      bcrypt.compareSync(req.body.password, user.password) === true
   ) {
      if (req.session) {
         console.log(req.session);
         req.session.loggedIn = true;
      }
      res.status(200).json({ message: "Authenticated. Logging you in..." });
   } else {
      res.status(401).json({ message: "Incorrect password" });
   }
});

// The amount of hashing rounds done on the password, default is 2^12
const saltRounds = process.env.BCRYPT_SALT_ROUNDS || 12;
/**
 * This route is used when a user is registering (new user on the website)
 * Requires a username and password on the request body
 */
app.post("/auth/register", async (req, res) => {
   // Has the user's preferred password
   const passwordHash = bcrypt.hashSync(req.body.password, saltRounds);
   // Push the password (that's hashed) onto the database for future use
   const newUser = await prisma.user.create({
      data: {
         username: req.body.username,
         password: passwordHash,
      },
   });
   // Send the hashed password back (just for testing, don't do in real projects)
   res.status(201).json(newUser);
});

app.listen(5000, () =>
   console.log("🚀 Server ready at: http://localhost:5000\n")
);
