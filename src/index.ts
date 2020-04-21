import { PrismaClient } from "@prisma/client";
import * as bodyParser from "body-parser";
import express from "express";
import bcrypt from "bcryptjs";

import { User } from "@prisma/client";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());

app.get("/users", async (req, res) => {
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
   // Compare the hashes of the passwords if the user is found
   if (
      user !== null &&
      bcrypt.compareSync(req.body.password, user.password) === true
   ) {
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
