import { PrismaClient } from "@prisma/client";
import * as bodyParser from "body-parser";
import express from "express";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());

app.get("/users", async (req, res) => {
   const users = await prisma.user.findMany();
   res.status(200).json(users);
});

app.post("/auth/login", async (req, res) => {
   const result = await prisma.user.create({
      data: {
         ...req.body,
      },
   });
   res.json(result);
});

app.post("/auth/register", async (req, res) => {
   const result = await prisma.user.create({
      data: {
         ...req.body,
      },
   });
   res.json(result);
});

app.listen(5000, () =>
   console.log("🚀 Server ready at: http://localhost:5000\n")
);
