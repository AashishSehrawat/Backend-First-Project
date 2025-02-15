import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();



// use cors middleware to control the requests from differnt domains
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);



// how to get data from body like form, etc
app.use(express.json({ limit: "16kb" }));
// how to get data from urls
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
// how to store locally images, pdf, etc.
app.use(express.static("public"));

app.use(cookieParser());


// routes import 
import userRouter from './routes/user.route.js'


// routes decleration
app.use("/api/v1/users", userRouter);


export { app };
