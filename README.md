# Project Summary 
First project creating a full-stack web application. Meant as first task management web app that uses MongoDB as a database.  

Features I wanted implemented:
 - Users can register and log in to create a private account, then add to and edit their tasks within the DB. All data should be exclusive to each profile that was made/authenticated. No one should view all tasks made by others. Should be empty.
 - HTML/CSS/JavaScript frontend with Express/Node.js for the backend and MongoDB as storage. 
- The focus was on implementing JWT authentication, password hashing, rate limiting, and input validation to explore web server hosting
- I used Render.com to host the website

## Notes:
- If running internally without Render.com or other domain site; 
  - Create a .env if you are hosting internally without Render.com or other site
  - Run npm install to install packages from package.jvs


## Backend
- Node.js – Runtime environment
- Express.js – Web framework for API and static file serving
- MongoDB (via Mongoose) – NoSQL database with schema modeling
- bcrypt – Password hashing
- jsonwebtoken (JWT) – Authentication tokens
- express-rate-limit – Rate limiting for auth and general routes
- dotenv – Environment variable management

## Frontend & Deployment
- HTML/CSS/JavaScript 
- Render.com – Hosted as a public Web Service


## Features to implement:
**JWT Authentication** - Secure login/registration with bcrypt password hashing and validation

**Private Task Management** - Users can only view/edit their own tasks via JWT-protected routes

**Security** - Rate limiting, input validation, and password strength requirements

**Full-Stack Single Server** - Express serves both the frontend and REST API from one deployment

## Setup & Deployment Steps

- Create a MongoDB Atlas cluster and obtain the connection string (MONGODB_URI).
  - Create a new Web Service on Render.com connected to your GitHub repository.
If running internally: 
- Set build command: npm install #this installs all libraries/packages in package.json
- Set start command: npm start
- Add environment variables: MONGODB_URI, JWT_SECRET, NODE_ENV=production
- Render automatically deploys and provides a public URL serving both the frontend and API.

## Steps:
- Create a MangoDB cluster:
<img width="1889" height="804" alt="image" src="https://github.com/user-attachments/assets/7f1c68af-11b0-47a4-b119-7008ed57ccdd" />
<img width="1910" height="1046" alt="image" src="https://github.com/user-attachments/assets/b7a73843-4c4d-4c3b-ab50-68bfa899d665" />

<img width="1404" height="746" alt="image" src="https://github.com/user-attachments/assets/ee1aaadb-3e05-4ce9-be92-ece45a47c124" />

**The connection string is used through Render -> Shown below.**

## Create Web Appplication through Render
<img width="1865" height="990" alt="image" src="https://github.com/user-attachments/assets/47cbb0d8-3d43-40e4-8dfb-65893212a257" />
<img width="1866" height="980" alt="image" src="https://github.com/user-attachments/assets/2efbd43e-ab49-4a96-9cdb-5bd871f8cccb" />
<img width="1865" height="990" alt="image" src="https://github.com/user-attachments/assets/3691dcc2-3222-4a16-90f0-b1e24e7c75a9" />
<img width="1865" height="990" alt="image" src="https://github.com/user-attachments/assets/72eec369-cba3-4fa1-a1df-2899e1846a44" />
<img width="1865" height="993" alt="image" src="https://github.com/user-attachments/assets/579ffad4-b7a8-4ca9-8513-331606c34d3e" />

## Images of current setup:
<img width="1400" height="470" alt="image" src="https://github.com/user-attachments/assets/fa84222b-520d-47b5-a094-5303d45eaba4" />
<img width="1250" height="496" alt="image" src="https://github.com/user-attachments/assets/f76466ff-f223-4e04-a2ef-492165e59add" />
<img width="1366" height="535" alt="image" src="https://github.com/user-attachments/assets/5e773e68-5806-494d-a407-7861b255d238" />
<img width="1615" height="814" alt="image" src="https://github.com/user-attachments/assets/bd82d99e-e352-4f82-bac5-c6b2355e0f5a" />


## Concluding Notes
Explored how modern web servers and RESTful APIs are structured using Node.js and Express.js
