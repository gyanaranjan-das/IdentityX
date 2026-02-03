import dotenv from 'dotenv';

dotenv.config();

const envVar = [
    "PORT",
    "NODE_ENV",
    "MONGO_URI",
    "JWT_SECRET",
    "JWT_EXPIRES_IN",
    "LOG_LEVEL",
    "CORS_ORIGIN",
]

envVar.forEach((key) => {
    if(!process.env[key]){
        throw new Error(`Missing required environment variable: ${key}`);
    }
})

const env = {
    port : process.env.PORT,
    nodeEnv : process.env.NODE_ENV,
    mongoUri : process.env.MONGO_URI,
}

export default env;