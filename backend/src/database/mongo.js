import mongoose from 'mongoose';
import { env } from '../config/index.js';

const connectDB = async () => {
    try{
        await mongoose.connect(env.MONGO_URI,{
            autoIndex: false,
        })
        console.log('MongoDB connected successfully');
    }catch(error){
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
}

const disconnectDB = async () => {
    try{
        await mongoose.connection.close();
        console.log('MongoDB disconnected successfully');
    }catch(error){
        console.error('MongoDB disconnection error:', error);
    }
}

export { connectDB, disconnectDB };