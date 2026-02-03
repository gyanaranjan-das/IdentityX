import app from './app.js';
import { env } from './config/index.js';
import { connectDB, disconnectDB } from './database/mongo.js';

const startServer = async () => {
    await connectDB();
}
const server = app.listen(env.PORT, ()=> {
    console.log(`Server is running on port ${env.PORT}`);
})

process.on('SIGINT', async () => {
    console.log('SIGINT signal received: closing HTTP server');
    await disconnectDB();
    server.close(() => process.exit(0));
});

startServer();