import express from 'express';

const app = express();

app.use(express.json());

app.get('/health',(req,res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Server is healthy',
        service: 'IdentityX Backend',
        timestamp: new Date().toISOString()
    })
})

export default app;