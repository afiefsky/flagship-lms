import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
app.use(express.json());

// In-memory user store
const users: any[] = [];
const JWT_SECRET = 'dev_secret'; // Change in production

type Role = 'admin' | 'instructor' | 'student';

// Signup
app.post('/signup', (req, res) => {
    const {
        email,
        password,
        role
    } = req.body;

    if (!email || !password || !role) return res.status(400).json({
        error: 'Missing fields'
    });

    if (!['admin', 'instructor', 'student'].includes(role)) return res.status(400).json({
        error: 'Invalid role'
    });

    if (users.find(u => u.email === email)) return res.status(409).json({
        error: 'Email exists'
    });

    const hash = bcrypt.hashSync(password, 8);
    users.push({
        email,
        password: hash,
        role
    });

    res.json({
        message: 'Signup successful'
    });
});

// Login
app.post('/login', (req, res) => {
    const {
        email,
        password
    } = req.body;

    const user = users.find(u => u.email === email);

    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({
        error: 'Invalid credentials'
    });

    const token = jwt.sign({
        email: user.email,
        role: user.role
    }, JWT_SECRET, {
        expiresIn: '1d'
    });

    res.json({
        token
    });
});

// Auth middleware
function auth(roles ? : Role[]) {
    return (req: any, res: any, next: any) => {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({
            error: 'No token'
        });
        const token = authHeader.split(' ')[1];
        try {
            const payload = jwt.verify(token, JWT_SECRET) as any;
            if (roles && !roles.includes(payload.role)) return res.status(403).json({
                error: 'Forbidden'
            });
            req.user = payload;
            next();
        } catch {
            res.status(401).json({
                error: 'Invalid token'
            });
        }
    };
}

// Example protected route
app.get('/me', auth(), (req: any, res) => {
    res.json({
        user: req.user
    });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
