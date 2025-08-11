import { PrismaClient, Role } from '../generated/prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Request } from 'express';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

export async function signup({ email, password, role }: { email: string, password: string, role: Role }) {
    if (!email || !password || !role) throw new Error('Missing fields');
    if (!['admin', 'instructor', 'student'].includes(role)) throw new Error('Invalid role');
    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) throw new Error('Email exists');
    const hash = await bcrypt.hash(password, 8);
    await prisma.user.create({ data: { email, password: hash, role } });
    return { message: 'Signup successful' };
}

export async function login({ email, password }: { email: string, password: string }) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) throw new Error('Invalid credentials');
    const token = jwt.sign({ email: user.email, role: user.role, id: user.id }, JWT_SECRET, { expiresIn: '1d' });
    return { token };
}

export async function getMe(req: Request) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) throw new Error('No token');
    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET) as any;
        const user = await prisma.user.findUnique({ where: { email: payload.email } });
        if (!user) throw new Error('User not found');
        return { id: user.id, email: user.email, role: user.role, createdAt: user.createdAt };
    } catch {
        throw new Error('Invalid token');
    }
}
