import { Request, Response } from 'express';
import * as authService from '../services/auth-service';

export async function signupController(req: Request, res: Response) {
    try {
        const result = await authService.signup(req.body);
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: (err as Error).message });
    }
}

export async function loginController(req: Request, res: Response) {
    try {
        const result = await authService.login(req.body);
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(401).json({ error: (err as Error).message });
    }
}

export async function meController(req: Request, res: Response) {
    try {
        const user = await authService.getMe(req);
        res.json({ user });
    } catch (err) {
        console.error(err);
        res.status(401).json({ error: (err as Error).message });
    }
}
