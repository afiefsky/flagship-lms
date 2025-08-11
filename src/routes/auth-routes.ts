import { Router } from 'express';
import { signupController, loginController, meController } from '../controllers/auth-controller';

const router = Router();

router.post('/signup', signupController);
router.post('/login', loginController);
router.get('/me', meController);

export default router;
