import { Router } from 'express';
import { AuthController } from '../controllers/authController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';

const router = Router();

// Public routes
router.post('/signup', AuthController.signUp);

// Protected routes (require authentication)
router.use(authMiddleware);
router.patch('/profile', requireAuth, AuthController.completeProfile);
router.post('/profile-picture', requireAuth, AuthController.uploadProfilePicture);

export const authRoutes = router;
