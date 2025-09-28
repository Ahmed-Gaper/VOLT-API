import { Router } from 'express';
import { AuthController } from '../controllers/authController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';

const router = Router();

// Public routes
router.post('/signup', AuthController.signUp);
router.post('/login', AuthController.login);
router.post('/forgotPassword', AuthController.forgotPassword);
router.patch('/resetpassword/:token', AuthController.resetPassword);
router.post('/refresh-token', AuthController.refreshToken);

// Protected routes (require authentication)
router.use(authMiddleware);
router.post('/logout', AuthController.logout);
router.patch('/profile', requireAuth, AuthController.completeProfile);
router.post('/profile-picture', requireAuth, AuthController.uploadProfilePicture);

export const authRoutes = router;
