import { Router } from 'express';
import { AuthController } from '../controllers/authController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';

const router = Router();

// Public routes
router.post('/signup', AuthController.signUp);
router.post('/login', AuthController.login);
router.post('/forgotPassword', AuthController.forgotPassword);
router.post('/verify-otp', AuthController.verifyOtp);
router.post('/resetpassword', AuthController.resetPassword);
router.post('/refresh-token', AuthController.refreshToken);
router.post('/resend-verification-otp', AuthController.resendVerificationOtp);
router.post('/complete-login-otp', AuthController.completeLoginWithOtp);

// Social Authentication routes (Google and Facebook)
router.post('/google', AuthController.googleLogin);
router.post('/facebook', AuthController.facebookLogin);
router.get('/oauth-urls', AuthController.getOAuthUrls);

// Protected routes (require authentication)
router.use(authMiddleware);
router.post('/logout', requireAuth, AuthController.logout);
router.patch('/password', requireAuth, AuthController.updatePassword);

export const authRoutes = router;
